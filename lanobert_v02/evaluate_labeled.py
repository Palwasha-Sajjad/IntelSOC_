"""Offline, read-only LAnoBERT v0.2 evaluation on independently labeled logs.

Input CSV: source,event_type,message,label,split
label: normal/anomaly; split: validation/test. Model never writes to the DB,
outputs only aggregate metrics, and never prints log message contents.
A threshold is chosen ONLY on validation and applied unchanged to test.
Evaluation results are not permission to enable automatic alerting.
"""
import argparse
import csv
import hashlib
import json
from collections import Counter
from math import isfinite
from pathlib import Path

from lanobert_v02.event_scoring_adapter import (
    ELIGIBLE_EVENTS, load_cpu_scorer, score_security_event,
)

FIELDS = {'source', 'event_type', 'message', 'label', 'split'}
MAX_ROWS = 500
MAX_CSV_BYTES = 32 * 1024 * 1024


def read_examples(path, limit=MAX_ROWS):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_CSV_BYTES:
        raise ValueError('Dataset missing or too large (32 MiB maximum)')
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_ROWS:
        raise ValueError('limit must be 1..500')
    records, fingerprints = [], {}
    with path.open('r', encoding='utf-8-sig', newline='') as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or not FIELDS.issubset(reader.fieldnames):
            raise ValueError('Dataset needs source,event_type,message,label,split')
        for idx, record in enumerate(reader, start=1):
            if idx > limit:
                raise ValueError('Dataset exceeds evaluation row limit')
            source = record['source'].strip()
            event_type = record['event_type'].strip()
            label = record['label'].strip().lower()
            split = record['split'].strip().lower()
            message = record['message']
            if event_type not in ELIGIBLE_EVENTS.get(source, ()):
                raise ValueError(f'Unsupported source/event type at row {idx}')
            if label not in ('normal', 'anomaly') or split not in ('validation', 'test'):
                raise ValueError(f'Unsupported label or split at row {idx}')
            if not message or not message.strip() or len(message) > 65536:
                raise ValueError(f'Invalid message at row {idx}')
            # Block duplicate source/event/message across both splits to prevent leakage.
            signature = hashlib.sha256((source + '\0' + event_type + '\0' + message.strip()).encode('utf-8')).hexdigest()
            if signature in fingerprints:
                raise ValueError(f'Duplicate log sample at rows {fingerprints[signature]} and {idx}')
            fingerprints[signature] = idx
            records.append((source, event_type, message, label, split))
    if not records:
        raise ValueError('Empty dataset')
    for split in ('validation', 'test'):
        present = {rec[3] for rec in records if rec[4] == split}
        if present != {'normal', 'anomaly'}:
            raise ValueError(f'{split} must include both normal and anomaly examples')
    return records


def confusion(items, threshold):
    # Higher bounded masked-token loss indicates higher novelty, not a threat probability.
    tp = fp = tn = fn = 0
    for score, label in items:
        predicted = score >= threshold
        actual = label == 'anomaly'
        if predicted and actual: tp += 1
        elif predicted: fp += 1
        elif actual: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'precision': round(precision, 4),
            'recall': round(recall, 4), 'f1': round(f1, 4), 'false_positive_rate': round(fpr, 4)}


def select_validation_threshold(items):
    if not items:
        raise ValueError('Missing validation data')
    # Candidate just above maximum represents no flagged events.
    scores = sorted({s for s, _ in items})
    candidates = scores + [scores[-1] + max(1.0, abs(scores[-1])) * 1e-6]
    # Tie-break: prefer fewer false positives, then higher threshold.
    return max(candidates, key=lambda threshold: (
        confusion(items, threshold)['f1'],
        -confusion(items, threshold)['fp'], threshold,
    ))


def evaluate(records, scorer, score_fn=score_security_event):
    by_split = {'validation': [], 'test': []}
    per_type = Counter()
    latencies = []
    for source, event_type, message, label, split in records:
        result = score_fn(scorer, source=source, event_type=event_type,
                          message=message, max_masks=16, batch_size=16)
        if result.get('status') != 'processed':
            raise RuntimeError('Evaluation inference failed; results not generated')
        score = result.get('anomaly_score')
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not isfinite(score) or score < 0:
            raise RuntimeError('Invalid anomaly score')
        by_split[split].append((score, label))
        per_type[event_type] += 1
        latency = result.get('latency_ms')
        if isinstance(latency, (int, float)) and not isinstance(latency, bool) and isfinite(latency) and latency >= 0:
            latencies.append(latency)
    threshold = select_validation_threshold(by_split['validation'])
    return {'model_version': 'LAnoBERT-v0.2', 'score_semantics': 'raw novelty score, higher is less expected',
            'threshold_status': 'experimental; validation-F1 selected; NOT operational',
            'evaluation_count': len(records), 'validation_count': len(by_split['validation']),
            'test_count': len(by_split['test']), 'validation_selected_threshold': round(threshold, 6),
            'validation': confusion(by_split['validation'], threshold),
            'test': confusion(by_split['test'], threshold),
            'mean_latency_ms': round(sum(latencies) / len(latencies), 2) if latencies else None,
            'event_type_counts': dict(sorted(per_type.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True, type=Path)
    parser.add_argument('--model-dir', type=Path, default=Path.home() / 'Downloads' / 'IntelSOC-LAnoBERT-v0.2-model')
    parser.add_argument('--limit', type=int, default=MAX_ROWS)
    args = parser.parse_args()
    try:
        records = read_examples(args.csv, args.limit)
        scorer = load_cpu_scorer(args.model_dir)
        report = evaluate(records, scorer)
        print(json.dumps(report, indent=2))
    except (ValueError, RuntimeError, OSError) as error:
        # Never echo raw exception strings; model/CSV failures can include log content.
        parser.exit(1, f'Evaluation failed: {type(error).__name__}\n')


if __name__ == '__main__':
    main()
