"""Batch 7 isolated, no checkpoint or PostgreSQL calls."""
import csv
import tempfile
import unittest
from pathlib import Path
from lanobert_v02.evaluate_labeled import read_examples, confusion, select_validation_threshold, evaluate


def sample_rows():
    return [
        ['windows_eventlog', 'windows_security_event', 'normal A', 'normal', 'validation'],
        ['windows_eventlog', 'windows_security_event', 'malicious B', 'anomaly', 'validation'],
        ['linux_journald', 'linux_ssh_event', 'normal C', 'normal', 'test'],
        ['linux_journald', 'linux_ssh_event', 'malicious D', 'anomaly', 'test'],
    ]


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / 'labeled.csv'

    def write_rows(self, rows):
        with self.file.open('w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(['source', 'event_type', 'message', 'label', 'split'])
            writer.writerows(rows)

    def test_reads_independent_splits(self):
        self.write_rows(sample_rows())
        self.assertEqual(len(read_examples(self.file)), 4)

    def test_missing_column_rejected(self):
        self.file.write_text('message,label\nhello,normal\n')
        with self.assertRaises(ValueError): read_examples(self.file)

    def test_duplicate_log_rejected(self):
        rows = sample_rows()
        rows[2][2] = rows[0][2]
        rows[2][0] = rows[0][0]
        rows[2][1] = rows[0][1]
        self.write_rows(rows)
        with self.assertRaises(ValueError): read_examples(self.file)

    def test_missing_class_rejected(self):
        rows = sample_rows()
        rows[3][3] = 'normal'
        self.write_rows(rows)
        with self.assertRaises(ValueError): read_examples(self.file)

    def test_invalid_category_rejected(self):
        rows = sample_rows()
        rows[0][0] = 'network_pcap'
        self.write_rows(rows)
        with self.assertRaises(ValueError): read_examples(self.file)

    def test_limit_enforced(self):
        self.write_rows(sample_rows())
        with self.assertRaises(ValueError): read_examples(self.file, limit=3)

    def test_confusion_metrics(self):
        stats = confusion([(1, 'normal'), (2, 'anomaly'), (3, 'normal'), (4, 'anomaly')], 2)
        self.assertEqual((stats['tp'], stats['fp'], stats['tn'], stats['fn']), (2, 1, 1, 0))
        self.assertAlmostEqual(stats['precision'], .6667, places=4)

    def test_validation_threshold_and_unseen_test(self):
        rows = sample_rows()
        observations = {'normal A': 1.0, 'malicious B': 4.0,
                        'normal C': 5.0, 'malicious D': 2.0}
        def fake_score(_scorer, **kw):
            return {'status': 'processed', 'anomaly_score': observations[kw['message']], 'latency_ms': 12}
        result = evaluate(rows, object(), score_fn=fake_score)
        self.assertEqual(result['validation']['f1'], 1.0)
        self.assertEqual(result['test']['f1'], 0.0)
        self.assertEqual(result['validation_selected_threshold'], 4.0)
        self.assertEqual(result['mean_latency_ms'], 12)

    def test_inference_failure_has_no_report(self):
        def broken(*args, **kwargs): return {'status': 'failed'}
        with self.assertRaises(RuntimeError): evaluate(sample_rows(), object(), score_fn=broken)


if __name__ == '__main__': unittest.main()
