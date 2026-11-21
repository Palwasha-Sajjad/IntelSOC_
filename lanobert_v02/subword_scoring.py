"""Experimental full-subword scorer for IntelSOC LAnoBERT v0.2.

Evaluation only. Does not replace bounded_masking.py.
Currently supports events fitting within one model window.
"""

import re

import numpy as np
import torch

from lanobert_v02.mask_selection import select_mask_positions


def score_subwords(scorer, text, max_masks=16, max_subwords=64, batch_size=16):
    if not text or not text.strip():
        raise ValueError("Empty log")

    if min(max_masks, max_subwords, batch_size) < 1:
        raise ValueError("Scoring limits must be positive")

    tok = scorer.tokenizer

    if not getattr(tok, "is_fast", False):
        raise ValueError("Fast tokenizer required")

    words = list(re.finditer(r"\S+", text))
    selected = select_mask_positions(text, max_masks=max_masks)

    enc = tok(
        text,
        return_offsets_mapping=True,
        truncation=False,
    )

    ids = enc["input_ids"]
    offsets = enc["offset_mapping"]

    if len(ids) > scorer.max_len:
        raise ValueError(
            "Log exceeds model context; sliding windows not implemented"
        )

    positions = []

    for wi in selected:
        word = words[wi]

        matches = [
            i for i, (start, end) in enumerate(offsets)
            if start < word.end()
            and end > word.start()
            and start != end
        ]

        positions.extend(matches)

    positions = list(dict.fromkeys(positions))[:max_subwords]

    if not positions:
        raise RuntimeError("No subwords selected")

    input_ids = torch.tensor(ids, dtype=torch.long)
    attention_mask = torch.ones_like(input_ids)

    errors = []

    with torch.inference_mode():
        for start in range(0, len(positions), batch_size):
            current = positions[start:start + batch_size]

            batch = input_ids.unsqueeze(0).repeat(len(current), 1)

            targets = []

            for row, pos in enumerate(current):
                targets.append(int(batch[row, pos]))
                batch[row, pos] = scorer.mask_id

            mask = attention_mask.unsqueeze(0).repeat(
                len(current), 1
            )

            logits = scorer.model(
                input_ids=batch.to(scorer.device),
                attention_mask=mask.to(scorer.device),
            ).logits

            for row, pos in enumerate(current):
                lp = torch.log_softmax(logits[row, pos], dim=-1)
                errors.append(-lp[targets[row]].item())

    return {
        "score": float(np.mean(errors)),
        "subwords_scored": len(errors),
        "words_selected": len(selected),
        "total_words": len(words),
        "total_tokens": len(ids),
    }
