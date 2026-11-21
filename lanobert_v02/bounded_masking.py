"""Experimental bounded word-masking scorer for IntelSOC LAnoBERT v0.2.

This preserves the reference scorer's sliding-window layout and
first-subword CE targets while evaluating a bounded set of words.
It is not a drop-in replacement for exhaustive scoring.
"""

import bisect
import numpy as np
import torch
from lanobert_v02.mask_selection import select_mask_positions


def score_bounded(scorer, text, max_masks=32, batch_size=16):
    if max_masks < 1 or batch_size < 1:
        raise ValueError("max_masks and batch_size must be positive")

    tok = scorer.tokenizer
    if not getattr(tok, "is_fast", False):
        raise ValueError("A fast tokenizer is required")

    words = text.split()
    n = len(words)
    if not n:
        raise ValueError("Empty log")

    def targets_and_lengths(parts):
        joined = " ".join(parts)
        starts = []
        cursor = 0
        for word in parts:
            starts.append(cursor)
            cursor += len(word) + 1

        enc = tok(
            joined,
            add_special_tokens=False,
            return_offsets_mapping=True,
        )

        first = [None] * len(parts)
        lengths = [0] * len(parts)

        for tid, (a, b) in zip(
            enc["input_ids"], enc["offset_mapping"]
        ):
            if a >= b:
                continue
            while a < b and joined[a] == " ":
                a += 1

            wi = bisect.bisect_right(starts, a) - 1
            if 0 <= wi < len(parts):
                lengths[wi] += 1
                if first[wi] is None:
                    first[wi] = tid

        return first, [max(1, x) for x in lengths]

    _, lengths = targets_and_lengths(words)

    budget = max(1, scorer.max_len - 2)
    windows = []
    s = 0

    while s < n:
        e, total = s, 0
        while e < n and (
            e == s or total + lengths[e] <= budget
        ):
            total += lengths[e]
            e += 1

        windows.append((s, e))
        s = e

    selected = select_mask_positions(text, max_masks=max_masks)

    errors = []

    with torch.inference_mode():
        for ws, we in windows:
            positions = [
                i - ws for i in selected if ws <= i < we
            ]

            if not positions:
                continue

            parts = words[ws:we]
            targets, _ = targets_and_lengths(parts)

            for start in range(0, len(positions), batch_size):
                current = positions[start:start + batch_size]
                masked = []

                for pos in current:
                    copy = list(parts)
                    copy[pos] = tok.mask_token
                    masked.append(" ".join(copy))

                batch = tok(
                    masked,
                    return_tensors="pt",
                    padding=True,
                    truncation=True,
                    max_length=scorer.max_len,
                ).to(scorer.device)

                logits = scorer.model(**batch).logits

                for j, pos in enumerate(current):
                    locations = (
                        batch["input_ids"][j] == scorer.mask_id
                    ).nonzero(as_tuple=True)[0]

                    target = targets[pos]
                    if locations.numel() == 0 or target is None:
                        continue

                    mask_at = int(locations[0].item())

                    lp = torch.log_softmax(
                        logits[j, mask_at], dim=-1
                    )

                    errors.append(-lp[target].item())

    if not errors:
        raise RuntimeError("No masked positions scored")

    return {
        "score": float(np.mean(errors)),
        "positions_scored": len(errors),
        "total_words": n,
        "windows": len(windows),
    }
