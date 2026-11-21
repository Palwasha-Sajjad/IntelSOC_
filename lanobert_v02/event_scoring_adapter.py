"""Advisory-only adapter for IntelSOC's existing LAnoBERT v0.2 scorer.

No database access, alert verdicts, risk updates, or background execution.
Pass only normalized ``security_events.message`` values from eligible sources.
"""

from math import isfinite
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace


ELIGIBLE_EVENTS = {
    "windows_eventlog": frozenset({
        "windows_security_event",
        "windows_application_event",
        "windows_system_event",
        "windows_microsoft-windows-powershell/operational_event",
    }),
    "linux_journald": frozenset({"linux_ssh_event", "linux_sudo_event"}),
    "linux_audit": frozenset({
        "linux_account_audit_event", "linux_process_audit_event"
    }),
}

MODEL_VERSION = "LAnoBERT-v0.2"
SCORER_VERSION = "bounded-masking-v0.2"
MAX_EVENT_CHARS = 65536  # Existing SecurityEvent message limit.


def is_eligible_event(source: str, event_type: str) -> bool:
    """Exclude test sources and categories outside the approved telemetry scope."""
    return event_type in ELIGIBLE_EVENTS.get(source, ())


def load_cpu_scorer(model_dir: str | Path):
    """Load the existing local checkpoint once; never access the network."""
    from transformers import AutoModelForMaskedLM, AutoTokenizer
    import torch

    path = Path(model_dir).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Model checkpoint path must be a directory")

    tokenizer = AutoTokenizer.from_pretrained(
        str(path), local_files_only=True, use_fast=True
    )
    if not tokenizer.is_fast or tokenizer.mask_token_id is None:
        raise ValueError("LAnoBERT requires a fast masked-language tokenizer")

    model = AutoModelForMaskedLM.from_pretrained(
        str(path), local_files_only=True
    )
    model.to("cpu")
    model.eval()

    context = int(model.config.max_position_embeddings)
    if context < 4:
        raise ValueError("Invalid model context length")

    return SimpleNamespace(
        model=model,
        tokenizer=tokenizer,
        device=torch.device("cpu"),
        max_len=context,
        mask_id=tokenizer.mask_token_id,
    )


def score_security_event(
    scorer,
    *,
    source: str,
    event_type: str,
    message: str,
    max_masks: int = 16,
    batch_size: int = 16,
    score_fn=None,
) -> dict:
    """Compute an advisory novelty score with no database or alert side effects.

    Invalid caller arguments raise ValueError; runtime inference failures return
    a sanitized ``failed`` result without exposing log text or exception strings.
    A skipped event never invokes the model. The caller owns persistence/retries.
    """
    if not is_eligible_event(source, event_type):
        return {"status": "skipped", "reason": "ineligible_event"}

    if not isinstance(message, str) or not message.strip():
        raise ValueError("An eligible event requires nonempty message text")
    if len(message) > MAX_EVENT_CHARS:
        raise ValueError("Event message exceeds the configured size limit")
    if not isinstance(max_masks, int) or isinstance(max_masks, bool) or max_masks < 1:
        raise ValueError("max_masks must be a positive integer")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")

    if score_fn is None:
        from lanobert_v02.bounded_masking import score_bounded
        score_fn = score_bounded

    started = perf_counter()
    try:
        result = score_fn(
            scorer, message, max_masks=max_masks, batch_size=batch_size
        )
        elapsed_ms = (perf_counter() - started) * 1000.0

        if not isinstance(result, dict):
            raise ValueError("Invalid scorer output")
        value = result.get("score")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Invalid scorer output")
        score = float(value)
        if not isfinite(score) or score < 0:
            raise ValueError("Invalid scorer output")

        metadata = {}
        for key in ("positions_scored", "total_words", "windows"):
            item = result.get(key)
            if isinstance(item, bool) or not isinstance(item, int) or item < 1:
                raise ValueError("Invalid scorer output")
            metadata[key] = item

    except Exception:
        # Deliberately omit exception text: model exceptions can embed raw logs.
        return {
            "status": "failed",
            "reason": "inference_error",
            "model_version": MODEL_VERSION,
            "scorer_version": SCORER_VERSION,
            "latency_ms": (perf_counter() - started) * 1000.0,
        }

    return {
        "status": "processed",
        "model_version": MODEL_VERSION,
        "scorer_version": SCORER_VERSION,
        "anomaly_score": score,
        "latency_ms": elapsed_ms,
        "details": metadata,
    }
