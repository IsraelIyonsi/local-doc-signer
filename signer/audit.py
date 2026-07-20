"""Append-only audit log. Every signing event is recorded as one JSON line,
mirroring the tamper-evident event history a signing service keeps."""
from __future__ import annotations

import json
from typing import Iterator

from . import config
from .identity import Signer
from .metadata import SigningContext


def record(
    signer: Signer,
    context: SigningContext,
    reason: str,
    output_name: str,
    declared_location: str = config.NOT_DECLARED,
) -> dict:
    entry = {
        "event": "document_signed",
        "signer_name": signer.name,
        "signer_email": signer.email,
        "signer_title": signer.title,
        "reason": reason,
        "declared_location": declared_location or config.NOT_DECLARED,
        "signed_output": output_name,
        **context.as_dict(),
    }
    with config.AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def read_all() -> Iterator[dict]:
    if not config.AUDIT_LOG_PATH.exists():
        return
    with config.AUDIT_LOG_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)
