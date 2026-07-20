"""Verification: proves a signed PDF has not been altered since signing.
Reports whether the embedded signature is cryptographically intact and whether
the signed byte range still covers the whole document."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


@dataclass(frozen=True)
class VerificationResult:
    field_name: str
    signer_name: str
    intact: bool
    valid: bool
    covers_whole_document: bool
    signing_time: str


def verify_pdf(path: Path) -> list[VerificationResult]:
    results: list[VerificationResult] = []
    with path.open("rb") as raw:
        reader = PdfFileReader(raw)
        for sig in reader.embedded_signatures:
            trust = ValidationContext(trust_roots=[sig.signer_cert])
            status = validate_pdf_signature(sig, signer_validation_context=trust)
            signer_name = ""
            if sig.signer_cert is not None:
                signer_name = sig.signer_cert.subject.human_friendly
            reported = status.signer_reported_dt
            signing_time = str(reported) if reported else ""
            covers_all = status.coverage is not None and status.coverage.name == "ENTIRE_FILE"
            results.append(
                VerificationResult(
                    field_name=sig.field_name,
                    signer_name=signer_name,
                    intact=bool(status.intact),
                    valid=bool(status.valid),
                    covers_whole_document=covers_all,
                    signing_time=signing_time,
                )
            )
    return results
