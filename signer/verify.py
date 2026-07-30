"""Verification: proves a signed PDF has not been altered since signing.
Reports whether the embedded signature is cryptographically intact, whether the
signed byte range still covers the document, and how any post-signing revisions
are classified (benign long-term-validation / form-fill updates versus content
changes)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

_BENIGN_LEVELS = {"NONE", "LTA_UPDATES", "FORM_FILLING"}


@dataclass(frozen=True)
class VerificationResult:
    field_name: str
    signer_name: str
    intact: bool
    valid: bool
    covers_whole_document: bool
    modification_level: str
    only_benign_updates: bool
    has_trusted_timestamp: bool
    signing_time: str


def verify_pdf(path: Path) -> list[VerificationResult]:
    results: list[VerificationResult] = []
    with path.open("rb") as raw:
        reader = PdfFileReader(raw, strict=False)
        for sig in reader.embedded_signatures:
            if str(sig.sig_object.get("/Type")) == "/DocTimeStamp":
                continue
            trust_roots = [sig.signer_cert] if sig.signer_cert is not None else []
            trust = ValidationContext(
                trust_roots=trust_roots, allow_fetching=False, revocation_mode="soft-fail"
            )
            status = validate_pdf_signature(sig, signer_validation_context=trust)

            signer_name = ""
            if sig.signer_cert is not None:
                signer_name = sig.signer_cert.subject.human_friendly

            reported = status.signer_reported_dt
            signing_time = str(reported) if reported else ""

            coverage_name = status.coverage.name if status.coverage is not None else ""
            covers_all = coverage_name == "ENTIRE_FILE"

            mod_level = status.modification_level.name if status.modification_level else "UNKNOWN"
            only_benign = covers_all or mod_level in _BENIGN_LEVELS

            has_ts = status.timestamp_validity is not None

            results.append(
                VerificationResult(
                    field_name=sig.field_name,
                    signer_name=signer_name,
                    intact=bool(status.intact),
                    valid=bool(status.valid),
                    covers_whole_document=covers_all,
                    modification_level=mod_level,
                    only_benign_updates=bool(only_benign),
                    has_trusted_timestamp=has_ts,
                    signing_time=signing_time,
                )
            )
    return results
