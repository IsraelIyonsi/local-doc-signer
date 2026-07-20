"""PDF signing engine. Applies a real PAdES (PKI) digital signature using the
signer's certificate, plus a visible signature appearance on the page. The
resulting file is tamper-evident and verifiable in Adobe Reader and any
standards-compliant PDF viewer."""
from __future__ import annotations

from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter, append_signature_field
from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
from pyhanko.stamp import TextStampStyle

from . import config
from .identity import Signer
from .metadata import SigningContext

_SIGNATURE_BOX = (40, 40, 320, 132)
_STAMP_TEMPLATE = (
    "Digitally signed by %(signer)s\n"
    "%(email)s\n"
    "Reason: %(reason)s\n"
    "%(ts)s"
)


def _last_page_index(writer: IncrementalPdfFileWriter) -> int:
    page_count = writer.root["/Pages"]["/Count"]
    return int(page_count) - 1


def _stamp_style(signer: Signer, reason: str) -> TextStampStyle:
    stamp_text = _STAMP_TEMPLATE % {
        "signer": signer.name,
        "email": signer.email,
        "reason": reason,
        "ts": "%(ts)s",
    }
    return TextStampStyle(stamp_text=stamp_text)


def sign_pdf(
    source: Path,
    pkcs12_path: Path,
    password: str,
    signer: Signer,
    context: SigningContext,
    reason: str,
    page_index: int | None = None,
) -> Path:
    cms_signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=str(pkcs12_path), passphrase=password.encode("utf-8")
    )

    output_path = config.OUTPUT_DIR / f"{source.stem}{config.SIGNED_SUFFIX}.pdf"

    with source.open("rb") as raw:
        writer = IncrementalPdfFileWriter(raw)
        target_page = page_index if page_index is not None else _last_page_index(writer)
        append_signature_field(
            writer,
            SigFieldSpec(
                sig_field_name=config.SIGNATURE_FIELD_NAME,
                on_page=target_page,
                box=_SIGNATURE_BOX,
            ),
        )

        signature_meta = PdfSignatureMetadata(
            field_name=config.SIGNATURE_FIELD_NAME,
            reason=reason,
            name=signer.name,
            subfilter=SigSeedSubFilter.PADES,
        )
        pdf_signer = PdfSigner(
            signature_meta,
            signer=cms_signer,
            stamp_style=_stamp_style(signer, reason),
        )

        with output_path.open("wb") as out:
            pdf_signer.sign_pdf(writer, output=out)

    return output_path
