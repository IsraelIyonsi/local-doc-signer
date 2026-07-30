"""PDF signing engine. Applies a real PAdES (PKI) digital signature using the
signer's certificate, plus a visible signature appearance on the page. The
resulting file is tamper-evident and verifiable in Adobe Reader and any
standards-compliant PDF viewer.

Optionally attaches a trusted RFC 3161 timestamp and embeds long-term
validation data (LTV/DSS, i.e. PAdES-LTA) so the signature stays verifiable
after certificates expire. This is the same standard a service like DocuSign
produces; the difference is only whose identity does the signing."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import certifi
from pyhanko.keys import load_certs_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter, append_signature_field
from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator import ValidationContext

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


@dataclass(frozen=True)
class SignOptions:
    reason: str
    page_index: int | None = None
    location: str = ""
    timestamp_url: str | None = None
    long_term: bool = False
    certify: bool = False


@dataclass(frozen=True)
class SignResult:
    output_path: Path
    timestamp_url: str | None
    long_term: bool
    certified: bool


def _public_ca_roots() -> list:
    return list(load_certs_from_pemder([certifi.where()]))


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


def _timestamper(options: SignOptions) -> tuple[HTTPTimeStamper | None, str | None]:
    url = options.timestamp_url
    if url is None and options.long_term:
        url = config.DEFAULT_TSA_URL
    if url is None:
        return None, None
    return HTTPTimeStamper(url, https=url.lower().startswith("https")), url


def sign_pdf(
    source: Path,
    pkcs12_path: Path,
    password: str,
    signer: Signer,
    context: SigningContext,
    options: SignOptions,
) -> SignResult:
    cms_signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=str(pkcs12_path), passphrase=password.encode("utf-8")
    )

    timestamper, resolved_tsa = _timestamper(options)

    validation_context = None
    if options.long_term:
        validation_context = ValidationContext(
            trust_roots=[cms_signer.signing_cert, *_public_ca_roots()],
            allow_fetching=True,
            revocation_mode=config.REVOCATION_MODE,
        )

    signature_meta = PdfSignatureMetadata(
        field_name=config.SIGNATURE_FIELD_NAME,
        reason=options.reason,
        name=signer.name,
        location=options.location or None,
        md_algorithm=config.MD_ALGORITHM,
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=options.long_term,
        use_pades_lta=options.long_term,
        validation_context=validation_context,
        certify=options.certify,
    )

    output_path = config.OUTPUT_DIR / f"{source.stem}{config.SIGNED_SUFFIX}.pdf"
    stamp_style = _stamp_style(signer, options.reason)

    def attempt(meta: PdfSignatureMetadata) -> None:
        with source.open("rb") as raw:
            writer = IncrementalPdfFileWriter(raw)
            target_page = (
                options.page_index
                if options.page_index is not None
                else _last_page_index(writer)
            )
            append_signature_field(
                writer,
                SigFieldSpec(
                    sig_field_name=config.SIGNATURE_FIELD_NAME,
                    on_page=target_page,
                    box=_SIGNATURE_BOX,
                ),
            )
            pdf_signer = PdfSigner(
                meta,
                signer=cms_signer,
                timestamper=timestamper,
                stamp_style=stamp_style,
            )
            with output_path.open("wb") as out:
                pdf_signer.sign_pdf(writer, output=out)

    long_term_applied = options.long_term
    try:
        attempt(signature_meta)
    except Exception as exc:
        if not options.long_term:
            raise
        print(f"Long-term validation could not be embedded ({exc}).")
        print("Falling back to a plain trusted-timestamp signature.")
        fallback_meta = PdfSignatureMetadata(
            field_name=config.SIGNATURE_FIELD_NAME,
            reason=options.reason,
            name=signer.name,
            location=options.location or None,
            md_algorithm=config.MD_ALGORITHM,
            subfilter=SigSeedSubFilter.PADES,
            certify=options.certify,
        )
        long_term_applied = False
        attempt(fallback_meta)

    return SignResult(
        output_path=output_path,
        timestamp_url=resolved_tsa,
        long_term=long_term_applied,
        certified=options.certify,
    )
