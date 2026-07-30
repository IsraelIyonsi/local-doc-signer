"""Command-line entry point for the local document signer.

Examples:
  python sign_document.py sign "C:/path/to/agreement.pdf" \
      --name "Israel Iyonsi" --email israel@example.com \
      --title "Director" --reason "I approve this document"

  python sign_document.py verify "output/agreement-signed.pdf"
"""
from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from signer import audit, metadata, report, sign, verify
from signer.identity import Signer

DEFAULT_REASON = "I am the author and approve this document"
_NOISY_LOGGERS = ("pyhanko", "pyhanko_certvalidator")


def _quiet_library_logging() -> None:
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.CRITICAL)


def _resolve_password(supplied: str | None) -> str:
    if supplied:
        return supplied
    return getpass.getpass("Key passphrase (protects your local certificate): ")


def _cmd_sign(args: argparse.Namespace) -> int:
    source = Path(args.document).expanduser().resolve()
    if not source.exists():
        print(f"File not found: {source}", file=sys.stderr)
        return 1
    if source.suffix.lower() != ".pdf":
        print("Only PDF documents are supported.", file=sys.stderr)
        return 1

    password = _resolve_password(args.password)
    signer = Signer(name=args.name, email=args.email, title=args.title or "")

    if args.pkcs12:
        pkcs12_path = Path(args.pkcs12).expanduser().resolve()
        if not pkcs12_path.exists():
            print(f"Certificate file not found: {pkcs12_path}", file=sys.stderr)
            return 1
    else:
        from signer.identity import ensure_identity

        pkcs12_path = ensure_identity(signer, password)
    context = metadata.capture(source)
    options = sign.SignOptions(
        reason=args.reason,
        page_index=args.page,
        location=args.location,
        timestamp_url=args.timestamp_url,
        long_term=args.long_term,
        certify=args.certify,
    )
    result = sign.sign_pdf(
        source=source,
        pkcs12_path=pkcs12_path,
        password=password,
        signer=signer,
        context=context,
        options=options,
    )
    signed = result.output_path

    entry = audit.record(
        signer,
        context,
        args.reason,
        signed.name,
        args.location,
        timestamp_authority=result.timestamp_url or "",
        long_term_validation=result.long_term,
        certified=result.certified,
    )

    results = verify.verify_pdf(signed)
    intact = all(r.intact for r in results) if results else False
    valid = all(r.valid for r in results) if results else False
    cert = report.build_report(entry, intact, valid)

    print(f"Signed PDF:   {signed}")
    print(f"Certificate:  {cert}")
    print(f"Audit log:    appended ({entry['signature_id']})")
    print(f"Timestamp:    {result.timestamp_url or 'none'}")
    print(f"Long-term:    {result.long_term}")
    print(f"Verification: intact={intact} valid={valid}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    target = Path(args.document).expanduser().resolve()
    if not target.exists():
        print(f"File not found: {target}", file=sys.stderr)
        return 1
    results = verify.verify_pdf(target)
    if not results:
        print("No digital signatures found in this document.")
        return 1
    for r in results:
        print(f"Field:   {r.field_name}")
        print(f"Signer:  {r.signer_name}")
        print(f"Signed:  {r.signing_time}")
        print(f"Intact:  {r.intact}")
        print(f"Valid:   {r.valid}")
        print(f"Covers whole document: {r.covers_whole_document}")
        print(f"Post-signing changes:  {r.modification_level} (benign only: {r.only_benign_updates})")
        print(f"Trusted timestamp:     {r.has_trusted_timestamp}")
        print("-" * 40)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign PDFs locally with a real PKI signature.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sign = sub.add_parser("sign", help="Sign a PDF document.")
    p_sign.add_argument("document", help="Path to the PDF to sign.")
    p_sign.add_argument("--name", required=True, help="Your full name.")
    p_sign.add_argument("--email", required=True, help="Your email address.")
    p_sign.add_argument("--title", default="", help="Your title (optional).")
    p_sign.add_argument("--reason", default=DEFAULT_REASON, help="Reason for signing.")
    p_sign.add_argument("--location", default="", help="Your true place of signing, recorded as self-declared (e.g. \"Lagos, Nigeria\").")
    p_sign.add_argument("--password", default=None, help="Passphrase for your key (local self-signed key, or the --pkcs12 file).")
    p_sign.add_argument("--pkcs12", default=None, help="Path to your own PKCS#12 (.p12/.pfx) certificate, e.g. a purchased AATL document-signing cert. Overrides the self-signed identity; --password is its passphrase.")
    p_sign.add_argument("--page", type=int, default=None, help="0-based page for the visible signature (default: last).")
    p_sign.add_argument("--timestamp-url", dest="timestamp_url", default=None, help="RFC 3161 TSA URL for a trusted timestamp (e.g. http://timestamp.digicert.com).")
    p_sign.add_argument("--long-term", dest="long_term", action="store_true", help="Embed LTV/DSS data (PAdES-LTA) so the signature validates long-term. Uses a default TSA if none given.")
    p_sign.add_argument("--certify", action="store_true", help="Apply a certifying (author) signature with a DocMDP lock.")
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a signed PDF.")
    p_verify.add_argument("document", help="Path to the signed PDF.")
    p_verify.set_defaults(func=_cmd_verify)

    return parser


def main() -> int:
    _quiet_library_logging()
    parser = _build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
