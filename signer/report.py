"""Certificate of Completion report, styled after a signing service's audit
page. Renders one HTML file per signed document from the recorded audit entry."""
from __future__ import annotations

import html
from pathlib import Path

from . import config

_FIELDS = [
    ("Signature ID", "signature_id"),
    ("Signer", "signer_name"),
    ("Email", "signer_email"),
    ("Title", "signer_title"),
    ("Reason", "reason"),
    ("Document", "document_name"),
    ("SHA-256 hash", "document_sha256"),
    ("Signed (UTC)", "timestamp_utc"),
    ("Signed (local)", "timestamp_local"),
    ("Public IP", "public_ip"),
    ("Local IP", "local_ip"),
    ("IP-derived location", "geolocation"),
    ("Place of signing (self-declared)", "declared_location"),
    ("Host", "hostname"),
    ("OS user", "os_user"),
    ("Platform", "platform"),
]

_STYLE = """
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, Segoe UI, sans-serif;
  margin: 0; padding: 2.5rem; line-height: 1.5rem; }
.wrap { max-width: 48rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
.sub { color: #6b7280; font-size: 0.875rem; margin: 0 0 1.75rem; }
.badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 1rem;
  font-size: 0.8125rem; font-weight: 600; }
.ok { background: #dcfce7; color: #166534; }
.bad { background: #fee2e2; color: #991b1b; }
table { width: 100%; border-collapse: collapse; margin-top: 1.5rem;
  font-size: 0.9375rem; }
th, td { text-align: left; padding: 0.625rem 0.75rem; vertical-align: top;
  border-bottom: 0.0625rem solid rgba(128,128,128,0.25); }
th { width: 12rem; color: #6b7280; font-weight: 500; }
td { word-break: break-word; font-variant-numeric: tabular-nums; }
.foot { margin-top: 2rem; font-size: 0.8125rem; color: #6b7280; }
"""

_ROW = "<tr><th>{label}</th><td>{value}</td></tr>"


def _verification_badge(intact: bool, valid: bool) -> str:
    if intact and valid:
        return '<span class="badge ok">Signature valid &middot; document intact</span>'
    return '<span class="badge bad">Signature could not be verified</span>'


def build_report(entry: dict, intact: bool, valid: bool) -> Path:
    rows = "\n".join(
        _ROW.format(
            label=html.escape(label),
            value=html.escape(str(entry.get(key, config.UNAVAILABLE)) or config.UNAVAILABLE),
        )
        for label, key in _FIELDS
    )
    document = html.escape(entry.get("document_name", ""))
    page = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certificate of Completion - {document}</title>
<style>{_STYLE}</style></head>
<body><div class="wrap">
<h1>Certificate of Completion</h1>
<p class="sub">Locally generated audit record for a PKI-signed document.</p>
{_verification_badge(intact, valid)}
<table><tbody>
{rows}
</tbody></table>
<p class="foot">This record reflects the actual signing context detected on this
machine at signing time. The signature is a PAdES digital signature; open the
signed PDF in a compliant reader to independently confirm its validity.</p>
</div></body></html>"""

    output = config.REPORTS_DIR / f"{Path(entry['document_name']).stem}-certificate.html"
    output.write_text(page, encoding="utf-8")
    return output
