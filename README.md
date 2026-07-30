# Local Document Signer

Sign your own PDF documents on this PC with a real PKI digital signature
(PAdES, the same class of cryptography e-signature services use under the
hood) plus an honest audit trail and a DocuSign-style Certificate of
Completion. No subscription, no cloud, no account.

## What it does

- Embeds a genuine PAdES digital signature in the PDF using your own X.509
  certificate. The result is tamper-evident and shows a validity check in
  Adobe Reader and any compliant PDF viewer.
- Records an audit trail of the real signing context: document SHA-256 hash,
  UTC and local timestamp, the machine's actual local and public IP,
  approximate location derived from that IP, hostname, and OS user.
- Generates an HTML Certificate of Completion per document.
- Verifies any signed PDF and detects tampering.

## What it does not do

By design it records the *real* signing context. It does not let you type in
an arbitrary IP address, an invented location, or a signer identity that is
not your own. Those fields exist to be truthful evidence of who signed, when,
and from where. Falsifying them would turn a signed document into a forgery,
so the tool captures them honestly instead.

## Requirements

- Python 3.11+ (tested on 3.14)
- `pyhanko`, `pyhanko-certvalidator`, `cryptography`, `requests`
  (already installed on this machine)

## Usage

Sign a document:

    python sign_document.py sign "C:/path/to/document.pdf" ^
        --name "Your Name" ^
        --email you@example.com ^
        --title "Director" ^
        --reason "I approve this document"

You will be prompted for a key passphrase (or pass `--password`). This
passphrase protects your local certificate file in `certs/`. Your certificate
is created automatically the first time you sign and reused after that.

Verify a signed document:

    python sign_document.py verify "output/document-signed.pdf"

Optional flags for `sign`:

- `--page N`  0-based page for the visible signature block (default: last page)
- `--password`  supply the key passphrase non-interactively
- `--location "Lagos, Nigeria"`  your true place of signing. Recorded in a
  separate field labelled "self-declared" so it is never presented as a
  system-detected value. The IP-derived location is still captured alongside it.
- `--timestamp-url URL`  attach a trusted RFC 3161 timestamp from a Time Stamp
  Authority (for example `http://timestamp.sectigo.com`). Proves the signing
  time independently of the machine clock.
- `--long-term`  embed long-term validation data (LTV/DSS, i.e. PAdES-LTA) so
  the signature still verifies years later after certificates expire. Uses a
  default TSA if `--timestamp-url` is not given. This produces the same
  multi-revision structure a DocuSign document has. If the chosen TSA's chain
  cannot be validated, it falls back to a plain trusted-timestamp signature.
- `--certify`  apply a certifying (author) signature with a DocMDP lock.

- `--pkcs12 PATH`  sign with your own certificate (a `.p12`/`.pfx` file) instead
  of the auto-generated self-signed one. `--password` is that file's passphrase.

### Reaching DocuSign-level quality

`--long-term` gets the tool to PAdES-LTA: a real digital signature, a trusted
timestamp, and embedded long-term validation data. That is the same standard a
DocuSign document uses. The one remaining difference is trust anchoring: the
auto-generated certificate is self-signed, so verifiers trust it by trusting
your certificate directly.

For the automatic green check that strangers see, buy a document-signing
certificate from a CA in Adobe's Approved Trust List (AATL) and point the tool
at it:

    python sign_document.py sign "document.pdf" ^
        --name "Israel Iyonsi" --email you@example.com ^
        --pkcs12 "C:/path/to/your-aatl-cert.p12" --password "cert-passphrase" ^
        --long-term

With a real AATL certificate plus `--long-term`, the output is equivalent to a
DocuSign-signed document: trusted issuer, trusted timestamp, and long-term
validation, all under your own identity. The signing standard is already
equivalent with the self-signed cert; the certificate is only what makes third
parties trust it automatically.

## Output

- `output/<name>-signed.pdf` - the signed PDF
- `output/reports/<name>-certificate.html` - the Certificate of Completion
- `output/audit_log.jsonl` - append-only log, one JSON line per signing event
- `certs/<you>.p12` - your local certificate and private key

## How it compares to DocuSign

The cryptographic signature is real and equivalent in kind: an X.509
certificate plus an RSA signature over the document, embedded as PAdES. The
difference is trust anchoring. DocuSign's certificate chains to a publicly
trusted CA, so third parties accept it without extra steps. Yours is
self-signed, so a verifier trusts it by trusting your certificate directly. To
get the automatic green check for external parties, obtain a certificate from
a trusted CA (for example a document-signing certificate) and load that
instead of the self-signed one.
