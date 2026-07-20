"""Central configuration and constants. No magic literals elsewhere."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"
OUTPUT_DIR = PROJECT_ROOT / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"
AUDIT_LOG_PATH = OUTPUT_DIR / "audit_log.jsonl"

HASH_ALGORITHM = "sha256"
HASH_READ_CHUNK_BYTES = 65536

CERTIFICATE_VALIDITY_YEARS = 10
RSA_KEY_SIZE_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537

PUBLIC_IP_LOOKUP_URL = "https://api.ipify.org"
GEO_LOOKUP_URL_TEMPLATE = "https://ipapi.co/{ip}/json/"
GEO_FALLBACK_URL_TEMPLATE = "http://ip-api.com/json/{ip}"
NETWORK_TIMEOUT_SECONDS = 5
UNAVAILABLE = "unavailable"
NOT_DECLARED = "not declared"

SIGNATURE_FIELD_NAME = "Signature"
SIGNED_SUFFIX = "-signed"

for _directory in (CERTS_DIR, OUTPUT_DIR, REPORTS_DIR):
    _directory.mkdir(parents=True, exist_ok=True)
