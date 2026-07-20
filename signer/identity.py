"""Signer identity: a self-signed X.509 certificate bound to the signer's own
name and email. This is the real key material used for the PKI signature."""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from . import config


@dataclass(frozen=True)
class Signer:
    name: str
    email: str
    title: str = ""

    @property
    def slug(self) -> str:
        return "".join(c if c.isalnum() else "-" for c in self.name.lower()).strip("-")


def _pkcs12_path(signer: Signer) -> Path:
    return config.CERTS_DIR / f"{signer.slug}.p12"


def _build_subject(signer: Signer) -> x509.Name:
    attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, signer.name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, signer.email),
    ]
    if signer.title:
        attributes.append(x509.NameAttribute(NameOID.TITLE, signer.title))
    return x509.Name(attributes)


def _generate_certificate(signer: Signer, password: bytes) -> Path:
    key = rsa.generate_private_key(
        public_exponent=config.RSA_PUBLIC_EXPONENT,
        key_size=config.RSA_KEY_SIZE_BITS,
    )
    subject = _build_subject(signer)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now.replace(year=now.year + config.CERTIFICATE_VALIDITY_YEARS)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(signer.email)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    bundle = pkcs12.serialize_key_and_certificates(
        name=signer.name.encode("utf-8"),
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    path = _pkcs12_path(signer)
    path.write_bytes(bundle)
    return path


def ensure_identity(signer: Signer, password: str) -> Path:
    """Return the signer's PKCS#12 path, creating the certificate on first use."""
    path = _pkcs12_path(signer)
    if not path.exists():
        _generate_certificate(signer, password.encode("utf-8"))
    return path
