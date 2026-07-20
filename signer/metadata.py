"""Honest capture of the real signing context: document hash, timestamp, and
the actual machine/network the signature was produced on. Nothing here is
user-supplied. If a value cannot be detected, it is recorded as unavailable
rather than guessed or overridden."""
from __future__ import annotations

import datetime
import getpass
import hashlib
import platform
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import config


def hash_file(path: Path) -> str:
    digest = hashlib.new(config.HASH_ALGORITHM)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(config.HASH_READ_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return config.UNAVAILABLE


def _public_ip() -> str:
    try:
        response = requests.get(
            config.PUBLIC_IP_LOOKUP_URL, timeout=config.NETWORK_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        return response.text.strip() or config.UNAVAILABLE
    except requests.RequestException:
        return config.UNAVAILABLE


def _geo_from(url: str, keys: tuple[str, ...]) -> str:
    response = requests.get(url, timeout=config.NETWORK_TIMEOUT_SECONDS)
    response.raise_for_status()
    data = response.json()
    parts = [data.get(k) for k in keys]
    return ", ".join(p for p in parts if p)


def _geolocation(public_ip: str) -> str:
    if public_ip == config.UNAVAILABLE:
        return config.UNAVAILABLE
    providers = (
        (config.GEO_LOOKUP_URL_TEMPLATE.format(ip=public_ip), ("city", "region", "country_name")),
        (config.GEO_FALLBACK_URL_TEMPLATE.format(ip=public_ip), ("city", "regionName", "country")),
    )
    for url, keys in providers:
        try:
            located = _geo_from(url, keys)
            if located:
                return located
        except (requests.RequestException, ValueError):
            continue
    return config.UNAVAILABLE


@dataclass(frozen=True)
class SigningContext:
    signature_id: str
    timestamp_utc: str
    timestamp_local: str
    document_name: str
    document_sha256: str
    local_ip: str
    public_ip: str
    geolocation: str
    hostname: str
    os_user: str
    platform: str

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def capture(document: Path) -> SigningContext:
    now = datetime.datetime.now(datetime.timezone.utc)
    public_ip = _public_ip()
    return SigningContext(
        signature_id=str(uuid.uuid4()),
        timestamp_utc=now.isoformat(),
        timestamp_local=now.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        document_name=document.name,
        document_sha256=hash_file(document),
        local_ip=_local_ip(),
        public_ip=public_ip,
        geolocation=_geolocation(public_ip),
        hostname=socket.gethostname(),
        os_user=getpass.getuser(),
        platform=platform.platform(),
    )
