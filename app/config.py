"""Environment-driven configuration, validated fail-fast at startup.

Bundles are declared through Compose as numbered slots 1..8:

    BUNDLE_<n>_FILE    - path to a read-only mounted evidence file
    BUNDLE_<n>_SHA256  - lowercase hex SHA-256 of that file

Both variables of a slot must be set together, the digest must be 64
lowercase hex chars, and the file must actually hash to it - otherwise the
service refuses to start.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

MAX_BUNDLES = 8
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ConfigError(Exception):
    """Raised when the service is misconfigured; aborts startup."""


@dataclass(frozen=True)
class Bundle:
    bundle_id: str
    path: str
    sha256: str  # lowercase hex, verified against the file at startup


@dataclass(frozen=True)
class Settings:
    public_origin: str
    token_issuer: str
    token_audience: str
    issuer_public_key_pem: str
    replay_db_path: str
    dpop_iat_window_seconds: int
    token_clock_skew_seconds: int
    replay_retention_seconds: int
    bundles: dict[str, Bundle]


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} must be set")
    return value


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _load_bundles(env: Mapping[str, str]) -> dict[str, Bundle]:
    bundles: dict[str, Bundle] = {}
    for n in range(1, MAX_BUNDLES + 1):
        file_var, sha_var = f"BUNDLE_{n}_FILE", f"BUNDLE_{n}_SHA256"
        path = env.get(file_var, "").strip()
        sha = env.get(sha_var, "").strip()
        if bool(path) != bool(sha):
            raise ConfigError(f"{file_var} and {sha_var} must be set together")
        if not path:
            continue
        if not _SHA256_RE.fullmatch(sha):
            raise ConfigError(
                f"{sha_var} must be a lowercase hex SHA-256 (64 chars, [0-9a-f])"
            )
        bundle_file = Path(path)
        if not bundle_file.is_file():
            raise ConfigError(f"{file_var} points to a missing file: {path}")
        actual = hashlib.sha256(bundle_file.read_bytes()).hexdigest()
        if actual != sha:
            raise ConfigError(
                f"{file_var} integrity check failed: configured {sha}, "
                f"but the file hashes to {actual}"
            )
        bundles[str(n)] = Bundle(bundle_id=str(n), path=str(bundle_file), sha256=sha)
    if not bundles:
        raise ConfigError(
            f"configure at least one bundle via BUNDLE_<1..{MAX_BUNDLES}>_FILE "
            "and BUNDLE_<n>_SHA256"
        )
    return bundles


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env

    origin = env.get("PUBLIC_ORIGIN", "http://localhost:8080").strip().rstrip("/")
    if not origin.startswith(("http://", "https://")):
        raise ConfigError(
            "PUBLIC_ORIGIN must be an absolute http(s) origin, "
            "e.g. https://lab.example:8080"
        )

    key_file = _require(env, "ISSUER_PUBLIC_KEY_FILE")
    try:
        pem = Path(key_file).read_text()
        key = load_pem_public_key(pem.encode())
    except (OSError, ValueError) as exc:
        raise ConfigError(
            f"ISSUER_PUBLIC_KEY_FILE is unreadable or not a PEM public key: {exc}"
        ) from exc
    if not (isinstance(key, EllipticCurvePublicKey) and isinstance(key.curve, SECP256R1)):
        raise ConfigError("issuer public key must be an ECDSA P-256 (ES256) key")

    return Settings(
        public_origin=origin,
        token_issuer=_require(env, "TOKEN_ISSUER"),
        token_audience=_require(env, "TOKEN_AUDIENCE"),
        issuer_public_key_pem=pem,
        replay_db_path=env.get("REPLAY_DB_PATH", "/data/replay.db").strip()
        or "/data/replay.db",
        dpop_iat_window_seconds=_int(env, "DPOP_IAT_WINDOW_SECONDS", 120, 1),
        token_clock_skew_seconds=_int(env, "TOKEN_CLOCK_SKEW_SECONDS", 30, 0),
        replay_retention_seconds=_int(env, "REPLAY_RETENTION_SECONDS", 86400, 60),
        bundles=_load_bundles(env),
    )
