"""Mint ES256 access tokens and DPoP proofs (demo issuer / reference client)."""
from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from app.security import jwk_thumbprint, sha256_b64url  # noqa: F401  (re-exported)


def generate_ec_key() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_to_pem(key: EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def public_key_to_pem(key) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _b64url_int(value: int) -> str:
    import base64

    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def jwk_from_public_key(public_key) -> dict:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_int(numbers.x),
        "y": _b64url_int(numbers.y),
    }


def ath_for(access_token: str) -> str:
    """ath claim: base64url-no-pad SHA-256 of the ASCII access token."""
    return sha256_b64url(access_token.encode("ascii"))


def make_access_token(
    private_key_pem: str,
    *,
    issuer: str,
    audience: str,
    subject: str | None,
    scope: str,
    jkt: str | None,
    expires_in: int = 300,
    issued_at: int | None = None,
    not_before: int | None = None,
    extra_claims: dict | None = None,
    alg: str = "ES256",
) -> str:
    iat = int(time.time()) if issued_at is None else issued_at
    claims = {
        "iss": issuer,
        "aud": audience,
        "iat": iat,
        "nbf": iat - 1 if not_before is None else not_before,
        "exp": iat + expires_in,
        "scope": scope,
    }
    if subject is not None:
        claims["sub"] = subject
    if jkt is not None:
        claims["cnf"] = {"jkt": jkt}
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, private_key_pem, algorithm=alg)


def make_dpop_proof(
    private_key_pem: str,
    *,
    htm: str,
    htu: str,
    ath: str,
    iat: int | None = None,
    jti: str | None = None,
    typ: str = "dpop+jwt",
    jwk: dict | None = None,
    alg: str = "ES256",
) -> str:
    headers = {"typ": typ}
    if jwk is None:
        key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        headers["jwk"] = jwk_from_public_key(key.public_key())
    else:
        headers["jwk"] = jwk
    claims = {
        "jti": uuid.uuid4().hex if jti is None else jti,
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
        "ath": ath,
    }
    return jwt.encode(claims, private_key_pem, algorithm=alg, headers=headers)
