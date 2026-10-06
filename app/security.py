"""ES256 access-token and DPoP proof validation (RFC 9449 style).

Access token (JWT, ES256, registered issuer):
  iss / aud / sub / scope "bundles:read" / exp+nbf freshness / cnf.jkt

DPoP proof (JWT, ES256, key bound to the token via cnf.jkt):
  typ "dpop+jwt" / embedded public jwk / signature / jti single-use /
  iat within a short window / htm == GET / htu == public origin + path /
  ath == base64url(SHA-256(access token))

Every rejection raises ApiError with a stable code from app.errors.codes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt
from jwt.algorithms import ECAlgorithm
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from app.config import Settings
from app.errors import ApiError, codes
from app.replay import ReplayStore

REQUIRED_SCOPE = "bundles:read"
DPOP_TYP = "dpop+jwt"
ES256 = "ES256"
_MAX_JTI_LEN = 512
_JKT_RE_LEN = 43  # base64url-no-pad of a SHA-256 digest


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_b64url(data: bytes) -> str:
    return _b64url_nopad(hashlib.sha256(data).digest())


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint of an EC P-256 public JWK."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    encoded = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_nopad(hashlib.sha256(encoded).digest())


def validate_access_token(token: str, settings: Settings, issuer_public_key_pem: str) -> dict:
    """Verify the sender-constrained access token; return its claims."""
    try:
        header = jwt.get_unverified_header(token)
    except DecodeError as exc:
        raise ApiError(401, codes.MALFORMED_TOKEN, "access token is not a well-formed JWT") from exc
    if header.get("alg") != ES256:
        raise ApiError(401, codes.INVALID_TOKEN_ALG, "access token must be signed with ES256")

    try:
        claims = jwt.decode(
            token,
            issuer_public_key_pem,
            algorithms=[ES256],
            audience=settings.token_audience,
            issuer=settings.token_issuer,
            leeway=settings.token_clock_skew_seconds,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except ExpiredSignatureError as exc:
        raise ApiError(401, codes.TOKEN_EXPIRED, "access token has expired") from exc
    except ImmatureSignatureError as exc:
        raise ApiError(401, codes.TOKEN_NOT_YET_VALID, "access token is not yet valid (nbf)") from exc
    except InvalidIssuerError as exc:
        raise ApiError(401, codes.INVALID_ISSUER, "access token issuer is not registered") from exc
    except InvalidAudienceError as exc:
        raise ApiError(401, codes.INVALID_AUDIENCE, "access token audience does not match this service") from exc
    except MissingRequiredClaimError as exc:
        if exc.claim == "sub":
            raise ApiError(401, codes.MISSING_SUBJECT, "access token must carry a subject (sub)") from exc
        raise ApiError(401, codes.MALFORMED_TOKEN, f"access token is missing claim {exc.claim!r}") from exc
    except InvalidSignatureError as exc:
        raise ApiError(401, codes.INVALID_TOKEN_SIGNATURE, "access token signature verification failed") from exc
    except (DecodeError, InvalidIssuedAtError, InvalidTokenError) as exc:
        raise ApiError(401, codes.MALFORMED_TOKEN, "access token is not a well-formed JWT") from exc

    if not isinstance(claims.get("sub"), str) or not claims["sub"].strip():
        raise ApiError(401, codes.MISSING_SUBJECT, "access token must carry a subject (sub)")

    scope = claims.get("scope", "")
    granted = scope.split() if isinstance(scope, str) else list(scope) if isinstance(scope, list) else []
    if REQUIRED_SCOPE not in granted:
        raise ApiError(403, codes.INSUFFICIENT_SCOPE, f"scope {REQUIRED_SCOPE!r} is required")

    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str) or not cnf["jkt"]:
        raise ApiError(401, codes.MISSING_CNF, "access token must be sender-constrained via cnf.jkt")
    if len(cnf["jkt"]) != _JKT_RE_LEN:
        raise ApiError(401, codes.INVALID_CNF, "cnf.jkt must be a base64url SHA-256 JWK thumbprint")

    return claims


def validate_dpop_proof(
    proof: str,
    *,
    settings: Settings,
    method: str,
    expected_htu: str,
    access_token: str,
    expected_jkt: str,
    store: ReplayStore,
    now: float | None = None,
) -> str:
    """Verify the DPoP proof and atomically consume its jti. Returns the jkt."""
    try:
        header = jwt.get_unverified_header(proof)
    except DecodeError as exc:
        raise ApiError(401, codes.MALFORMED_DPOP_PROOF, "DPoP proof is not a well-formed JWT") from exc

    if header.get("typ") != DPOP_TYP:
        raise ApiError(401, codes.INVALID_DPOP_TYP, f"DPoP proof typ must be {DPOP_TYP!r}")
    if header.get("alg") != ES256:
        raise ApiError(401, codes.INVALID_DPOP_ALG, "DPoP proof must be signed with ES256")

    jwk = header.get("jwk")
    if (
        not isinstance(jwk, dict)
        or jwk.get("kty") != "EC"
        or jwk.get("crv") != "P-256"
        or not isinstance(jwk.get("x"), str)
        or not isinstance(jwk.get("y"), str)
        or "d" in jwk
    ):
        raise ApiError(401, codes.INVALID_DPOP_JWK, "DPoP proof must embed a public EC P-256 jwk")
    try:
        proof_key = ECAlgorithm.from_jwk(json.dumps(jwk))
    except (InvalidKeyError, ValueError) as exc:
        raise ApiError(401, codes.INVALID_DPOP_JWK, "embedded jwk is not a valid P-256 key") from exc

    try:
        claims = jwt.decode(proof, key=proof_key, algorithms=[ES256], options={"verify_aud": False})
    except InvalidSignatureError as exc:
        raise ApiError(401, codes.INVALID_DPOP_SIGNATURE, "DPoP proof signature verification failed") from exc
    except (ExpiredSignatureError, ImmatureSignatureError) as exc:
        raise ApiError(401, codes.DPOP_PROOF_EXPIRED, "DPoP proof iat is outside the allowed window") from exc
    except (DecodeError, InvalidIssuedAtError) as exc:
        raise ApiError(401, codes.MALFORMED_DPOP_PROOF, "DPoP proof is not a well-formed JWT") from exc

    jkt = jwk_thumbprint(jwk)
    if not hmac.compare_digest(jkt, expected_jkt):
        raise ApiError(
            401,
            codes.DPOP_KEY_BINDING_MISMATCH,
            "proof key does not match the access token cnf.jkt binding",
        )

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > _MAX_JTI_LEN:
        raise ApiError(401, codes.MISSING_JTI, "DPoP proof must carry a unique jti")

    if claims.get("htm") != method:
        raise ApiError(401, codes.INVALID_HTM, f"DPoP proof htm must be {method!r}")

    if claims.get("htu") != expected_htu:
        raise ApiError(401, codes.INVALID_HTU, "DPoP proof htu must be the full public URL of this resource")

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise ApiError(401, codes.MALFORMED_DPOP_PROOF, "DPoP proof iat must be a numeric date")
    now = time.time() if now is None else now
    if abs(now - iat) > settings.dpop_iat_window_seconds:
        raise ApiError(401, codes.DPOP_PROOF_EXPIRED, "DPoP proof iat is outside the allowed window")

    expected_ath = sha256_b64url(access_token.encode("ascii"))
    ath = claims.get("ath")
    if not isinstance(ath, str) or not hmac.compare_digest(ath, expected_ath):
        raise ApiError(401, codes.INVALID_ATH, "DPoP proof ath does not match the access token")

    if not store.claim(jkt, jti, int(iat), now=now):
        raise ApiError(401, codes.DPOP_REPLAY_DETECTED, "this DPoP proof has already been used")

    return jkt
