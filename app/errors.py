"""Stable, machine-readable error codes returned by the bundle API.

Every failure response is JSON: {"error": <code>, "error_description": <text>}.
The codes below are part of the API contract and must not be renamed; clients
(and the verify service) rely on them to distinguish signature, binding,
freshness and replay failures.
"""
from __future__ import annotations


class codes:  # noqa: N801 - namespace of constants, not a class to instantiate
    # --- access token failures ---
    MISSING_TOKEN = "missing_token"
    MALFORMED_TOKEN = "malformed_token"
    INVALID_TOKEN_TYPE = "invalid_token_type"
    INVALID_TOKEN_ALG = "invalid_token_alg"
    INVALID_TOKEN_SIGNATURE = "invalid_token_signature"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_AUDIENCE = "invalid_audience"
    MISSING_SUBJECT = "missing_subject"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    MISSING_CNF = "missing_cnf"
    INVALID_CNF = "invalid_cnf"

    # --- DPoP proof failures ---
    MISSING_DPOP_PROOF = "missing_dpop_proof"
    MALFORMED_DPOP_PROOF = "malformed_dpop_proof"
    INVALID_DPOP_TYP = "invalid_dpop_typ"
    INVALID_DPOP_ALG = "invalid_dpop_alg"
    INVALID_DPOP_JWK = "invalid_dpop_jwk"
    INVALID_DPOP_SIGNATURE = "invalid_dpop_signature"
    DPOP_KEY_BINDING_MISMATCH = "dpop_key_binding_mismatch"
    INVALID_HTM = "invalid_htm"
    INVALID_HTU = "invalid_htu"
    DPOP_PROOF_EXPIRED = "dpop_proof_expired"
    INVALID_ATH = "invalid_ath"
    MISSING_JTI = "missing_jti"
    DPOP_REPLAY_DETECTED = "dpop_replay_detected"

    # --- bundle lookup ---
    BUNDLE_NOT_FOUND = "bundle_not_found"


class ApiError(Exception):
    """An HTTP error carrying a stable machine-readable code."""

    def __init__(self, status_code: int, code: str, description: str):
        super().__init__(f"{code}: {description}")
        self.status_code = status_code
        self.code = code
        self.description = description
