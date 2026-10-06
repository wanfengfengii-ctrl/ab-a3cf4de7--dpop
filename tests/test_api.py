import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from app.config import ConfigError, load_settings
from app.errors import codes
from app.replay import ReplayStore
from app.security import jwk_thumbprint
from client import mint
from tests.conftest import (
    AUDIENCE,
    BUNDLE_CONTENT,
    ISSUER,
    ORIGIN,
    auth_headers,
    make_proof,
)

BUNDLE_SHA = hashlib.sha256(BUNDLE_CONTENT).hexdigest()
URL = "/api/calibration-bundles/1"


# ---------------------------------------------------------------- happy path


def test_download_returns_exact_bytes_and_digest(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token)
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 200
    assert resp.content == BUNDLE_CONTENT
    assert resp.headers["x-content-sha256"] == BUNDLE_SHA
    assert resp.headers["x-content-sha256"] == resp.headers["x-content-sha256"].lower()
    assert resp.headers["cache-control"] == "no-store"


def test_repeated_downloads_are_byte_identical(client, valid_token, dpop_key):
    bodies = []
    for _ in range(3):
        proof = make_proof(dpop_key, valid_token)  # fresh jti each time
        resp = client.get(URL, headers=auth_headers(valid_token, proof))
        assert resp.status_code == 200
        bodies.append(resp.content)
    assert bodies[0] == bodies[1] == bodies[2] == BUNDLE_CONTENT


# ------------------------------------------------------- access token checks


def test_missing_authorization_header(client):
    resp = client.get(URL)
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.MISSING_TOKEN
    assert "DPoP" in resp.headers["www-authenticate"]


def test_bearer_scheme_rejected(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token)
    resp = client.get(URL, headers={"Authorization": f"Bearer {valid_token}", "DPoP": proof})
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_TOKEN_TYPE


def test_missing_dpop_header(client, valid_token):
    resp = client.get(URL, headers={"Authorization": f"DPoP {valid_token}"})
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.MISSING_DPOP_PROOF


def test_token_signed_by_wrong_key(client, rogue_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(rogue_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read", jkt=dpop_jkt,
    )
    proof = make_proof(dpop_key, token)
    resp = client.get(URL, headers=auth_headers(token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_TOKEN_SIGNATURE


def test_token_wrong_alg(client, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        "shared-secret",
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read",
        jkt=dpop_jkt, alg="HS256",
    )
    proof = make_proof(dpop_key, token)
    resp = client.get(URL, headers=auth_headers(token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_TOKEN_ALG


def test_wrong_issuer(client, issuer_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer="https://evil.example", audience=AUDIENCE, subject="s",
        scope="bundles:read", jkt=dpop_jkt,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_ISSUER


def test_wrong_audience(client, issuer_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience="someone-else", subject="s",
        scope="bundles:read", jkt=dpop_jkt,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_AUDIENCE


def test_missing_subject(client, issuer_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject=None,
        scope="bundles:read", jkt=dpop_jkt,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.MISSING_SUBJECT


def test_insufficient_scope(client, issuer_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s",
        scope="bundles:write", jkt=dpop_jkt,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 403
    assert resp.json()["error"] == codes.INSUFFICIENT_SCOPE


def test_expired_token(client, issuer_key, dpop_key, dpop_jkt):
    now = int(time.time())
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read",
        jkt=dpop_jkt, issued_at=now - 1000, expires_in=10,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.TOKEN_EXPIRED


def test_not_yet_valid_token(client, issuer_key, dpop_key, dpop_jkt):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read",
        jkt=dpop_jkt, not_before=int(time.time()) + 3600,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.TOKEN_NOT_YET_VALID


def test_missing_cnf(client, issuer_key, dpop_key):
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read", jkt=None,
    )
    resp = client.get(URL, headers=auth_headers(token, make_proof(dpop_key, token)))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.MISSING_CNF


# ---------------------------------------------------------- DPoP proof checks


def test_dpop_wrong_typ(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, typ="JWT")
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_DPOP_TYP


def test_dpop_wrong_alg(client, valid_token, dpop_key):
    import jwt as pyjwt

    proof = pyjwt.encode(
        {"jti": "x", "htm": "GET", "htu": f"{ORIGIN}/api/calibration-bundles/1",
         "iat": int(time.time()), "ath": mint.ath_for(valid_token)},
        "shared-secret",
        algorithm="HS256",
        headers={"typ": "dpop+jwt",
                 "jwk": mint.jwk_from_public_key(dpop_key.public_key())},
    )
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_DPOP_ALG


def test_dpop_signature_mismatch(client, valid_token, dpop_key, rogue_key):
    # signed by rogue key, but the embedded jwk claims to be the dpop key
    proof = mint.make_dpop_proof(
        mint.private_key_to_pem(rogue_key),
        htm="GET", htu=f"{ORIGIN}/api/calibration-bundles/1",
        ath=mint.ath_for(valid_token),
        jwk=mint.jwk_from_public_key(dpop_key.public_key()),
    )
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_DPOP_SIGNATURE


def test_dpop_key_binding_mismatch(client, issuer_key, dpop_key, rogue_key):
    rogue_jkt = jwk_thumbprint(mint.jwk_from_public_key(rogue_key.public_key()))
    token = mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER, audience=AUDIENCE, subject="s", scope="bundles:read", jkt=rogue_jkt,
    )
    proof = make_proof(dpop_key, token)  # proof key != bound key
    resp = client.get(URL, headers=auth_headers(token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.DPOP_KEY_BINDING_MISMATCH


def test_dpop_wrong_method(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, htm="POST")
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_HTM


def test_dpop_wrong_htu(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, htu=f"{ORIGIN}/api/calibration-bundles/2")
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_HTU


def test_dpop_stale_iat(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, iat=int(time.time()) - 3600)
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.DPOP_PROOF_EXPIRED


def test_dpop_future_iat(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, iat=int(time.time()) + 3600)
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.DPOP_PROOF_EXPIRED


def test_dpop_bad_ath(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, ath=mint.ath_for("some-other-token"))
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.INVALID_ATH


def test_dpop_missing_jti(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, jti="")
    resp = client.get(URL, headers=auth_headers(valid_token, proof))
    assert resp.status_code == 401
    assert resp.json()["error"] == codes.MISSING_JTI


def test_dpop_replay_rejected(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token)
    headers = auth_headers(valid_token, proof)
    assert client.get(URL, headers=headers).status_code == 200
    second = client.get(URL, headers=headers)
    assert second.status_code == 401
    assert second.json()["error"] == codes.DPOP_REPLAY_DETECTED


# ------------------------------------------------------- concurrency & restart


def test_concurrent_replay_single_winner(live_server, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token)
    headers = auth_headers(valid_token, proof)
    url = f"{live_server}{URL}"

    def hit(_):
        with httpx.Client(timeout=10) as c:
            return c.get(url, headers=headers)

    n = 16
    with ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(hit, range(n)))

    winners = [r for r in responses if r.status_code == 200]
    replays = [
        r for r in responses
        if r.status_code == 401 and r.json().get("error") == codes.DPOP_REPLAY_DETECTED
    ]
    assert len(winners) == 1, f"expected exactly one success, got {len(winners)}"
    assert len(replays) == n - 1
    assert winners[0].content == BUNDLE_CONTENT


def test_replay_store_survives_reopen(tmp_path):
    db = str(tmp_path / "replay.db")
    store = ReplayStore(db)
    assert store.claim("jkt-a", "jti-1", iat=100) is True
    assert store.claim("jkt-a", "jti-1", iat=100) is False
    store.close()

    reopened = ReplayStore(db)  # simulates a container restart on the same volume
    assert reopened.claim("jkt-a", "jti-1", iat=100) is False
    # a different key may reuse the same jti value
    assert reopened.claim("jkt-b", "jti-1", iat=100) is True
    reopened.close()


# ------------------------------------------------------------------ bundle 404


def test_unknown_bundle_is_404(client, valid_token, dpop_key):
    proof = make_proof(dpop_key, valid_token, bundle_id="9")
    resp = client.get("/api/calibration-bundles/9", headers=auth_headers(valid_token, proof))
    assert resp.status_code == 404
    assert resp.json()["error"] == codes.BUNDLE_NOT_FOUND


# ------------------------------------------------------------ config validation


def _base_env(tmp_path, bundle_file, issuer_pub):
    return {
        "PUBLIC_ORIGIN": ORIGIN,
        "TOKEN_ISSUER": ISSUER,
        "TOKEN_AUDIENCE": AUDIENCE,
        "ISSUER_PUBLIC_KEY_FILE": str(issuer_pub),
        "REPLAY_DB_PATH": str(tmp_path / "replay.db"),
        "BUNDLE_1_FILE": str(bundle_file),
        "BUNDLE_1_SHA256": hashlib.sha256(BUNDLE_CONTENT).hexdigest(),
    }


def test_config_rejects_uppercase_digest(tmp_path, bundle_file, issuer_key):
    pub = tmp_path / "pub.pem"
    pub.write_text(mint.public_key_to_pem(issuer_key.public_key()))
    env = _base_env(tmp_path, bundle_file, pub)
    env["BUNDLE_1_SHA256"] = env["BUNDLE_1_SHA256"].upper()
    with pytest.raises(ConfigError, match="lowercase"):
        load_settings(env)


def test_config_rejects_digest_mismatch(tmp_path, bundle_file, issuer_key):
    pub = tmp_path / "pub.pem"
    pub.write_text(mint.public_key_to_pem(issuer_key.public_key()))
    env = _base_env(tmp_path, bundle_file, pub)
    env["BUNDLE_1_SHA256"] = "0" * 64
    with pytest.raises(ConfigError, match="integrity"):
        load_settings(env)


def test_config_requires_paired_bundle_vars(tmp_path, bundle_file, issuer_key):
    pub = tmp_path / "pub.pem"
    pub.write_text(mint.public_key_to_pem(issuer_key.public_key()))
    env = _base_env(tmp_path, bundle_file, pub)
    del env["BUNDLE_1_SHA256"]
    with pytest.raises(ConfigError, match="together"):
        load_settings(env)


def test_config_requires_at_least_one_bundle(tmp_path, issuer_key):
    pub = tmp_path / "pub.pem"
    pub.write_text(mint.public_key_to_pem(issuer_key.public_key()))
    env = _base_env(tmp_path, tmp_path / "missing.bin", pub)
    del env["BUNDLE_1_FILE"], env["BUNDLE_1_SHA256"]
    with pytest.raises(ConfigError, match="at least one bundle"):
        load_settings(env)


def test_error_body_shape(client):
    resp = client.get(URL)
    body = resp.json()
    assert set(body) == {"error", "error_description"}
