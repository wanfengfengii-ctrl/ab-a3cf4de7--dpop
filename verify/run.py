"""One-shot verify service.

Runs after the app reports healthy, then:
  1. code tests      - pytest suite against the shipped sources
  2. build           - byte-compile all sources (catches syntax/packaging faults)
  3. smoke: download - valid token+proof returns exact bytes and digest header
  4. smoke: restart  - a proof consumed before an app restart is still rejected
                       (only when the Docker socket is mounted; else skipped)
  5. smoke: tamper   - each signature/binding/freshness violation maps to its
                       stable error code
  6. smoke: replay   - one proof fired concurrently is admitted exactly once

Exit code 0 iff every executed step passed; the container then exits.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from app.security import jwk_thumbprint
from client import mint

APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://app:8000")
PUBLIC_ORIGIN = os.environ.get("PUBLIC_ORIGIN", "http://localhost:8080").rstrip("/")
TOKEN_ISSUER = os.environ.get("TOKEN_ISSUER", "")
TOKEN_AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "")
PRIVATE_KEYS_DIR = Path(os.environ.get("PRIVATE_KEYS_DIR", "/keys-private"))
BUNDLES_DIR = Path(os.environ.get("BUNDLES_DIR", "/bundles"))
SMOKE_BUNDLE_ID = os.environ.get("SMOKE_BUNDLE_ID", "1")
APP_CONTAINER = os.environ.get("APP_CONTAINER_NAME", "calibration-app")
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
HEALTH_TIMEOUT = int(os.environ.get("HEALTH_TIMEOUT_SECONDS", "90"))
SRC_DIRS = ["app", "client", "verify", "tests"]

URL_PATH = f"/api/calibration-bundles/{SMOKE_BUNDLE_ID}"
HTU = f"{PUBLIC_ORIGIN}{URL_PATH}"

RESULTS: list[tuple[str, bool, str]] = []


def run_step(name: str, fn) -> bool:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - report any failure as a failed step
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        print(f"[FAIL] {name} - {type(exc).__name__}: {exc}", flush=True)
        return False
    RESULTS.append((name, True, ""))
    print(f"[PASS] {name}", flush=True)
    return True


def wait_for_health() -> None:
    deadline = time.time() + HEALTH_TIMEOUT
    url = f"{APP_BASE_URL}/healthz"
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=3).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise TimeoutError(f"app at {url} not healthy within {HEALTH_TIMEOUT}s")


def code_tests() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests"],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise AssertionError(f"pytest exited with {proc.returncode}")


def build_check() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", *SRC_DIRS],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise AssertionError(f"compileall exited with {proc.returncode}")


class Smoke:
    """HTTP smoke tests against the live app container."""

    def __init__(self) -> None:
        self.issuer_private_pem = (PRIVATE_KEYS_DIR / "issuer_es256_private.pem").read_text()
        self.dpop_key = mint.generate_ec_key()
        self.dpop_private_pem = mint.private_key_to_pem(self.dpop_key)
        self.jkt = jwk_thumbprint(mint.jwk_from_public_key(self.dpop_key.public_key()))
        self.rogue_key = mint.generate_ec_key()
        self.bundle_bytes = (BUNDLES_DIR / f"bundle-{SMOKE_BUNDLE_ID}.bin").read_bytes()
        self.bundle_sha = hashlib.sha256(self.bundle_bytes).hexdigest()
        self.client = httpx.Client(base_url=APP_BASE_URL, timeout=10)
        self._consumed: tuple[str, str] | None = None

    # -- helpers -----------------------------------------------------------

    def token(self, **overrides) -> str:
        params = {
            "issuer": TOKEN_ISSUER,
            "audience": TOKEN_AUDIENCE,
            "subject": "verify-smoke",
            "scope": "bundles:read",
            "jkt": self.jkt,
        }
        params.update(overrides)
        return mint.make_access_token(self.issuer_private_pem, **params)

    def proof(self, token: str, **overrides) -> str:
        params = {"htm": "GET", "htu": HTU, "ath": mint.ath_for(token)}
        params.update(overrides)
        return mint.make_dpop_proof(self.dpop_private_pem, **params)

    def get(self, token: str, proof: str) -> httpx.Response:
        return self.client.get(
            URL_PATH, headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )

    def expect(self, status: int, code: str, *, token=None, proof=None, headers=None,
               token_kw=None, proof_kw=None) -> None:
        token = token if token is not None else self.token(**(token_kw or {}))
        proof = proof if proof is not None else self.proof(token, **(proof_kw or {}))
        headers = headers if headers is not None else {
            "Authorization": f"DPoP {token}", "DPoP": proof
        }
        resp = self.client.get(URL_PATH, headers=headers)
        assert resp.status_code == status, (
            f"[{code}] expected HTTP {status}, got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert body.get("error") == code, f"expected error {code!r}, got {body}"
        if status == 401:
            assert "www-authenticate" in {k.lower() for k in resp.headers}

    # -- steps -------------------------------------------------------------

    def download(self) -> None:
        token = self.token()
        proof = self.proof(token)
        resp = self.get(token, proof)
        assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
        assert resp.content == self.bundle_bytes, "downloaded bytes differ from the evidence file"
        assert resp.headers.get("x-content-sha256") == self.bundle_sha, "digest header mismatch"

        # a second, fresh proof must yield byte-identical evidence
        token2 = self.token()
        resp2 = self.get(token2, self.proof(token2))
        assert resp2.status_code == 200 and resp2.content == resp.content

        self._consumed = (token, proof)

    def restart_persistence(self) -> None:
        import stat

        if not (
            os.path.exists(DOCKER_SOCKET)
            and stat.S_ISSOCK(os.stat(DOCKER_SOCKET).st_mode)
        ):
            print("  docker socket not mounted - skipping restart check", flush=True)
            return
        assert self._consumed, "download step must run first"
        token, proof = self._consumed
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=DOCKER_SOCKET),
            base_url="http://docker",
            timeout=30,
        ) as docker:
            resp = docker.post(f"/containers/{APP_CONTAINER}/restart", params={"t": "5"})
            assert resp.status_code == 204, f"restart failed: {resp.status_code} {resp.text}"
        wait_for_health()
        resp = self.get(token, proof)
        assert resp.status_code == 401, f"expected 401 after restart, got {resp.status_code}"
        assert resp.json().get("error") == "dpop_replay_detected", (
            f"consumed proof must stay consumed across restarts, got {resp.text}"
        )

    def tamper(self) -> None:
        now = int(time.time())
        rogue_pem = mint.private_key_to_pem(self.rogue_key)
        rogue_jkt = jwk_thumbprint(mint.jwk_from_public_key(self.rogue_key.public_key()))

        self.expect(401, "missing_token", headers={})
        self.expect(401, "invalid_token_type",
                    headers={"Authorization": f"Bearer {self.token()}", "DPoP": "x"})
        self.expect(401, "missing_dpop_proof",
                    headers={"Authorization": f"DPoP {self.token()}"})
        self.expect(401, "invalid_token_signature",
                    token=mint.make_access_token(
                        rogue_pem, issuer=TOKEN_ISSUER, audience=TOKEN_AUDIENCE,
                        subject="s", scope="bundles:read", jkt=self.jkt))
        self.expect(401, "invalid_issuer", token_kw={"issuer": "https://evil.example"})
        self.expect(401, "invalid_audience", token_kw={"audience": "other-service"})
        self.expect(401, "missing_subject", token_kw={"subject": None})
        self.expect(403, "insufficient_scope", token_kw={"scope": "bundles:write"})
        self.expect(401, "token_expired",
                    token_kw={"issued_at": now - 1000, "expires_in": 10})
        self.expect(401, "token_not_yet_valid", token_kw={"not_before": now + 3600})
        self.expect(401, "missing_cnf", token_kw={"jkt": None})
        self.expect(401, "dpop_key_binding_mismatch", token_kw={"jkt": rogue_jkt})
        self.expect(401, "invalid_dpop_typ", proof_kw={"typ": "JWT"})
        self.expect(401, "invalid_htm", proof_kw={"htm": "POST"})
        self.expect(401, "invalid_htu",
                    proof_kw={"htu": f"{PUBLIC_ORIGIN}/api/calibration-bundles/999"})
        self.expect(401, "dpop_proof_expired", proof_kw={"iat": now - 3600})
        self.expect(401, "invalid_ath", proof_kw={"ath": mint.ath_for("forged-token")})
        self.expect(401, "missing_jti", proof_kw={"jti": ""})

        # proof signed by a rogue key but embedding the bound key's jwk
        token = self.token()
        forged = mint.make_dpop_proof(
            rogue_pem, htm="GET", htu=HTU, ath=mint.ath_for(token),
            jwk=mint.jwk_from_public_key(self.dpop_key.public_key()),
        )
        self.expect(401, "invalid_dpop_signature", token=token, proof=forged)

        # unknown bundle id with otherwise fully valid credentials
        token9 = self.token()
        proof9 = mint.make_dpop_proof(
            self.dpop_private_pem, htm="GET",
            htu=f"{PUBLIC_ORIGIN}/api/calibration-bundles/9",
            ath=mint.ath_for(token9),
        )
        resp = self.client.get(
            "/api/calibration-bundles/9",
            headers={"Authorization": f"DPoP {token9}", "DPoP": proof9},
        )
        assert resp.status_code == 404 and resp.json().get("error") == "bundle_not_found"

    def concurrent_replay(self) -> None:
        token = self.token()
        proof = self.proof(token)
        headers = {"Authorization": f"DPoP {token}", "DPoP": proof}
        url = f"{APP_BASE_URL}{URL_PATH}"

        def hit(_):
            with httpx.Client(timeout=10) as client:
                return client.get(url, headers=headers)

        n = 16
        with ThreadPoolExecutor(max_workers=n) as pool:
            responses = list(pool.map(hit, range(n)))

        winners = [r for r in responses if r.status_code == 200]
        replays = [
            r for r in responses
            if r.status_code == 401 and r.json().get("error") == "dpop_replay_detected"
        ]
        assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}"
        assert len(replays) == n - 1, f"expected {n - 1} replay rejections, got {len(replays)}"
        assert winners[0].content == self.bundle_bytes


def main() -> int:
    print("== verify: waiting for app health ==", flush=True)
    if not run_step("wait_for_health", wait_for_health):
        return summarize()

    run_step("code_tests_pytest", code_tests)
    run_step("build_compileall", build_check)

    smoke = Smoke()
    run_step("smoke_download", smoke.download)
    run_step("smoke_restart_persistence", smoke.restart_persistence)
    run_step("smoke_tamper", smoke.tamper)
    run_step("smoke_concurrent_replay", smoke.concurrent_replay)
    return summarize()


def summarize() -> int:
    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"== verify: {len(RESULTS) - len(failed)}/{len(RESULTS)} steps passed ==", flush=True)
    if failed:
        print("failed steps: " + ", ".join(failed), flush=True)
        return 1
    print("verify: ALL CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
