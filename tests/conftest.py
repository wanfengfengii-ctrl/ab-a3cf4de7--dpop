import hashlib
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app
from app.security import jwk_thumbprint
from client import mint

ISSUER = "https://issuer.calibration-lab.example"
AUDIENCE = "calibration-bundles"
ORIGIN = "http://localhost:8080"
BUNDLE_CONTENT = b"calibration-evidence-" + bytes(range(256)) * 4


@pytest.fixture()
def issuer_key():
    return mint.generate_ec_key()


@pytest.fixture()
def dpop_key():
    return mint.generate_ec_key()


@pytest.fixture()
def rogue_key():
    return mint.generate_ec_key()


@pytest.fixture()
def bundle_file(tmp_path):
    path = tmp_path / "bundle-1.bin"
    path.write_bytes(BUNDLE_CONTENT)
    return path


@pytest.fixture()
def settings(tmp_path, issuer_key, bundle_file):
    issuer_pub = tmp_path / "issuer_public.pem"
    issuer_pub.write_text(mint.public_key_to_pem(issuer_key.public_key()))
    env = {
        "PUBLIC_ORIGIN": ORIGIN,
        "TOKEN_ISSUER": ISSUER,
        "TOKEN_AUDIENCE": AUDIENCE,
        "ISSUER_PUBLIC_KEY_FILE": str(issuer_pub),
        "REPLAY_DB_PATH": str(tmp_path / "replay.db"),
        "DPOP_IAT_WINDOW_SECONDS": "120",
        "TOKEN_CLOCK_SKEW_SECONDS": "30",
        "BUNDLE_1_FILE": str(bundle_file),
        "BUNDLE_1_SHA256": hashlib.sha256(BUNDLE_CONTENT).hexdigest(),
    }
    return load_settings(env)


@pytest.fixture()
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture()
def dpop_jkt(dpop_key):
    return jwk_thumbprint(mint.jwk_from_public_key(dpop_key.public_key()))


@pytest.fixture()
def valid_token(issuer_key, dpop_jkt):
    return mint.make_access_token(
        mint.private_key_to_pem(issuer_key),
        issuer=ISSUER,
        audience=AUDIENCE,
        subject="partner-007",
        scope="bundles:read bundles:admin",
        jkt=dpop_jkt,
    )


def make_proof(dpop_key, token, bundle_id="1", **overrides):
    params = {
        "htm": "GET",
        "htu": f"{ORIGIN}/api/calibration-bundles/{bundle_id}",
        "ath": mint.ath_for(token),
    }
    params.update(overrides)
    return mint.make_dpop_proof(mint.private_key_to_pem(dpop_key), **params)


def auth_headers(token, proof):
    return {"Authorization": f"DPoP {token}", "DPoP": proof}


@pytest.fixture()
def live_server(settings):
    """Run the app through real uvicorn so concurrency is genuinely parallel."""
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = uvicorn.Server(
        uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("uvicorn did not start")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture()
def http():
    with httpx.Client(timeout=10) as c:
        yield c
