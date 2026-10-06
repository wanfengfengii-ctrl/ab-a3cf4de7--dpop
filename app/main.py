"""HTTP surface: GET /api/calibration-bundles/{bundleId} guarded by DPoP."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.config import Settings
from app.errors import ApiError, codes
from app.replay import ReplayStore
from app.security import validate_access_token, validate_dpop_proof


def _extract_dpop_token(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header:
        raise ApiError(401, codes.MISSING_TOKEN, "Authorization header is required")
    parts = header.split()
    if len(parts) != 2 or not parts[1]:
        raise ApiError(401, codes.MALFORMED_TOKEN, "Authorization header must be: DPoP <jwt>")
    if parts[0].lower() != "dpop":
        raise ApiError(401, codes.INVALID_TOKEN_TYPE, "authorization scheme must be DPoP (sender-constrained)")
    return parts[1]


def create_app(settings: Settings) -> FastAPI:
    store = ReplayStore(settings.replay_db_path, settings.replay_retention_seconds)
    # Evidence files are mounted read-only and were digest-checked at config
    # load; serve the exact bytes verified at startup.
    bundle_bytes = {bid: Path(b.path).read_bytes() for bid, b in settings.bundles.items()}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        store.close()

    app = FastAPI(
        title="Calibration Bundle Service",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.replay_store = store

    @app.exception_handler(ApiError)
    async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
        headers = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = (
                f'DPoP realm="calibration-bundles", error="{exc.code}", '
                f'error_description="{exc.description}"'
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.code, "error_description": exc.description},
            headers=headers,
        )

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/api/calibration-bundles/{bundle_id}")
    def download_bundle(bundle_id: str, request: Request) -> Response:
        token = _extract_dpop_token(request)

        proof = request.headers.get("dpop")
        if not proof:
            raise ApiError(401, codes.MISSING_DPOP_PROOF, "DPoP header with a proof JWT is required")

        claims = validate_access_token(token, settings, settings.issuer_public_key_pem)
        expected_htu = f"{settings.public_origin}/api/calibration-bundles/{bundle_id}"
        validate_dpop_proof(
            proof,
            settings=settings,
            method="GET",
            expected_htu=expected_htu,
            access_token=token,
            expected_jkt=claims["cnf"]["jkt"],
            store=store,
        )

        bundle = settings.bundles.get(bundle_id)
        if bundle is None:
            raise ApiError(404, codes.BUNDLE_NOT_FOUND, f"no bundle configured with id {bundle_id!r}")

        return Response(
            content=bundle_bytes[bundle_id],
            media_type="application/octet-stream",
            headers={
                "X-Content-SHA256": bundle.sha256,
                "Content-Disposition": f'attachment; filename="bundle-{bundle_id}.bin"',
                "Cache-Control": "no-store",
            },
        )

    return app
