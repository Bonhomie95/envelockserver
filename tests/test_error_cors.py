"""A 500 must still carry the CORS header, so a real server error surfaces as a
real error in the browser instead of a misleading 'CORS policy' block."""

from __future__ import annotations

from fastapi.testclient import TestClient

from envelock.config import get_settings
from envelock.main import create_app

ALLOWED_ORIGIN = "https://envelockclient.vercel.app"


def _app_with_boom():
    app = create_app()

    @app.get("/api/v1/_boom")
    async def _boom():  # noqa: ANN202
        raise RuntimeError("kaboom")

    return app


def test_500_keeps_cors_header_for_allowed_origin() -> None:
    assert ALLOWED_ORIGIN in get_settings().cors_origin_list
    client = TestClient(_app_with_boom(), raise_server_exceptions=False)
    resp = client.get("/api/v1/_boom", headers={"Origin": ALLOWED_ORIGIN})
    assert resp.status_code == 500
    # The header the browser was complaining about is present on the error.
    assert resp.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert resp.json()["detail"] == "internal server error"


def test_500_no_cors_header_for_unknown_origin() -> None:
    client = TestClient(_app_with_boom(), raise_server_exceptions=False)
    resp = client.get("/api/v1/_boom", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 500
    # An origin we don't trust gets no ACAO header — no cross-origin leak.
    assert resp.headers.get("access-control-allow-origin") is None
