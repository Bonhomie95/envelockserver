"""Security headers, request limits and rate-limit enforcement."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from envelock.security.limits import MAX_RAW_MESSAGE_BYTES, active_limiter

#: Route prefix → rate-limit bucket. Most specific match wins.
_BUCKETS: tuple[tuple[str, str], ...] = (
    ("/api/v1/auth/login", "auth.login"),
    ("/api/v1/auth/register", "auth.register"),
    ("/api/v1/auth/mfa", "auth.mfa"),
    ("/api/v1/auth/recovery", "auth.recovery"),
    ("/api/v1/auth/refresh", "auth.refresh"),
    ("/api/v1/analyse", "analyse"),
    ("/api/v1/domains", "scan.domain"),
    ("/api/v1/export", "export"),
)


def _bucket_for(path: str) -> str:
    for prefix, bucket in _BUCKETS:
        if path.startswith(prefix):
            return bucket
    return "default"


def client_identity(request: Request) -> str:
    """Prefer the authenticated subject; fall back to peer address.

    `X-Forwarded-For` is deliberately NOT trusted by default — anyone can send
    it, so honouring it hands an attacker a trivial rate-limit bypass. Enable it
    only behind a proxy you control, via `trust_forwarded`.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        # Bucket by token identity without parsing it: a stable hash is enough
        # and avoids doing crypto work before the limiter has run.
        return f"tok:{hash(auth[7:60]) & 0xFFFFFFFF:08x}"
    if request.client:
        return f"ip:{request.client.host}"
    return "ip:unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defence-in-depth headers on every response."""

    def __init__(self, app, *, production: bool) -> None:  # noqa: ANN001
        super().__init__(app)
        self.production = production

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        # The API returns JSON only; nothing should ever be rendered from it.
        h["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        h["Cache-Control"] = "no-store"
        if self.production:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        # Do not advertise the stack. MutableHeaders has no pop().
        if "server" in h:
            del h["server"]
        return response


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Body-size ceiling and rate limiting, applied before routing work."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_RAW_MESSAGE_BYTES:
            return JSONResponse(
                {"detail": "request body too large"},
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        if request.url.path.startswith("/api/"):
            bucket = _bucket_for(request.url.path)
            allowed, retry_after = await active_limiter().acheck(
                bucket, client_identity(request)
            )
            if not allowed:
                return JSONResponse(
                    {"detail": "rate limit exceeded", "retry_after": retry_after},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)
