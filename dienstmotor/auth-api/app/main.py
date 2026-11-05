import hmac
import ipaddress
import logging
import os
import threading
import time
from collections import deque
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import Settings
from .oidc import AuthError, Identity, OidcValidator
from .tickets import CONN_TYPES, PEER_ID_RE, ReplayGuard, TicketError, TicketSigner

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("dm-auth")


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 50_000:
                self._hits.clear()
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            return True


def create_app(settings: Settings | None = None, http: httpx.AsyncClient | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = http or httpx.AsyncClient(timeout=settings.http_timeout, follow_redirects=False)
        app.state.oidc = OidcValidator(settings, client)
        yield
        if http is None:
            await client.aclose()

    app = FastAPI(title="Dienstmotor Remote auth", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    signer = TicketSigner(settings.ticket_signing_key, settings.ticket_issuer, settings.ticket_ttl)
    replay = ReplayGuard(settings.ticket_max_uses, settings.ticket_bind_source_ip)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    trusted = [ipaddress.ip_network(n, strict=False) for n in settings.trusted_proxies]

    def peer_ip(request: Request) -> str:
        return request.client.host if request.client else ""

    def is_trusted(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in trusted)

    def client_ip(request: Request) -> str:
        ip = peer_ip(request)
        if is_trusted(ip):
            real = request.headers.get("x-real-ip")
            if real:
                return real.strip()
        return ip

    def rate_limited(request: Request):
        if not limiter.allow(client_ip(request)):
            raise HTTPException(status_code=429, detail="too many requests")

    async def identity(request: Request) -> Identity:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        try:
            return await request.app.state.oidc.validate(auth[7:].strip())
        except AuthError as e:
            log.info("rejected access token from %s: %s", client_ip(request), e)
            status = 503 if str(e) == "identity provider unavailable" else 401
            raise HTTPException(status_code=status, detail=str(e), headers={"WWW-Authenticate": "Bearer"})

    def internal_only(request: Request):
        # nginx always adds these; their presence means the call came through the public proxy.
        if request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"):
            raise HTTPException(status_code=404)
        auth = request.headers.get("authorization", "")
        expected = "Bearer " + settings.internal_api_token
        if not hmac.compare_digest(auth.encode(), expected.encode()):
            raise HTTPException(status_code=404)
        try:
            addr = ipaddress.ip_address(peer_ip(request))
        except ValueError:
            raise HTTPException(status_code=404)
        if not (addr.is_private or addr.is_loopback):
            raise HTTPException(status_code=404)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.error("unhandled error on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/auth/config", dependencies=[Depends(rate_limited)])
    async def auth_config():
        return {
            "issuer": settings.oidc_issuer,
            "client_id": settings.oidc_client_id,
            "scopes": settings.oidc_scopes,
            "ticket_ttl": settings.ticket_ttl,
        }

    @app.get("/auth/me", dependencies=[Depends(rate_limited)])
    async def me(user: Identity = Depends(identity)):
        return {"sub": user.sub, "username": user.username, "name": user.name, "email": user.email}

    class TicketRequest(BaseModel):
        peer_id: str = Field(max_length=64)
        conn_type: str = Field(default="default", max_length=32)

    @app.post("/auth/ticket", dependencies=[Depends(rate_limited)])
    async def ticket(body: TicketRequest, request: Request, user: Identity = Depends(identity)):
        if not PEER_ID_RE.match(body.peer_id):
            raise HTTPException(status_code=400, detail="invalid peer id")
        if body.conn_type not in CONN_TYPES:
            raise HTTPException(status_code=400, detail="invalid connection type")
        t = signer.issue(user.sub, user.username, body.peer_id, body.conn_type)
        log.info("ticket issued sub=%s user=%s peer=%s ct=%s jti=%s ip=%s",
                 user.sub, user.username, body.peer_id, body.conn_type, t.claims["jti"][:8], client_ip(request))
        return {"ticket": t.raw, "expires_at": t.claims["exp"], "username": user.username}

    class AuthorizeRequest(BaseModel):
        ticket: str = Field(default="", max_length=4096)
        peer_id: str = Field(max_length=64)
        source_ip: str = Field(max_length=64)
        kind: str = Field(default="punch", max_length=16)

    @app.post("/internal/authorize", dependencies=[Depends(internal_only)])
    async def authorize(body: AuthorizeRequest):
        try:
            claims = signer.verify(body.ticket, body.peer_id)
            replay.consume(claims, body.source_ip)
        except TicketError as e:
            log.info("denied %s to peer=%s from=%s: %s", body.kind, body.peer_id, body.source_ip, e)
            return {"allowed": False, "reason": str(e)}
        log.info("allowed %s to peer=%s from=%s sub=%s jti=%s",
                 body.kind, body.peer_id, body.source_ip, claims["sub"], claims["jti"][:8])
        return {"allowed": True, "reason": "", "sub": claims["sub"], "username": claims.get("usr", "")}

    return app


def app_factory() -> FastAPI:
    return create_app()
