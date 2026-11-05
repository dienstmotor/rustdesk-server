"""Validation of Authentik (OIDC) access tokens.

A token is accepted only when every check passes; any error, timeout or missing data
rejects it. Checks: JWS signature against the provider JWKS, issuer, audience/azp equal to
the configured client, temporal claims, optional required scopes, and finally a live check
with Authentik (introspection when credentials are configured, otherwise userinfo) so that
revoked tokens and ended sessions are refused even before the JWT expires.
"""

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx
import jwt

from .config import Settings

log = logging.getLogger("dm-auth.oidc")

ALLOWED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"]
LEEWAY = 30
JWKS_MIN_REFRESH = 60
DISCOVERY_TTL = 3600


class AuthError(Exception):
    pass


@dataclass
class Identity:
    sub: str
    username: str
    name: str
    email: str


class OidcValidator:
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.s = settings
        self.http = client
        self._discovery: dict | None = None
        self._discovery_at = 0.0
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_at = 0.0
        self._lock = asyncio.Lock()

    async def discovery(self) -> dict:
        if self._discovery and time.monotonic() - self._discovery_at < DISCOVERY_TTL:
            return self._discovery
        async with self._lock:
            if self._discovery and time.monotonic() - self._discovery_at < DISCOVERY_TTL:
                return self._discovery
            url = self.s.oidc_issuer + ".well-known/openid-configuration"
            resp = await self.http.get(url)
            resp.raise_for_status()
            doc = resp.json()
            if doc.get("issuer", "").rstrip("/") != self.s.oidc_issuer.rstrip("/"):
                raise AuthError("issuer mismatch in discovery document")
            self._discovery, self._discovery_at = doc, time.monotonic()
            return doc

    async def _signing_key(self, kid: str | None):
        for attempt in range(2):
            if self._jwks is None or (
                attempt == 1 and time.monotonic() - self._jwks_at > JWKS_MIN_REFRESH
            ):
                doc = await self.discovery()
                resp = await self.http.get(doc["jwks_uri"])
                resp.raise_for_status()
                self._jwks, self._jwks_at = jwt.PyJWKSet.from_dict(resp.json()), time.monotonic()
            for key in self._jwks.keys:
                if kid is None or key.key_id == kid:
                    return key
        raise AuthError("unknown signing key")

    def _issuer_matches(self, iss: str) -> bool:
        return isinstance(iss, str) and iss.rstrip("/") == self.s.oidc_issuer.rstrip("/")

    async def validate(self, token: str) -> Identity:
        if not token or len(token) > 8192:
            raise AuthError("missing token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthError("malformed token")
        if header.get("alg") not in ALLOWED_ALGS:
            raise AuthError("unsupported token algorithm")
        try:
            key = await self._signing_key(header.get("kid"))
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.warning("JWKS fetch failed: %s", type(e).__name__)
            raise AuthError("identity provider unavailable")
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=ALLOWED_ALGS,
                audience=self.s.oidc_client_id,
                leeway=LEEWAY,
                options={"require": ["exp", "iat", "iss", "sub", "aud"], "verify_iss": False},
            )
        except (jwt.PyJWTError, httpx.HTTPError, KeyError, ValueError) as e:
            raise AuthError(f"token rejected: {type(e).__name__}")
        if not self._issuer_matches(claims.get("iss")):
            raise AuthError("token rejected: issuer")
        azp = claims.get("azp")
        if azp is not None and azp != self.s.oidc_client_id:
            raise AuthError("token rejected: authorized party")
        if self.s.oidc_required_scopes:
            granted = set(str(claims.get("scope", "")).split())
            if not set(self.s.oidc_required_scopes) <= granted:
                raise AuthError("token rejected: scope")
        info = await self._live_check(token, claims)
        sub = claims["sub"]
        if info.get("sub") not in (None, sub):
            raise AuthError("token rejected: subject mismatch")
        merged = {**claims, **info}
        return Identity(
            sub=sub,
            username=str(merged.get("preferred_username") or merged.get("nickname") or sub),
            name=str(merged.get("name") or ""),
            email=str(merged.get("email") or ""),
        )

    async def _live_check(self, token: str, claims: dict) -> dict:
        try:
            doc = await self.discovery()
            if self.s.oidc_introspection_client_id and self.s.oidc_introspection_client_secret:
                resp = await self.http.post(
                    doc["introspection_endpoint"],
                    data={"token": token, "token_type_hint": "access_token"},
                    auth=(self.s.oidc_introspection_client_id, self.s.oidc_introspection_client_secret),
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("active") is not True:
                    raise AuthError("token rejected: inactive")
                if data.get("client_id") not in (None, self.s.oidc_client_id):
                    raise AuthError("token rejected: client")
                return {k: v for k, v in data.items() if k in ("sub", "preferred_username", "name", "email")}
            resp = await self.http.get(
                doc["userinfo_endpoint"], headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code in (401, 403):
                raise AuthError("token rejected: session ended or revoked")
            resp.raise_for_status()
            return resp.json()
        except AuthError:
            raise
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.warning("live token check failed: %s", type(e).__name__)
            raise AuthError("identity provider unavailable")
