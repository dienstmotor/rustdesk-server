import base64
import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    return value or ""


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Settings:
    oidc_issuer: str
    oidc_client_id: str
    oidc_scopes: str
    oidc_required_scopes: tuple[str, ...]
    oidc_introspection_client_id: str
    oidc_introspection_client_secret: str
    ticket_signing_key: bytes
    ticket_issuer: str
    ticket_ttl: int
    ticket_max_uses: int
    ticket_bind_source_ip: bool
    internal_api_token: str
    http_timeout: float
    rate_limit_per_minute: int
    trusted_proxies: tuple[str, ...] = field(default_factory=tuple)

    @staticmethod
    def from_env() -> "Settings":
        issuer = _env("OIDC_ISSUER", required=True)
        if not issuer.endswith("/"):
            issuer += "/"
        seed = base64.b64decode(_env("TICKET_SIGNING_KEY", required=True))
        if len(seed) != 32:
            raise RuntimeError("TICKET_SIGNING_KEY must be a base64 encoded 32 byte Ed25519 seed")
        internal = _env("INTERNAL_API_TOKEN", required=True)
        if len(internal) < 32:
            raise RuntimeError("INTERNAL_API_TOKEN must be at least 32 characters")
        return Settings(
            oidc_issuer=issuer,
            oidc_client_id=_env("OIDC_CLIENT_ID", required=True),
            oidc_scopes=_env("OIDC_SCOPES", "openid profile email offline_access"),
            oidc_required_scopes=tuple(_env("OIDC_REQUIRED_SCOPES", "").split()),
            oidc_introspection_client_id=_env("OIDC_INTROSPECTION_CLIENT_ID", ""),
            oidc_introspection_client_secret=_env("OIDC_INTROSPECTION_CLIENT_SECRET", ""),
            ticket_signing_key=seed,
            ticket_issuer=_env("TICKET_ISSUER", "https://remote-api.dienstmotor.com"),
            ticket_ttl=_env_int("TICKET_TTL_SECONDS", 60),
            ticket_max_uses=_env_int("TICKET_MAX_USES", 16),
            ticket_bind_source_ip=_env_bool("TICKET_BIND_SOURCE_IP", True),
            internal_api_token=internal,
            http_timeout=float(_env("HTTP_TIMEOUT_SECONDS", "5")),
            rate_limit_per_minute=_env_int("RATE_LIMIT_PER_MINUTE", 60),
            trusted_proxies=tuple(_env("TRUSTED_PROXIES", "127.0.0.1 ::1 172.16.0.0/12").split()),
        )
