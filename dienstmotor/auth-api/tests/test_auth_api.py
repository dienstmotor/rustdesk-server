import base64
import os
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.tickets import ReplayGuard, TicketError, TicketSigner

ISSUER = "https://auth.example.test/application/o/dienstmotor-remote/"
CLIENT_ID = "dm-remote"
INTERNAL = "i" * 40
SEED = os.urandom(32)

IDP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_of(key, kid):
    d = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    d.update(kid=kid, use="sig", alg="RS256")
    return d


def access_token(key=IDP_KEY, kid="k1", **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": CLIENT_ID, "azp": CLIENT_ID, "sub": "user-1",
              "iat": now, "exp": now + 300, "preferred_username": "alice"}
    claims.update(over)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class FakeIdp:
    def __init__(self):
        self.revoked: set[str] = set()
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down")
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "jwks_uri": "https://auth.example.test/jwks",
                "userinfo_endpoint": "https://auth.example.test/userinfo",
            })
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [jwk_of(IDP_KEY, "k1")]})
        if path == "/userinfo":
            tok = request.headers.get("authorization", "")[7:]
            if tok in self.revoked:
                return httpx.Response(401)
            return httpx.Response(200, json={"sub": "user-1", "preferred_username": "alice", "name": "Alice"})
        return httpx.Response(404)


def settings(**over):
    base = dict(
        oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_scopes="openid offline_access",
        oidc_required_scopes=(), oidc_introspection_client_id="", oidc_introspection_client_secret="",
        ticket_signing_key=SEED, ticket_issuer="https://remote-api.example.test", ticket_ttl=60,
        ticket_max_uses=16, ticket_bind_source_ip=True, internal_api_token=INTERNAL,
        http_timeout=2.0, rate_limit_per_minute=0, trusted_proxies=("127.0.0.1",),
    )
    base.update(over)
    return Settings(**base)


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def client(idp):
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    with TestClient(create_app(settings(), http=http), client=("10.0.0.5", 5000)) as c:
        yield c


def get_ticket(client, token, peer="123456789"):
    return client.post("/auth/ticket", json={"peer_id": peer}, headers={"Authorization": f"Bearer {token}"})


def authorize(client, ticket, peer="123456789", ip="203.0.113.7", headers=None):
    h = {"Authorization": f"Bearer {INTERNAL}"}
    h.update(headers or {})
    return client.post("/internal/authorize", json={"ticket": ticket, "peer_id": peer, "source_ip": ip, "kind": "punch"}, headers=h)


def test_config_exposes_only_public_values(client):
    body = client.get("/auth/config").json()
    assert body["issuer"] == ISSUER and body["client_id"] == CLIENT_ID
    assert not any("secret" in k or "key" in k for k in body)


def test_operator_without_login_is_rejected(client):
    assert client.post("/auth/ticket", json={"peer_id": "123456789"}).status_code == 401
    assert authorize(client, "").json()["allowed"] is False


def test_operator_with_valid_login_is_allowed(client):
    r = get_ticket(client, access_token())
    assert r.status_code == 200, r.text
    assert authorize(client, r.json()["ticket"]).json()["allowed"] is True
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {access_token()}"}).json()["username"] == "alice"


@pytest.mark.parametrize("token", [
    access_token(key=OTHER_KEY),                       # forged signature
    access_token(exp=int(time.time()) - 120),          # expired
    access_token(aud="another-app", azp="another-app"),  # other Authentik application
    access_token(iss="https://evil.test/"),           # other issuer
    "not-a-jwt",
])
def test_invalid_access_tokens_are_rejected(client, token):
    assert get_ticket(client, token).status_code == 401


def test_revoked_or_logged_out_token_is_rejected(client, idp):
    tok = access_token()
    idp.revoked.add(tok)
    assert get_ticket(client, tok).status_code == 401


def test_identity_provider_down_fails_closed(client, idp):
    idp.down = True
    assert get_ticket(client, access_token()).status_code == 503


def test_ticket_only_for_plain_peer_ids(client):
    for peer in ("192.168.1.10", "1.2.3.4:21118", "123456789@rs-ny.rustdesk.com"):
        assert get_ticket(client, access_token(), peer=peer).status_code == 400


def test_forged_and_foreign_tickets_are_denied(client):
    other = TicketSigner(os.urandom(32), "https://remote-api.example.test", 60)
    forged = other.issue("user-1", "alice", "123456789", "default").raw
    assert authorize(client, forged).json() == {"allowed": False, "reason": "invalid ticket signature"}
    good = get_ticket(client, access_token()).json()["ticket"]
    assert authorize(client, good, peer="987654321").json()["allowed"] is False
    head, payload, sig = good.split(".")
    tampered = ".".join([head, payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB"), sig])
    assert authorize(client, tampered).json()["allowed"] is False


def test_ticket_replay_from_another_address_is_denied(client):
    t = get_ticket(client, access_token()).json()["ticket"]
    assert authorize(client, t, ip="203.0.113.7").json()["allowed"] is True
    assert authorize(client, t, ip="203.0.113.7").json()["allowed"] is True  # same attempt, relay fallback
    assert authorize(client, t, ip="198.51.100.9").json()["allowed"] is False


def test_internal_endpoint_requires_service_credentials(client):
    t = get_ticket(client, access_token()).json()["ticket"]
    assert authorize(client, t, headers={"Authorization": "Bearer wrong"}).status_code == 404
    assert authorize(client, t, headers={"X-Real-IP": "203.0.113.7"}).status_code == 404
    assert authorize(client, t, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 404


def test_internal_endpoint_refuses_public_peers(idp):
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    with TestClient(create_app(settings(), http=http), client=("8.8.8.8", 5000)) as c:
        assert authorize(c, "x").status_code == 404


def test_expired_ticket_and_use_cap():
    signer = TicketSigner(SEED, "iss", 60)
    t = signer.issue("u", "alice", "123456789", "default", now=1000)
    with pytest.raises(TicketError, match="expired"):
        signer.verify(t.raw, "123456789", now=1060)
    claims = signer.verify(t.raw, "123456789", now=1010)
    guard = ReplayGuard(max_uses=2, bind_source_ip=True)
    guard.consume(claims, "1.1.1.1", now=1010)
    guard.consume(claims, "1.1.1.1", now=1011)
    with pytest.raises(TicketError, match="already used"):
        guard.consume(claims, "1.1.1.1", now=1012)


def test_ticket_format_matches_host_verifier_vector():
    """Pins the wire format the Rust host verifier (src/dienstmotor_auth.rs) parses."""
    seed = bytes(range(32))
    t = TicketSigner(seed, "https://remote-api.dienstmotor.com", 60).issue("u", "alice", "123456789", "default", now=1_700_000_000)
    head, payload, sig = t.raw.split(".")
    assert head == "dm1" and len(base64.urlsafe_b64decode(sig + "==")) == 64
