"""Connection tickets: short-lived Ed25519 signed authorizations for one connection attempt.

Wire format: ``dm1.<b64url(payload json)>.<b64url(signature)>``. The signature covers the
ASCII bytes of ``dm1.<b64url(payload json)>``. The Rust verifiers in hbbs (via this service)
and in the Dienstmotor Remote host must stay in sync with this format.
"""

import base64
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PREFIX = "dm1"
AUDIENCE = "dienstmotor-remote"
MAX_TICKET_LEN = 2048
# RustDesk IDs: 6-16 chars, letters/digits/_/- (custom IDs allowed). No IPs, no "@server".
PEER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,32}$")
CONN_TYPES = {"default", "file_transfer", "port_forward", "rdp", "view_camera", "terminal"}


class TicketError(Exception):
    pass


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def public_key_b64(seed: bytes) -> str:
    pk = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64.b64encode(pk.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


@dataclass
class Ticket:
    raw: str
    claims: dict


class TicketSigner:
    def __init__(self, seed: bytes, issuer: str, ttl: int):
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        self._pk: Ed25519PublicKey = self._sk.public_key()
        self.issuer = issuer
        self.ttl = ttl

    def issue(self, sub: str, username: str, peer_id: str, conn_type: str, now: int | None = None) -> Ticket:
        now = int(time.time()) if now is None else now
        claims = {
            "v": 1,
            "iss": self.issuer,
            "aud": AUDIENCE,
            "sub": sub,
            "usr": username,
            "tgt": peer_id,
            "ct": conn_type,
            "jti": secrets.token_hex(16),
            "iat": now,
            "exp": now + self.ttl,
        }
        body = PREFIX + "." + _b64e(json.dumps(claims, separators=(",", ":")).encode())
        sig = self._sk.sign(body.encode())
        return Ticket(raw=body + "." + _b64e(sig), claims=claims)

    def verify(self, raw: str, peer_id: str, now: int | None = None) -> dict:
        now = int(time.time()) if now is None else now
        if not raw or len(raw) > MAX_TICKET_LEN:
            raise TicketError("missing ticket")
        parts = raw.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise TicketError("malformed ticket")
        try:
            sig = _b64d(parts[2])
            self._pk.verify(sig, (parts[0] + "." + parts[1]).encode())
            claims = json.loads(_b64d(parts[1]))
        except (InvalidSignature, ValueError):
            raise TicketError("invalid ticket signature")
        if not isinstance(claims, dict) or claims.get("v") != 1:
            raise TicketError("unsupported ticket version")
        if claims.get("aud") != AUDIENCE or claims.get("iss") != self.issuer:
            raise TicketError("ticket not issued for this service")
        exp, iat = claims.get("exp"), claims.get("iat")
        if not isinstance(exp, int) or not isinstance(iat, int):
            raise TicketError("malformed ticket")
        if now >= exp:
            raise TicketError("ticket expired")
        if iat > now + 5:
            raise TicketError("ticket not yet valid")
        if claims.get("tgt") != peer_id:
            raise TicketError("ticket issued for another device")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            raise TicketError("malformed ticket")
        return claims


class ReplayGuard:
    """Lets one ticket serve exactly one connection attempt.

    A single attempt legitimately sends several rendezvous messages carrying the same ticket
    (up to three punch retries on two parallel sockets, then relay fallback), so a ticket is
    bound on first use to the source IP and target and may be presented again only from there,
    a bounded number of times, until it expires. The host additionally enforces strict single
    use of the jti at login.
    """

    def __init__(self, max_uses: int, bind_source_ip: bool):
        self.max_uses = max_uses
        self.bind_source_ip = bind_source_ip
        self._lock = threading.Lock()
        self._seen: dict[str, tuple[str, str, int, int]] = {}

    def consume(self, claims: dict, source_ip: str, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        jti, tgt, exp = claims["jti"], claims["tgt"], claims["exp"]
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: v for k, v in self._seen.items() if v[3] > now}
            entry = self._seen.get(jti)
            if entry is None:
                self._seen[jti] = (source_ip, tgt, 1, exp)
                return
            ip, seen_tgt, uses, _ = entry
            if seen_tgt != tgt or (self.bind_source_ip and ip != source_ip):
                raise TicketError("ticket replay")
            if uses >= self.max_uses:
                raise TicketError("ticket already used")
            self._seen[jti] = (ip, seen_tgt, uses + 1, exp)
