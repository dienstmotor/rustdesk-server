"""End-to-end: the real patched hbbs binary + this auth API, driven over the RustDesk
rendezvous protocol (TCP framing + protobuf) by a fake controller and a fake host.

Asserts what reaches the host: hbbs must forward PunchHole / FetchLocalAddr / RequestRelay
to the target only for requests carrying a valid ticket, and tell the controller why not.

Run with HBBS_BIN=/path/to/hbbs (see dienstmotor/README.md); skipped otherwise.
"""

import base64
import importlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from app.tickets import TicketSigner

HBBS = os.environ.get("HBBS_BIN")
pytestmark = pytest.mark.skipif(not HBBS, reason="HBBS_BIN not set")

ROOT = Path(__file__).resolve().parents[3]
PROTO_DIR = ROOT / "libs" / "hbb_common" / "protos"
SEED = os.urandom(32)
INTERNAL = "e2e-internal-token-" + "x" * 32
ISSUER = "https://remote-api.dienstmotor.com"
API_PORT = 18000
RS_PORT = 31116
HOST_ID = "123456789"


def free(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if not free(port):
            return
        time.sleep(0.2)
    raise RuntimeError(f"port {port} never opened")


@pytest.fixture(scope="module")
def pb():
    out = Path(tempfile.mkdtemp())
    from grpc_tools import protoc

    assert protoc.main(["protoc", f"-I{PROTO_DIR}", f"--python_out={out}", str(PROTO_DIR / "rendezvous.proto")]) == 0
    sys.path.insert(0, str(out))
    return importlib.import_module("rendezvous_pb2")


@pytest.fixture(scope="module")
def api():
    env = dict(os.environ,
               OIDC_ISSUER="https://auth.invalid/application/o/x/", OIDC_CLIENT_ID="x",
               TICKET_SIGNING_KEY=base64.b64encode(SEED).decode(), TICKET_ISSUER=ISSUER,
               INTERNAL_API_TOKEN=INTERNAL)
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app_factory", "--factory",
                          "--host", "127.0.0.1", "--port", str(API_PORT), "--log-level", "warning"],
                         cwd=Path(__file__).resolve().parents[1], env=env)
    wait_port(API_PORT)
    yield p
    p.terminate()
    p.wait()


@pytest.fixture(scope="module")
def hbbs(api):
    work = tempfile.mkdtemp()
    env = dict(os.environ, DM_AUTH_URL=f"http://127.0.0.1:{API_PORT}/internal/authorize",
               DM_AUTH_TOKEN=INTERNAL, RUST_LOG="info")
    p = subprocess.Popen([HBBS, "-p", str(RS_PORT)], cwd=work, env=env,
                         stdout=open(Path(work) / "hbbs.log", "w"), stderr=subprocess.STDOUT)
    wait_port(RS_PORT)
    time.sleep(0.5)
    key = (Path(work) / "id_ed25519.pub").read_text().strip()
    yield key
    p.terminate()
    p.wait()
    print((Path(work) / "hbbs.log").read_text()[-4000:])


def frame(data: bytes) -> bytes:
    """hbb_common BytesCodec header: little-endian (len << 2 | header_len - 1)."""
    n = len(data)
    for size in range(1, 5):
        if n < 1 << (8 * size - 2):
            return ((n << 2) | (size - 1)).to_bytes(size, "little")
    raise ValueError("frame too large")


def send_tcp(msg, src="127.0.0.1", timeout=6.0):
    """Sends one RendezvousMessage over TCP, returns the first reply (or None)."""
    data = msg.SerializeToString()
    s = socket.socket()
    s.bind((src, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", RS_PORT))
    s.sendall(frame(data) + data)
    try:
        head = s.recv(1)
        if not head:
            return None
        hl = (head[0] & 3) + 1
        rest = s.recv(hl - 1) if hl > 1 else b""
        n = int.from_bytes(head + rest, "little") >> 2
        body = b""
        while len(body) < n:
            chunk = s.recv(n - len(body))
            if not chunk:
                break
            body += chunk
        return body
    except socket.timeout:
        return None
    finally:
        s.close()


class Host:
    def __init__(self, pb):
        self.pb = pb
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.uuid = uuid.uuid4().bytes
        self.pk = os.urandom(32)

    def send(self, msg):
        self.sock.sendto(msg.SerializeToString(), ("127.0.0.1", RS_PORT))

    def register(self):
        m = self.pb.RendezvousMessage()
        m.register_pk.id, m.register_pk.uuid, m.register_pk.pk = HOST_ID, self.uuid, self.pk
        self.send(m)
        m = self.pb.RendezvousMessage()
        m.register_peer.id = HOST_ID
        self.send(m)
        time.sleep(0.3)
        self.drain()

    def drain(self):
        self.sock.settimeout(0.2)
        try:
            while True:
                self.sock.recv(65535)
        except socket.timeout:
            pass

    def received(self, wait=2.0):
        """Kinds of the messages hbbs forwarded to this host."""
        kinds = []
        self.sock.settimeout(wait)
        try:
            while True:
                m = self.pb.RendezvousMessage()
                m.ParseFromString(self.sock.recv(65535))
                kinds.append(m.WhichOneof("union"))
                self.sock.settimeout(0.3)
        except socket.timeout:
            pass
        return [k for k in kinds if k not in ("register_peer_response", "register_pk_response", "configure_update")]


@pytest.fixture
def host(pb, hbbs):
    h = Host(pb)
    h.register()
    return h


def ticket(peer=HOST_ID, ttl=60, seed=SEED, now=None):
    return TicketSigner(seed, ISSUER, ttl).issue("user-1", "alice", peer, "default", now=now).raw


def punch(pb, key, token, src="127.0.0.1"):
    m = pb.RendezvousMessage()
    m.punch_hole_request.id = HOST_ID
    m.punch_hole_request.licence_key = key
    m.punch_hole_request.token = token
    reply = send_tcp(m, src=src, timeout=3.0)
    if reply is None:
        return None
    r = pb.RendezvousMessage()
    r.ParseFromString(reply)
    return r.punch_hole_response


def relay(pb, key, token, src="127.0.0.1"):
    m = pb.RendezvousMessage()
    m.request_relay.id = HOST_ID
    m.request_relay.uuid = str(uuid.uuid4())
    m.request_relay.licence_key = key
    m.request_relay.token = token
    reply = send_tcp(m, src=src, timeout=3.0)
    if reply is None:
        return None
    r = pb.RendezvousMessage()
    r.ParseFromString(reply)
    return r.relay_response


def test_official_client_without_ticket_is_refused(pb, hbbs, host):
    r = punch(pb, hbbs, "")
    assert "sign in" in r.other_failure
    assert host.received() == []


def test_authorized_operator_reaches_host(pb, hbbs, host):
    punch(pb, hbbs, ticket())  # hbbs answers the host, not the controller, on success
    assert host.received() in (["fetch_local_addr"], ["punch_hole"])


def test_forged_expired_and_foreign_tickets_are_refused(pb, hbbs, host):
    for bad in (ticket(seed=os.urandom(32)),
                ticket(now=int(time.time()) - 120),
                ticket(peer="987654321")):
        r = punch(pb, hbbs, bad)
        assert r is not None and "authorization rejected" in r.other_failure, bad
    assert host.received() == []


def test_ticket_replayed_from_another_address_is_refused(pb, hbbs, host):
    t = ticket()
    punch(pb, hbbs, t, src="127.0.0.1")
    assert host.received() != []
    r = punch(pb, hbbs, t, src="127.0.0.2")
    assert "ticket replay" in r.other_failure
    assert host.received() == []


def test_relay_requires_ticket(pb, hbbs, host):
    r = relay(pb, hbbs, "")
    assert "sign in" in r.refuse_reason
    assert host.received() == []
    relay(pb, hbbs, ticket())
    assert host.received() == ["request_relay"]


def test_auth_api_down_fails_closed(pb, hbbs, host, api):
    api.terminate()
    api.wait()
    r = punch(pb, hbbs, ticket())
    assert "unavailable" in r.other_failure
    assert host.received() == []
