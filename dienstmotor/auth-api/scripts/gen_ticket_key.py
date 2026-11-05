"""Generate the Ed25519 key pair used to sign connection tickets.

Prints TICKET_SIGNING_KEY (secret, for the auth-api environment only) and the public key
to paste into DM_TICKET_PUBKEYS in the client's src/branding.rs.
"""
import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

seed = os.urandom(32)
pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print("TICKET_SIGNING_KEY=" + base64.b64encode(seed).decode())
print("public key (src/branding.rs DM_TICKET_PUBKEYS): " + base64.b64encode(pk).decode())
