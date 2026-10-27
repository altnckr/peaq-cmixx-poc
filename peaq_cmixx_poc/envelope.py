"""Application-layer envelope (v2): compact, authenticated, encrypted, fixed size.

Designed for a small per-message budget (the working assumption is ~384 bytes
per cMixx message; the real value must be read from the network at runtime).

Wire format (big-endian)::

    magic        2   b"P2"
    msg_class    1
    ts_s         4   unix seconds
    nonce       12   (also the AEAD nonce and the replay id)
    eph_pub     32   sender's ephemeral X25519 public key
    sender_id    8   key id of the sender's signing key
    recipient_id 8   key id of the recipient's signing key
    ct_len       2
    ciphertext  ct_len   ChaCha20-Poly1305, AAD = everything above
                         plaintext = payload_len(2) | payload | zero padding
    signature   64   Ed25519 over everything above

The envelope is padded so that its total length is EXACTLY ``wire_size`` bytes,
whatever the payload length (cMixx messages are fixed-size anyway).

Fixed overhead is ``FIXED_OVERHEAD`` bytes, so payload capacity per envelope is
``wire_size - FIXED_OVERHEAD - 2``.

Notes
-----
* Sender authentication is tied to a peaq DID (via the registry). Confidentiality
  here is independent of the transport; cMixx / xxDK adds its own end-to-end
  encryption and metadata protection underneath and does NOT get replaced.
* Neither X25519 nor Ed25519 is post-quantum; quantum resistance of the whole
  channel is expected to come from xxDK. A post-quantum signature/KEM could be
  added here later, but would be much larger than this budget allows without
  heavier chunking.
* The signature is verified BEFORE decryption.
* A 64-byte signature per envelope is the biggest overhead item. A later
  optimisation is an authenticated session (one signed handshake, then MACs).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import KEY_ID_LEN, MachineIdentity, pub_bytes
from .registry import ChannelBinding

MAGIC = b"P2"
NONCE_LEN = 12
SIG_LEN = 64
TAG_LEN = 16
_HEADER_LEN = 2 + 1 + 4 + NONCE_LEN + 32 + KEY_ID_LEN + KEY_ID_LEN  # 67
FIXED_OVERHEAD = _HEADER_LEN + 2 + TAG_LEN + SIG_LEN                  # 149
_INFO = b"peaq-cmixx-poc/v2"


class EnvelopeError(Exception):
    """Raised when an inbound envelope is rejected. ``reason`` is a short code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Opened:
    sender_did: str
    recipient_did: str
    msg_class: int
    ts_s: int
    nonce: bytes
    payload: bytes


def capacity(wire_size: int) -> int:
    """Payload bytes that fit in one envelope of ``wire_size`` bytes."""
    return max(0, wire_size - FIXED_OVERHEAD - 2)


def _derive_key(shared: bytes, sender_did: str, recipient_did: str) -> bytes:
    info = _INFO + b"|" + sender_did.encode() + b"|" + recipient_did.encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal(
    sender: MachineIdentity,
    recipient: ChannelBinding,
    msg_class: int,
    payload: bytes,
    ts_s: int,
    wire_size: int,
    nonce: bytes | None = None,
) -> bytes:
    """Build a signed, encrypted envelope of exactly ``wire_size`` bytes."""
    if len(payload) > capacity(wire_size):
        raise ValueError(f"payload {len(payload)} B exceeds envelope capacity {capacity(wire_size)} B")
    nonce = nonce or os.urandom(NONCE_LEN)
    eph = X25519PrivateKey.generate()
    eph_pub = pub_bytes(eph.public_key())

    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient.kex_pub))
    key = _derive_key(shared, sender.did, recipient.did)

    pt_len = wire_size - FIXED_OVERHEAD
    plaintext = len(payload).to_bytes(2, "big") + payload
    plaintext += b"\x00" * (pt_len - len(plaintext))

    header = (
        MAGIC
        + bytes([msg_class])
        + ts_s.to_bytes(4, "big")
        + nonce
        + eph_pub
        + sender.key_id
        + recipient.key_id
    )
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
    body = header + len(ct).to_bytes(2, "big") + ct
    raw = body + sender.sign(body)
    assert len(raw) == wire_size
    return raw


def open_(
    recipient: MachineIdentity,
    raw: bytes,
    resolve_by_key_id: Callable[[bytes], ChannelBinding | None],
) -> Opened:
    """Verify and decrypt an envelope addressed to ``recipient``.

    Raises ``EnvelopeError`` with one of: malformed, unknown_sender,
    bad_signature, wrong_recipient, decrypt_failed, bad_padding.
    """
    if len(raw) < FIXED_OVERHEAD + 2 or raw[:2] != MAGIC:
        raise EnvelopeError("malformed")
    body, sig = raw[:-SIG_LEN], raw[-SIG_LEN:]

    pos = 2
    msg_class = body[pos]; pos += 1
    ts_s = int.from_bytes(body[pos : pos + 4], "big"); pos += 4
    nonce = body[pos : pos + NONCE_LEN]; pos += NONCE_LEN
    eph_pub = body[pos : pos + 32]; pos += 32
    sender_id = body[pos : pos + KEY_ID_LEN]; pos += KEY_ID_LEN
    recipient_id = body[pos : pos + KEY_ID_LEN]; pos += KEY_ID_LEN
    header = body[:pos]
    ct_len = int.from_bytes(body[pos : pos + 2], "big"); pos += 2
    ct = body[pos:]
    if len(ct) != ct_len or ct_len < TAG_LEN + 2:
        raise EnvelopeError("malformed")

    binding = resolve_by_key_id(sender_id)
    if binding is None:
        raise EnvelopeError("unknown_sender")
    try:
        Ed25519PublicKey.from_public_bytes(binding.sign_pub).verify(sig, body)
    except InvalidSignature:
        raise EnvelopeError("bad_signature") from None

    if recipient_id != recipient.key_id:
        raise EnvelopeError("wrong_recipient")

    key = _derive_key(recipient.key_agreement(eph_pub), binding.did, recipient.did)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ct, header)
    except InvalidTag:
        raise EnvelopeError("decrypt_failed") from None

    n = int.from_bytes(plaintext[:2], "big")
    if n > len(plaintext) - 2:
        raise EnvelopeError("bad_padding")
    return Opened(binding.did, recipient.did, msg_class, ts_s, nonce, plaintext[2 : 2 + n])
