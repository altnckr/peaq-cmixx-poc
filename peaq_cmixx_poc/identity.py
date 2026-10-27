"""Machine identity for the PoC.

In production a machine's identity is a peaq DID anchored on-chain. Here we
model it with two locally generated keypairs:

* Ed25519  - signs envelopes (authenticates the sender)
* X25519   - receives encrypted envelopes (key agreement)

The mock DID is derived from the signing public key so a registry can check
that a DID and its key belong together. A real peaq DID is derived and
registered differently; see README "What is mocked".
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

_RAW = dict(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def pub_bytes(key) -> bytes:
    """Raw 32-byte public key."""
    return key.public_bytes(**_RAW)


def did_from_sign_pub(sign_pub: bytes) -> str:
    """Mock DID derived from the Ed25519 public key."""
    return "did:peaq:mock:" + hashlib.sha256(sign_pub).hexdigest()[:20]


KEY_ID_LEN = 8


def key_id_from_sign_pub(sign_pub: bytes) -> bytes:
    """Short (8-byte) identifier of a signing key, used on the wire instead of the
    full DID string to save space in the small cMixx message budget."""
    return hashlib.sha256(b"key-id|" + sign_pub).digest()[:KEY_ID_LEN]


class MachineIdentity:
    """A machine's keys and DID. Private keys never leave this object."""

    def __init__(self, name: str = "machine") -> None:
        self.name = name
        self._sign_key = Ed25519PrivateKey.generate()
        self._kex_key = X25519PrivateKey.generate()
        self.sign_pub: bytes = pub_bytes(self._sign_key.public_key())
        self.kex_pub: bytes = pub_bytes(self._kex_key.public_key())
        self.did: str = did_from_sign_pub(self.sign_pub)
        self.key_id: bytes = key_id_from_sign_pub(self.sign_pub)

    def sign(self, data: bytes) -> bytes:
        return self._sign_key.sign(data)

    def key_agreement(self, ephemeral_pub: bytes) -> bytes:
        """X25519 shared secret with a sender's ephemeral public key."""
        return self._kex_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))

    def __repr__(self) -> str:  # never print key material
        return f"MachineIdentity(name={self.name!r}, did={self.did!r})"
