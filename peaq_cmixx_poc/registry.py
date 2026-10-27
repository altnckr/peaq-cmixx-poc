"""Channel-binding registry.

A *channel binding* tells a peer how to reach a machine privately:
its DID, public keys, and an opaque cMixx contact blob.

PoC: ``MockPeaqRegistry`` keeps bindings in memory.
Production: implement ``PeaqRegistry`` against the peaq chain (DID document
service endpoint or a dedicated storage/pallet entry). Which on-chain record
type fits best is an open question for the peaq team (architecture draft,
section 9, question 6).

Envelopes carry an 8-byte *key id* instead of the full DID string (the cMixx
message budget is small), so a registry must also resolve by key id. In
production the key id can be derived from the DID's public key.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .identity import did_from_sign_pub, key_id_from_sign_pub


@dataclass(frozen=True)
class ChannelBinding:
    did: str
    sign_pub: bytes      # Ed25519 public key (32 bytes)
    kex_pub: bytes       # X25519 public key (32 bytes)
    contact: bytes       # opaque cMixx contact info for the transport
    active: bool = True  # e.g. registered + bonded + in good standing

    @property
    def key_id(self) -> bytes:
        return key_id_from_sign_pub(self.sign_pub)


class RegistryError(Exception):
    pass


class PeaqRegistry(ABC):
    @abstractmethod
    def register(self, binding: ChannelBinding) -> None: ...

    @abstractmethod
    def resolve(self, did: str) -> ChannelBinding | None: ...

    @abstractmethod
    def resolve_by_key_id(self, key_id: bytes) -> ChannelBinding | None: ...


class MockPeaqRegistry(PeaqRegistry):
    """In-memory stand-in for on-chain DID / binding lookup."""

    def __init__(self) -> None:
        self._bindings: dict[str, ChannelBinding] = {}
        self._by_key_id: dict[bytes, str] = {}

    def register(self, binding: ChannelBinding) -> None:
        # A DID must correspond to its signing key (mock rule).
        if did_from_sign_pub(binding.sign_pub) != binding.did:
            raise RegistryError("DID does not match signing key")
        owner = self._by_key_id.get(binding.key_id)
        if owner is not None and owner != binding.did:
            raise RegistryError("key id collision")
        self._bindings[binding.did] = binding
        self._by_key_id[binding.key_id] = binding.did

    def resolve(self, did: str) -> ChannelBinding | None:
        b = self._bindings.get(did)
        return b if (b is not None and b.active) else None

    def resolve_by_key_id(self, key_id: bytes) -> ChannelBinding | None:
        did = self._by_key_id.get(key_id)
        return self.resolve(did) if did is not None else None

    def deactivate(self, did: str) -> None:
        """Simulate a machine losing its bond / being revoked."""
        b = self._bindings.get(did)
        if b is not None:
            self._bindings[did] = ChannelBinding(
                b.did, b.sign_pub, b.kex_pub, b.contact, active=False
            )
