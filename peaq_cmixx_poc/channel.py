"""Private Channel Module - the public API of the PoC.

    module = PrivateChannelModule(identity, registry, transport)
    module.publish_binding()                       # make this machine reachable
    module.on_message(lambda did, cls, data: ...)  # receive
    module.send(peer_did, MsgClass.TELEMETRY, b"...")

Payloads larger than one envelope are fragmented and reassembled transparently.
The per-message size comes from the transport (``max_message_bytes``), which for
the real xxDK sidecar should be the value reported by the network at runtime.

Inbound failures (bad signature, replay, stale, unknown sender, ...) are counted
in ``stats`` and silently dropped; nothing is sent back, so a remote party
cannot use the module as a validity oracle.
"""
from __future__ import annotations

import os
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Callable

from . import envelope, fragment
from .envelope import EnvelopeError
from .fragment import FragmentError, Reassembler
from .identity import MachineIdentity
from .policy import Decision, Lane, MsgClass, TrafficPolicy
from .registry import ChannelBinding, PeaqRegistry
from .transport import Transport

MessageHandler = Callable[[str, int, bytes], None]


class PayloadTooLarge(Exception):
    pass


class UnknownPeer(Exception):
    pass


@dataclass(frozen=True)
class SendResult:
    decision: Decision
    sent: bool
    queued: bool = False
    fragments: int = 0
    wire_bytes: int = 0   # total bytes handed to the transport


class PrivateChannelModule:
    def __init__(
        self,
        identity: MachineIdentity,
        registry: PeaqRegistry,
        transport: Transport,
        policy: TrafficPolicy | None = None,
        now_fn: Callable[[], float] = time.time,
        expected_latency_s: float = 3.0,
        replay_window_s: float = 600.0,
        max_payload_bytes: int = 16384,
        reassembly_timeout_s: float = 120.0,
        wire_size: int | None = None,
    ) -> None:
        self.identity = identity
        self.registry = registry
        self.transport = transport
        self.policy = policy or TrafficPolicy()
        self._now = now_fn
        self.expected_latency_s = expected_latency_s
        self.replay_window_s = replay_window_s
        self.max_payload_bytes = max_payload_bytes
        self._wire_size_override = wire_size
        self.stats: Counter[str] = Counter()
        self.outbox: deque[tuple[str, int, bytes]] = deque()
        self._seen: dict[bytes, float] = {}
        self._reasm = Reassembler(timeout_s=reassembly_timeout_s)
        self._handlers: list[MessageHandler] = []
        transport.set_handler(self.handle_raw)

    @property
    def wire_size(self) -> int:
        """Bytes per envelope. Read from the transport each time, so a changed
        network limit is picked up without restarting."""
        return self._wire_size_override or self.transport.max_message_bytes

    # -- setup --------------------------------------------------------------
    def publish_binding(self) -> ChannelBinding:
        b = ChannelBinding(
            did=self.identity.did,
            sign_pub=self.identity.sign_pub,
            kex_pub=self.identity.kex_pub,
            contact=self.transport.contact,
        )
        self.registry.register(b)
        return b

    def on_message(self, handler: MessageHandler) -> None:
        self._handlers.append(handler)

    # -- outbound -----------------------------------------------------------
    def send(self, peer_did: str, msg_class: int, payload: bytes, *, _from_outbox: bool = False) -> SendResult:
        decision = self.policy.decide(
            msg_class,
            private_available=self.transport.available(),
            est_latency_s=self.expected_latency_s,
        )
        if decision.lane is Lane.QUEUE:
            if not _from_outbox:
                self.outbox.append((peer_did, msg_class, payload))
                self.stats["queued"] += 1
            return SendResult(decision, sent=False, queued=True)
        if decision.lane is not Lane.PRIVATE:
            self.stats[f"lane_{decision.lane.value}"] += 1
            return SendResult(decision, sent=False)

        peer = self.registry.resolve(peer_did)
        if peer is None:
            raise UnknownPeer(peer_did)

        wire = self.wire_size
        chunk = envelope.capacity(wire) - fragment.HEADER_LEN
        if chunk < 1:
            raise PayloadTooLarge(f"transport limit {wire} B is too small for an envelope")
        if len(payload) > self.max_payload_bytes:
            raise PayloadTooLarge(f"payload {len(payload)} B exceeds module limit {self.max_payload_bytes} B")
        try:
            parts = fragment.split(payload, chunk, os.urandom(4))
        except ValueError as e:
            raise PayloadTooLarge(str(e)) from None

        ts = int(self._now())
        raws = [envelope.seal(self.identity, peer, int(msg_class), p, ts, wire) for p in parts]
        for raw in raws:  # a transport failure part-way leaves an incomplete message that the peer expires
            self.transport.send(peer.contact, raw)
        self.stats["sent"] += 1
        self.stats["fragments_sent"] += len(raws)
        return SendResult(decision, sent=True, fragments=len(raws), wire_bytes=wire * len(raws))

    def flush_outbox(self) -> int:
        """Retry queued messages. Returns how many were sent."""
        sent = 0
        for _ in range(len(self.outbox)):
            peer, cls, payload = self.outbox.popleft()
            res = self.send(peer, cls, payload, _from_outbox=True)
            if res.sent:
                sent += 1
            elif res.queued:
                self.outbox.append((peer, cls, payload))
        return sent

    # -- inbound ------------------------------------------------------------
    def expire_reassemblies(self) -> int:
        n = self._reasm.expire(self._now())
        if n:
            self.stats["reassembly_expired"] += n
        return n

    def handle_raw(self, raw: bytes) -> None:
        try:
            msg = envelope.open_(self.identity, raw, self.registry.resolve_by_key_id)
        except EnvelopeError as e:
            self.stats[f"rejected_{e.reason}"] += 1
            return

        now = self._now()
        if abs(now - msg.ts_s) > self.replay_window_s:
            self.stats["rejected_stale"] += 1
            return
        self._seen = {k: t for k, t in self._seen.items() if now - t <= self.replay_window_s}
        rid = msg.sender_did.encode() + b"|" + msg.nonce
        if rid in self._seen:
            self.stats["rejected_replay"] += 1
            return
        self._seen[rid] = now

        self.stats["fragments_received"] += 1
        self.expire_reassemblies()
        try:
            payload = self._reasm.add(msg.sender_did, msg.msg_class, msg.payload, now)
        except FragmentError as e:
            self.stats[f"rejected_fragment_{e.reason}"] += 1
            return
        if payload is None:
            return  # waiting for more fragments

        self.stats["received"] += 1
        try:
            cls: int | MsgClass = MsgClass(msg.msg_class)
        except ValueError:
            cls = msg.msg_class
        for h in self._handlers:
            h(msg.sender_did, cls, payload)
