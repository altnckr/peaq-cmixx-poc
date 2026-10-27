"""Transports.

``Transport`` is the seam where the real xxDK / cMixx plugs in.

* ``SimulatedMixnet`` / ``SimEndpoint`` - deterministic discrete-event model of a
  batching mixnet (rounds, processing delay, loss). It exists so the rest of the
  stack can be developed and tested offline. Its latency numbers are *model
  parameters*, NOT measurements of the xx network.
* ``SidecarTransport`` - talks to an external process over JSON lines. The real
  implementation of that process (Go + xxDK) is NOT included; see
  ``sidecar/README.md`` for the protocol. ``sidecar/fake_sidecar.py`` is a
  loopback stand-in used to test the plumbing.
"""
from __future__ import annotations

import base64
import json
import queue
import random
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Callable

Handler = Callable[[bytes], None]


class TransportError(Exception):
    pass


class Transport(ABC):
    max_message_bytes: int

    @property
    @abstractmethod
    def contact(self) -> bytes:
        """Opaque address other machines use to reach this endpoint."""

    @abstractmethod
    def send(self, contact: bytes, data: bytes) -> None: ...

    @abstractmethod
    def set_handler(self, handler: Handler) -> None: ...

    def available(self) -> bool:
        return True

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Simulated mixnet
# --------------------------------------------------------------------------- #
class SimClock:
    def __init__(self) -> None:
        self.now = 0.0


class SimulatedMixnet:
    """Batching mixnet model.

    Every ``round_interval_s`` the messages sent since the previous round are
    shuffled together as one batch and delivered ``processing_delay_s`` later.
    """

    def __init__(
        self,
        round_interval_s: float = 1.0,
        processing_delay_s: float = 2.0,
        loss_rate: float = 0.0,
        max_message_bytes: int = 384,
        seed: int = 0,
    ) -> None:
        self.clock = SimClock()
        self.round_interval_s = round_interval_s
        self.processing_delay_s = processing_delay_s
        self.loss_rate = loss_rate
        self.max_message_bytes = max_message_bytes
        self._rng = random.Random(seed)
        self._inboxes: dict[bytes, "SimEndpoint"] = {}
        self._pending: list[tuple[float, bytes, bytes]] = []          # (sent_at, to, data)
        self._in_flight: list[tuple[float, float, bytes, bytes]] = []  # (deliver_at, sent_at, to, data)
        self._next_round = round_interval_s
        # metrics
        self.sent = 0
        self.dropped_loss = 0
        self.dropped_unknown = 0
        self.delivered = 0
        self.latencies: list[float] = []
        self.batch_sizes: list[int] = []

    def endpoint(self) -> "SimEndpoint":
        ep = SimEndpoint(self, self._rng.randbytes(16))
        self._inboxes[ep.contact] = ep
        return ep

    # -- internal -----------------------------------------------------------
    def _submit(self, to: bytes, data: bytes) -> None:
        if len(data) > self.max_message_bytes:
            raise TransportError(f"message {len(data)} B exceeds limit {self.max_message_bytes} B")
        self.sent += 1
        if self._rng.random() < self.loss_rate:
            self.dropped_loss += 1
            return
        self._pending.append((self.clock.now, to, data))

    def run_until(self, t_end: float) -> None:
        inf = float("inf")
        while True:
            next_delivery = min((d[0] for d in self._in_flight), default=inf)
            t = min(self._next_round, next_delivery)
            if t > t_end:
                break
            self.clock.now = t
            if next_delivery <= self._next_round:
                due = [d for d in self._in_flight if d[0] <= t]
                self._in_flight = [d for d in self._in_flight if d[0] > t]
                for _, sent_at, to, data in due:
                    ep = self._inboxes.get(to)
                    if ep is None or ep._handler is None:
                        self.dropped_unknown += 1
                        continue
                    self.delivered += 1
                    self.latencies.append(t - sent_at)
                    ep._handler(data)
            else:
                batch, self._pending = self._pending, []
                self._rng.shuffle(batch)
                self.batch_sizes.append(len(batch))
                for sent_at, to, data in batch:
                    self._in_flight.append((t + self.processing_delay_s, sent_at, to, data))
                self._next_round += self.round_interval_s
        self.clock.now = max(self.clock.now, t_end)

    def run_until_idle(self, max_s: float = 600.0) -> None:
        limit = self.clock.now + max_s
        while (self._pending or self._in_flight) and self.clock.now < limit:
            self.run_until(min(self.clock.now + self.round_interval_s, limit))


class SimEndpoint(Transport):
    def __init__(self, net: SimulatedMixnet, contact: bytes) -> None:
        self._net = net
        self._contact = contact
        self._handler: Handler | None = None
        self.online = True

    @property
    def contact(self) -> bytes:
        return self._contact

    @property
    def max_message_bytes(self) -> int:  # type: ignore[override]
        return self._net.max_message_bytes

    def send(self, contact: bytes, data: bytes) -> None:
        if not self.online:
            raise TransportError("endpoint offline")
        self._net._submit(contact, data)

    def set_handler(self, handler: Handler) -> None:
        self._handler = handler

    def available(self) -> bool:
        return self.online


# --------------------------------------------------------------------------- #
# Sidecar transport (JSON lines over stdin/stdout)
# --------------------------------------------------------------------------- #
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class SidecarTransport(Transport):
    """Client for an external xxDK sidecar process. Protocol: sidecar/README.md."""

    def __init__(self, cmd: list[str], startup_timeout_s: float = 15.0, send_timeout_s: float = 30.0) -> None:
        self._send_timeout = send_timeout_s
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )
        self._wlock = threading.Lock()
        self._handler: Handler | None = None
        self._ready: "queue.Queue[dict]" = queue.Queue()
        self._acks: dict[int, "queue.Queue[dict]"] = {}
        self._next_id = 1
        self._alive = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        self._write({"op": "hello"})
        try:
            msg = self._ready.get(timeout=startup_timeout_s)
        except queue.Empty:
            self.close()
            raise TransportError("sidecar did not become ready") from None
        self._contact = base64.b64decode(msg["contact"])
        self.max_message_bytes = int(msg["max_message_bytes"])

    @property
    def contact(self) -> bytes:
        return self._contact

    def _write(self, obj: dict) -> None:
        with self._wlock:
            try:
                self._proc.stdin.write(json.dumps(obj) + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, ValueError) as e:
                raise TransportError("sidecar pipe closed") from e

    def _read_loop(self) -> None:
        for line in self._proc.stdout:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            op = msg.get("op")
            if op == "ready":
                self._ready.put(msg)
            elif op in ("sent", "error") and "id" in msg:
                q = self._acks.get(msg["id"])
                if q is not None:
                    q.put(msg)
            elif op == "recv" and self._handler is not None:
                self._handler(base64.b64decode(msg["data"]))
        self._alive = False

    def send(self, contact: bytes, data: bytes) -> None:
        if len(data) > self.max_message_bytes:
            raise TransportError(f"message {len(data)} B exceeds limit {self.max_message_bytes} B")
        mid = self._next_id
        self._next_id += 1
        q: "queue.Queue[dict]" = queue.Queue()
        self._acks[mid] = q
        try:
            self._write({"op": "send", "id": mid, "contact": _b64(contact), "data": _b64(data)})
            try:
                ack = q.get(timeout=self._send_timeout)
            except queue.Empty:
                raise TransportError("sidecar send timed out") from None
            if ack.get("op") == "error":
                raise TransportError(ack.get("message", "sidecar error"))
        finally:
            self._acks.pop(mid, None)

    def set_handler(self, handler: Handler) -> None:
        self._handler = handler

    def available(self) -> bool:
        return self._alive and self._proc.poll() is None

    def close(self) -> None:
        try:
            self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.wait(timeout=3)
        except Exception:
            self._proc.kill()
        self._reader.join(timeout=2)
        try:
            self._proc.stdout.close()
        except Exception:
            pass
        self._alive = False
