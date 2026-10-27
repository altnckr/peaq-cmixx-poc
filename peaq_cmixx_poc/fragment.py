"""Fragmentation and reassembly for payloads larger than one envelope.

Every fragment travels in its own signed, encrypted envelope, so each one is
independently authenticated. Fragment header (inside the encrypted payload)::

    msg_id  4   random id shared by all fragments of one message
    index   1
    total   1   number of fragments (1..255)

Reassembly state is bounded: at most ``max_pending`` incomplete messages are
tracked and each expires after ``timeout_s``. Incomplete messages are dropped,
never delivered partially.

Cost note: with a 384-byte budget a fragment carries ~227 payload bytes, so a
1 KB telemetry batch needs 5 mixnet messages. Using xxDK's own chunking layer,
or an authenticated session instead of a signature per fragment, are possible
later optimisations.
"""
from __future__ import annotations

from dataclasses import dataclass, field

HEADER_LEN = 6
MAX_FRAGMENTS = 255


class FragmentError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def split(payload: bytes, chunk_size: int, msg_id: bytes) -> list[bytes]:
    """Split ``payload`` into fragments of at most ``chunk_size`` payload bytes."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if len(msg_id) != 4:
        raise ValueError("msg_id must be 4 bytes")
    total = max(1, -(-len(payload) // chunk_size))
    if total > MAX_FRAGMENTS:
        raise ValueError(f"payload needs {total} fragments, limit is {MAX_FRAGMENTS}")
    return [
        msg_id + bytes([i, total]) + payload[i * chunk_size : (i + 1) * chunk_size]
        for i in range(total)
    ]


@dataclass
class _Pending:
    total: int
    msg_class: int
    first_seen: float
    parts: dict[int, bytes] = field(default_factory=dict)


class Reassembler:
    def __init__(self, timeout_s: float = 120.0, max_pending: int = 64) -> None:
        self.timeout_s = timeout_s
        self.max_pending = max_pending
        self._pending: dict[tuple[str, bytes], _Pending] = {}

    def __len__(self) -> int:
        return len(self._pending)

    def add(self, sender: str, msg_class: int, fragment: bytes, now: float) -> bytes | None:
        """Add one fragment. Returns the full payload when complete, else None."""
        if len(fragment) < HEADER_LEN:
            raise FragmentError("short_fragment")
        msg_id, index, total = fragment[:4], fragment[4], fragment[5]
        body = fragment[HEADER_LEN:]
        if total < 1 or index >= total:
            raise FragmentError("bad_index")
        if total == 1:
            return body

        key = (sender, msg_id)
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.max_pending:
                raise FragmentError("too_many_pending")
            entry = self._pending[key] = _Pending(total, msg_class, now)
        elif entry.total != total or entry.msg_class != msg_class:
            raise FragmentError("inconsistent")

        if index in entry.parts:
            return None  # duplicate fragment: ignore
        entry.parts[index] = body
        if len(entry.parts) < entry.total:
            return None
        del self._pending[key]
        return b"".join(entry.parts[i] for i in range(entry.total))

    def expire(self, now: float) -> int:
        """Drop incomplete messages older than the timeout; return how many."""
        dead = [k for k, e in self._pending.items() if now - e.first_seen > self.timeout_s]
        for k in dead:
            del self._pending[k]
        return len(dead)
