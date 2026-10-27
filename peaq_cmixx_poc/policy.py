"""Traffic policy engine.

Decides, per message class, whether a message may use the private (cMixx) lane.
Core principle from the architecture draft: cMixx is a *privacy lane*, not a
replacement for real-time robot networking. Control and video traffic are never
routed through the mixnet.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum


class MsgClass(IntEnum):
    TELEMETRY = 1
    TASK_RESULT = 2
    PAYMENT_INTENT = 3
    CREDENTIAL = 4
    MAINTENANCE = 5
    CONTROL = 250   # closed-loop / real-time control: never over the mixnet
    VIDEO = 251     # high-bandwidth streams: never over the mixnet


class Lane(Enum):
    PRIVATE = "private"   # send over cMixx
    DIRECT = "direct"     # caller uses its existing low-latency channel
    QUEUE = "queue"       # hold and retry when the private lane is available
    REJECT = "reject"     # refuse (no silent downgrade of privacy)


@dataclass(frozen=True)
class ClassRule:
    private_ok: bool
    latency_budget_s: float
    on_unavailable: Lane


@dataclass(frozen=True)
class Decision:
    lane: Lane
    reason: str


DEFAULT_RULES: dict[int, ClassRule] = {
    MsgClass.TELEMETRY:      ClassRule(True, 30.0, Lane.QUEUE),
    MsgClass.TASK_RESULT:    ClassRule(True, 30.0, Lane.QUEUE),
    MsgClass.MAINTENANCE:    ClassRule(True, 300.0, Lane.QUEUE),
    # Privacy-critical: never silently downgrade to a non-private path.
    MsgClass.PAYMENT_INTENT: ClassRule(True, 60.0, Lane.REJECT),
    MsgClass.CREDENTIAL:     ClassRule(True, 30.0, Lane.REJECT),
    MsgClass.CONTROL:        ClassRule(False, 0.05, Lane.DIRECT),
    MsgClass.VIDEO:          ClassRule(False, 0.2, Lane.DIRECT),
}


class TrafficPolicy:
    def __init__(self, rules: dict[int, ClassRule] | None = None) -> None:
        self.rules = dict(DEFAULT_RULES if rules is None else rules)

    def decide(
        self,
        msg_class: int,
        private_available: bool = True,
        est_latency_s: float | None = None,
    ) -> Decision:
        rule = self.rules.get(msg_class)
        if rule is None:
            return Decision(Lane.REJECT, "unknown message class")
        if not rule.private_ok:
            return Decision(Lane.DIRECT, "class needs low latency; never sent over the mixnet")
        if not private_available:
            return Decision(rule.on_unavailable, "private lane unavailable")
        if est_latency_s is not None and est_latency_s > rule.latency_budget_s:
            return Decision(rule.on_unavailable, "expected latency exceeds class budget")
        return Decision(Lane.PRIVATE, "ok")
