"""Demo / benchmark on the SIMULATED mixnet.

    python -m peaq_cmixx_poc.sim [--robots 5] [--messages 20] [--interval 5]
                                 [--round 1.0] [--delay 2.0] [--loss 0.02]
                                 [--payload-bytes 300] [--wire-size 384]

IMPORTANT: every latency / delivery number printed here comes from the model
parameters you pass in. It is NOT a measurement of the xx network. Replace the
transport with the real xxDK sidecar to get real numbers (Phase 1 goal).
"""
from __future__ import annotations

import argparse
import statistics

from .channel import PrivateChannelModule
from .identity import MachineIdentity
from .policy import Lane, MsgClass
from .registry import MockPeaqRegistry
from .transport import SimulatedMixnet

EPOCH = 1_800_000_000.0


def _pct(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))]


def run(robots: int, messages: int, interval: float, round_s: float, delay_s: float, loss: float, seed: int,
        payload_bytes: int = 300, wire_size: int = 384) -> dict:
    net = SimulatedMixnet(round_interval_s=round_s, processing_delay_s=delay_s, loss_rate=loss,
                          max_message_bytes=wire_size, seed=seed)
    registry = MockPeaqRegistry()
    now = lambda: EPOCH + net.clock.now

    backend_id = MachineIdentity("backend")
    backend = PrivateChannelModule(backend_id, registry, net.endpoint(), now_fn=now)
    backend.publish_binding()
    received: list[tuple[str, int]] = []
    backend.on_message(lambda did, cls, data: received.append((did, int(cls))))

    fleet = []
    for i in range(robots):
        m = PrivateChannelModule(MachineIdentity(f"robot-{i}"), registry, net.endpoint(), now_fn=now)
        m.publish_binding()
        fleet.append(m)

    sizes: set[int] = set()
    sent = direct = fragments = 0
    for k in range(messages):
        for i, robot in enumerate(fleet):
            # robots are not synchronised with mix rounds: stagger their sends
            net.run_until(k * interval + (i * 0.37) % interval)
            head = f"robot={i} seq={k} temp={20 + (i + k) % 7}.{k % 10};".encode()
            payload = (head * (payload_bytes // len(head) + 1))[:payload_bytes]
            res = robot.send(backend_id.did, MsgClass.TELEMETRY, payload)
            if res.sent:
                sent += 1
                fragments += res.fragments
                sizes.add(res.wire_bytes // res.fragments)
            # a real-time control message must never go over the mixnet
            if robot.send(backend_id.did, MsgClass.CONTROL, b"stop").decision.lane is Lane.DIRECT:
                direct += 1
    net.run_until_idle()

    lat = net.latencies or [0.0]
    return {
        "telemetry_sent": sent,
        "fragments_sent": fragments,
        "telemetry_received": len([1 for _, c in received if c == MsgClass.TELEMETRY]),
        "control_kept_off_mixnet": direct,
        "mixnet_messages_total": net.sent,
        "lost_in_model": net.dropped_loss,
        "latency_mean_s": statistics.mean(lat),
        "latency_p50_s": _pct(lat, 0.50),
        "latency_p95_s": _pct(lat, 0.95),
        "latency_max_s": max(lat),
        "rounds": len(net.batch_sizes),
        "mean_batch_size": statistics.mean([b for b in net.batch_sizes if b] or [0]),
        "distinct_envelope_sizes": sorted(sizes),
        "backend_stats": dict(backend.stats),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--robots", type=int, default=5)
    ap.add_argument("--messages", type=int, default=20, help="telemetry messages per robot")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between telemetry messages")
    ap.add_argument("--round", type=float, default=1.0, dest="round_s", help="mix round interval (s)")
    ap.add_argument("--delay", type=float, default=2.0, help="mix processing delay (s)")
    ap.add_argument("--loss", type=float, default=0.02, help="model loss probability")
    ap.add_argument("--payload-bytes", type=int, default=300, help="telemetry payload size per message")
    ap.add_argument("--wire-size", type=int, default=384, help="bytes per mixnet message (working assumption)")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()

    r = run(a.robots, a.messages, a.interval, a.round_s, a.delay, a.loss, a.seed,
            a.payload_bytes, a.wire_size)
    print("== cMixx x peaq PoC - SIMULATED mixnet (model parameters, not xx measurements) ==")
    print(f"robots={a.robots} messages/robot={a.messages} interval={a.interval}s "
          f"round={a.round_s}s delay={a.delay}s loss={a.loss}")
    print(f"payload={a.payload_bytes} B  wire size={a.wire_size} B per mixnet message")
    print(f"telemetry sent / received : {r['telemetry_sent']} / {r['telemetry_received']} "
          f"(complete messages; {r['fragments_sent']} mixnet messages used)")
    print(f"control msgs kept off mix : {r['control_kept_off_mixnet']} (routed DIRECT by policy)")
    print(f"latency mean/p50/p95/max  : {r['latency_mean_s']:.2f} / {r['latency_p50_s']:.2f} / "
          f"{r['latency_p95_s']:.2f} / {r['latency_max_s']:.2f} s")
    print(f"mix rounds, mean batch    : {r['rounds']}, {r['mean_batch_size']:.1f} msgs/round (non-empty rounds)")
    print(f"mixnet message sizes      : {r['distinct_envelope_sizes']} bytes (fixed)")
    print(f"backend stats             : {r['backend_stats']}")


if __name__ == "__main__":
    main()
