import os
import sys
import unittest

from peaq_cmixx_poc import envelope, fragment
from peaq_cmixx_poc.channel import PayloadTooLarge, PrivateChannelModule, UnknownPeer
from peaq_cmixx_poc.identity import MachineIdentity
from peaq_cmixx_poc.policy import Lane, MsgClass, TrafficPolicy
from peaq_cmixx_poc.registry import ChannelBinding, MockPeaqRegistry, RegistryError
from peaq_cmixx_poc.transport import SidecarTransport, SimulatedMixnet, TransportError

EPOCH = 1_800_000_000.0
WIRE = 384  # working assumption: ~3078 bits per cMixx message
FAKE_SIDECAR = os.path.join(os.path.dirname(__file__), "..", "sidecar", "fake_sidecar.py")


class Net:
    """Two machines on a simulated mixnet with a shared registry."""

    def __init__(self, **net_kwargs):
        self.net = SimulatedMixnet(**net_kwargs)
        self.registry = MockPeaqRegistry()
        now = lambda: EPOCH + self.net.clock.now
        self.a_id, self.b_id = MachineIdentity("robot"), MachineIdentity("backend")
        self.a_tx, self.b_tx = self.net.endpoint(), self.net.endpoint()
        self.a = PrivateChannelModule(self.a_id, self.registry, self.a_tx, now_fn=now)
        self.b = PrivateChannelModule(self.b_id, self.registry, self.b_tx, now_fn=now)
        self.a.publish_binding()
        self.b.publish_binding()
        self.inbox = []
        self.b.on_message(lambda did, cls, data: self.inbox.append((did, cls, data)))


def _pair():
    a, b = MachineIdentity("a"), MachineIdentity("b")
    reg = MockPeaqRegistry()
    for m in (a, b):
        reg.register(ChannelBinding(m.did, m.sign_pub, m.kex_pub, b"c"))
    return a, b, reg


class EnvelopeTests(unittest.TestCase):
    def test_roundtrip(self):
        a, b, reg = _pair()
        raw = envelope.seal(a, reg.resolve(b.did), 1, b"hello", ts_s=123, wire_size=WIRE)
        out = envelope.open_(b, raw, reg.resolve_by_key_id)
        self.assertEqual(out.payload, b"hello")
        self.assertEqual(out.sender_did, a.did)
        self.assertEqual(out.msg_class, 1)

    def test_every_envelope_is_exactly_wire_size(self):
        a, b, reg = _pair()
        bb = reg.resolve(b.did)
        for n in (0, 1, 50, 100, envelope.capacity(WIRE)):
            raw = envelope.seal(a, bb, 1, b"x" * n, 0, WIRE)
            self.assertEqual(len(raw), WIRE)

    def test_capacity_at_384_is_233_bytes(self):
        self.assertEqual(envelope.capacity(384), 233)
        a, b, reg = _pair()
        with self.assertRaises(ValueError):
            envelope.seal(a, reg.resolve(b.did), 1, b"x" * 234, 0, 384)

    def test_garbage_is_malformed(self):
        b = MachineIdentity("b")
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.open_(b, b"nonsense", lambda d: None)
        self.assertEqual(cm.exception.reason, "malformed")

    def test_registry_rejects_mismatched_did(self):
        a = MachineIdentity("a")
        with self.assertRaises(RegistryError):
            MockPeaqRegistry().register(ChannelBinding("did:peaq:mock:fake", a.sign_pub, a.kex_pub, b"c"))


class FragmentTests(unittest.TestCase):
    def test_split_and_reassemble_out_of_order(self):
        data = os.urandom(1000)
        parts = fragment.split(data, 227, b"abcd")
        self.assertEqual(len(parts), 5)
        r = fragment.Reassembler()
        out = None
        for p in reversed(parts):
            out = r.add("did:x", 1, p, now=0.0)
        self.assertEqual(out, data)
        self.assertEqual(len(r), 0)

    def test_duplicate_fragment_is_ignored(self):
        parts = fragment.split(b"y" * 500, 227, b"abcd")
        r = fragment.Reassembler()
        self.assertIsNone(r.add("d", 1, parts[0], 0))
        self.assertIsNone(r.add("d", 1, parts[0], 0))
        self.assertIsNone(r.add("d", 1, parts[1], 0))
        self.assertEqual(r.add("d", 1, parts[2], 0), b"y" * 500)

    def test_inconsistent_fragments_are_rejected(self):
        r = fragment.Reassembler()
        r.add("d", 1, fragment.split(b"z" * 500, 227, b"abcd")[0], 0)
        with self.assertRaises(fragment.FragmentError):
            r.add("d", 1, fragment.split(b"z" * 100, 50, b"abcd")[0], 0)  # same id, different total

    def test_pending_is_bounded_and_expires(self):
        r = fragment.Reassembler(timeout_s=10, max_pending=2)
        for i in range(2):
            r.add("d", 1, fragment.split(b"q" * 500, 227, bytes([i]) * 4)[0], 0)
        with self.assertRaises(fragment.FragmentError):
            r.add("d", 1, fragment.split(b"q" * 500, 227, b"\x09" * 4)[0], 0)
        self.assertEqual(r.expire(5), 0)
        self.assertEqual(r.expire(11), 2)

    def test_too_many_fragments(self):
        with self.assertRaises(ValueError):
            fragment.split(b"x" * 10_000, 10, b"abcd")


class ChannelTests(unittest.TestCase):
    def test_end_to_end_over_simulated_mixnet(self):
        n = Net()
        res = n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"temp=21.5")
        self.assertTrue(res.sent)
        self.assertEqual(res.fragments, 1)
        self.assertEqual(n.inbox, [])  # nothing yet: mixnet has latency
        n.net.run_until_idle()
        self.assertEqual(n.inbox, [(n.a_id.did, MsgClass.TELEMETRY, b"temp=21.5")])
        self.assertGreaterEqual(min(n.net.latencies), n.net.processing_delay_s)

    def test_large_payload_is_fragmented_and_reassembled(self):
        n = Net()
        data = os.urandom(1000)
        res = n.a.send(n.b_id.did, MsgClass.TASK_RESULT, data)
        self.assertEqual(res.fragments, 5)  # 1000 / 227 payload bytes per fragment
        self.assertEqual(n.net.sent, 5)
        n.net.run_until_idle()
        self.assertEqual([d for _, _, d in n.inbox], [data])  # mixnet shuffles; order must not matter
        self.assertEqual(n.b.stats["fragments_received"], 5)

    def test_all_wire_messages_have_identical_size(self):
        n = Net()
        for size in (1, 100, 600):
            n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x" * size)
        self.assertEqual({len(d) for _, _, d in n.net._pending}, {384})

    def test_lost_fragment_means_no_delivery_and_expiry(self):
        n = Net()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x" * 600)  # 3 fragments
        n.net._pending.pop()                                   # one is lost in the network
        n.net.run_until_idle()
        self.assertEqual(n.inbox, [])
        n.net.clock.now += 500
        self.assertEqual(n.b.expire_reassemblies(), 1)
        self.assertEqual(n.b.stats["reassembly_expired"], 1)

    def test_tampered_message_is_dropped(self):
        n = Net()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"data")
        raw = bytearray(n.net._pending[0][2])
        raw[len(raw) // 2] ^= 0x01
        n.b.handle_raw(bytes(raw))
        self.assertEqual(n.inbox, [])
        self.assertEqual(n.b.stats["rejected_bad_signature"], 1)

    def test_replay_is_dropped(self):
        n = Net()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"once")
        raw = n.net._pending[0][2]
        n.b.handle_raw(raw)
        n.b.handle_raw(raw)
        self.assertEqual(len(n.inbox), 1)
        self.assertEqual(n.b.stats["rejected_replay"], 1)

    def test_stale_message_is_dropped(self):
        n = Net()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"old")
        raw = n.net._pending[0][2]
        n.net.clock.now += 3600  # an hour later
        n.b.handle_raw(raw)
        self.assertEqual(n.inbox, [])
        self.assertEqual(n.b.stats["rejected_stale"], 1)

    def test_message_for_someone_else_is_rejected(self):
        n = Net()
        c_id = MachineIdentity("other")
        c = PrivateChannelModule(c_id, n.registry, n.net.endpoint(), now_fn=lambda: EPOCH + n.net.clock.now)
        c.publish_binding()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"for b only")
        c.handle_raw(n.net._pending[0][2])
        self.assertEqual(c.stats["rejected_wrong_recipient"], 1)

    def test_unknown_sender_is_rejected(self):
        n = Net()
        stranger = MachineIdentity("stranger")
        raw = envelope.seal(stranger, n.registry.resolve(n.b_id.did), 1, b"hi", int(EPOCH), WIRE)
        n.b.handle_raw(raw)
        self.assertEqual(n.b.stats["rejected_unknown_sender"], 1)

    def test_revoked_sender_is_rejected(self):
        n = Net()
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x")
        raw = n.net._pending[0][2]
        n.registry.deactivate(n.a_id.did)
        n.b.handle_raw(raw)
        self.assertEqual(n.b.stats["rejected_unknown_sender"], 1)

    def test_unknown_peer_raises(self):
        n = Net()
        with self.assertRaises(UnknownPeer):
            n.a.send("did:peaq:mock:nobody", MsgClass.TELEMETRY, b"x")

    def test_payload_over_module_limit_raises(self):
        n = Net()
        with self.assertRaises(PayloadTooLarge):
            n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x" * 20_000)

    def test_tiny_transport_limit_raises(self):
        n = Net(max_message_bytes=100)  # smaller than the fixed envelope overhead
        with self.assertRaises(PayloadTooLarge):
            n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x")

    def test_limit_is_read_from_transport_each_time(self):
        n = Net(max_message_bytes=384)
        n.net.max_message_bytes = 512  # the "network" limit changes at runtime
        res = n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x" * 300)
        self.assertEqual(res.fragments, 1)  # 512 B envelope carries 361 payload bytes
        n.net.run_until_idle()
        self.assertEqual(len(n.inbox), 1)


class PolicyTests(unittest.TestCase):
    def test_control_and_video_never_use_the_mixnet(self):
        n = Net()
        for cls in (MsgClass.CONTROL, MsgClass.VIDEO):
            res = n.a.send(n.b_id.did, cls, b"x")
            self.assertEqual(res.decision.lane, Lane.DIRECT)
            self.assertFalse(res.sent)
        self.assertEqual(n.net.sent, 0)

    def test_payment_is_rejected_not_downgraded_when_offline(self):
        n = Net()
        n.a_tx.online = False
        res = n.a.send(n.b_id.did, MsgClass.PAYMENT_INTENT, b"pay")
        self.assertEqual(res.decision.lane, Lane.REJECT)
        self.assertFalse(res.sent)

    def test_telemetry_is_queued_then_flushed(self):
        n = Net()
        n.a_tx.online = False
        res = n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"later")
        self.assertTrue(res.queued)
        self.assertEqual(n.a.flush_outbox(), 0)  # still offline
        self.assertEqual(len(n.a.outbox), 1)
        n.a_tx.online = True
        self.assertEqual(n.a.flush_outbox(), 1)
        n.net.run_until_idle()
        self.assertEqual([d for _, _, d in n.inbox], [b"later"])

    def test_latency_budget_is_enforced(self):
        n = Net()
        n.a.expected_latency_s = 120.0  # worse than the telemetry budget (30 s)
        res = n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x")
        self.assertTrue(res.queued)

    def test_unknown_class_is_rejected(self):
        self.assertEqual(TrafficPolicy().decide(99).lane, Lane.REJECT)


class SimulationTests(unittest.TestCase):
    def test_loss_is_counted(self):
        n = Net(loss_rate=1.0)
        n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"x")
        n.net.run_until_idle()
        self.assertEqual(n.net.dropped_loss, 1)
        self.assertEqual(n.inbox, [])

    def test_messages_are_batched_per_round(self):
        n = Net(round_interval_s=1.0)
        for i in range(5):
            n.a.send(n.b_id.did, MsgClass.TELEMETRY, b"m%d" % i)
        n.net.run_until_idle()
        self.assertEqual(n.net.batch_sizes[0], 5)
        self.assertEqual(len(n.inbox), 5)


class SidecarTests(unittest.TestCase):
    def test_loopback_through_fake_sidecar(self):
        import queue

        tx = SidecarTransport([sys.executable, FAKE_SIDECAR], startup_timeout_s=10)
        try:
            got: "queue.Queue[bytes]" = queue.Queue()
            tx.set_handler(got.put)
            self.assertEqual(tx.max_message_bytes, 384)
            tx.send(tx.contact, b"ping")
            self.assertEqual(got.get(timeout=5), b"ping")
            with self.assertRaises(TransportError):
                tx.send(tx.contact, b"x" * 2000)
        finally:
            tx.close()

    def test_full_stack_through_fake_sidecar(self):
        """A module talking to ITSELF through the sidecar: seal -> sidecar -> open."""
        import time

        tx = SidecarTransport([sys.executable, FAKE_SIDECAR], startup_timeout_s=10)
        try:
            reg = MockPeaqRegistry()
            ident = MachineIdentity("loop")
            m = PrivateChannelModule(ident, reg, tx)
            m.publish_binding()
            got = []
            m.on_message(lambda did, cls, data: got.append(data))
            data = os.urandom(700)  # 4 fragments through the JSON-lines protocol
            m.send(ident.did, MsgClass.TELEMETRY, data)
            deadline = time.time() + 5
            while not got and time.time() < deadline:
                time.sleep(0.02)
            self.assertEqual(got, [data])
        finally:
            tx.close()


if __name__ == "__main__":
    unittest.main()
