# peaq × cMixx — Private Channel Module (Phase 1 PoC skeleton, v0.2)

> **Independent community project.** Not affiliated with, endorsed by, or maintained by xx network, peaq, or the teams or foundations behind them. The analysis, documents and code were produced with the help of an AI assistant (Claude) and have not been reviewed by domain experts or audited. Everything here runs against a simulation.

Reference skeleton for an optional metadata-private communication lane for peaq
machines, built around xx network's cMixx via xxDK. It accompanies the
architecture draft "cMixx × peaq: Private Machine-to-Machine Communication".

**Status: offline skeleton, not a working integration.** It runs and is tested
against a *simulated* mixnet. It does **not** talk to the real xx network or to
the peaq chain yet. Read "What is mocked" before drawing any conclusion.

## What changed in v0.2

A former xx engineer indicated that one cMixx message carries **at least ~3078
bits (about 384 bytes)**, which he said came from the size of the prime in use
and is "about 90% confident" it can be relied on. This is **an unverified
working assumption**; the real limit should be read from the network at
runtime (xxDK exposes a "max message length" for the current network), and this
module already reads it from `transport.max_message_bytes` on every send.

The v0.1 envelope used ~215 bytes of overhead and would have left only ~124
payload bytes at this size. v0.2 therefore has:

* a **compact, fixed-size envelope** (149 bytes overhead; 233 payload bytes per 384-byte message);
* **fragmentation and bounded reassembly** for larger payloads;
* defaults changed from 1024 to 384 bytes.

## Quick start

```bash
pip install -r requirements.txt                # only needs `cryptography`
python -m unittest discover -s tests -t . -v   # 33 tests
python -m peaq_cmixx_poc.sim                   # demo on the simulated mixnet
python -m peaq_cmixx_poc.sim --payload-bytes 1000 --loss 0.02
```

Tested with Python 3.12.

## What it does

* **Identity** (`identity.py`): per-machine Ed25519 (signing) + X25519 (key agreement) keys, a mock DID and an 8-byte key id used on the wire.
* **Registry** (`registry.py`): `PeaqRegistry` interface + in-memory mock for *channel-binding records* (DID → public keys + cMixx contact), resolvable by DID or key id.
* **Envelope** (`envelope.py`): signed, encrypted, fixed-size message (exactly the transport's message size). Signature checked before decryption; replay id and timestamp included.
* **Fragmentation** (`fragment.py`): splits larger payloads into authenticated fragments; reassembly is bounded (max pending, timeout) and never delivers partial messages.
* **Policy** (`policy.py`): traffic classes → lanes. `CONTROL` and `VIDEO` are never sent over the mixnet. `PAYMENT_INTENT` / `CREDENTIAL` are rejected rather than silently downgraded if the private lane is down. Telemetry-like classes are queued and retried.
* **Channel** (`channel.py`): the public API — `publish_binding`, `send`, `on_message`, `flush_outbox`. Inbound failures are counted and silently dropped (no oracle).
* **Transports** (`transport.py`): the `Transport` seam, a deterministic `SimulatedMixnet`, and a `SidecarTransport` (JSON lines) for the future xxDK process.
* **Sidecar protocol** (`sidecar/README.md`): the contract the real xxDK bridge must implement, plus `fake_sidecar.py` (loopback, for tests only). The bridge language is open: native Go or an xxDK WASM build under Node would both fit, since the protocol is just JSON lines.

## What is mocked — please read

| Piece | In this PoC | In production |
|---|---|---|
| xx network / cMixx | `SimulatedMixnet`: batching rounds with configurable delay and loss | real xxDK client via the bridge |
| Message size | 384 B working assumption (unverified) | read from the network at runtime |
| Latency numbers | **model parameters you choose** — not measurements | measured on mainnet (Phase 1 deliverable) |
| Anonymity | simulated batches only; **no real anonymity property is demonstrated** | depends on real cMixx rounds and traffic volume |
| peaq identity | locally generated keys, DID = hash of public key | on-chain peaq DID / peaq ID |
| Binding record | in-memory dict | record on peaq chain (record type is an open question) |
| Fees | none | xx coin fees; sponsorship / relay model undecided |
| xxDK bridge | **not implemented** (only the protocol and a loopback fake) | Go or WASM program built from official xxDK docs |

## Known limitations

* **Fragmentation amplifies loss and cost.** A message of *n* fragments is lost if any fragment is lost: with 2% simulated loss, 1-fragment messages all arrived while 5-fragment (1 KB) messages lost about 7%. Each fragment is also a separate mixnet message (a 1 KB batch = 5 messages, each with its own fee). Mitigations to consider: keep telemetry small, acknowledgements and selective retransmission, erasure coding, or xxDK's own chunking layer.
* **A 64-byte signature per fragment** is the largest overhead item (149 of 384 bytes). An authenticated session (one signed handshake, then MACs) would raise payload capacity substantially.
* Ed25519/X25519 are **not post-quantum**; quantum resistance of the full channel is expected to come from xxDK. Post-quantum signatures would not fit this message budget without much heavier chunking.
* Not audited. Do not use for anything sensitive before independent review.
* Replay protection is in-memory (lost on restart) and time-window based; needs clock sanity on devices.
* Queued messages that fail the latency budget are retried forever; production needs expiry and persistence.
* A transport failure part-way through a multi-fragment send leaves an incomplete message that the receiver expires; there is no resume.
* Machine private keys live in process memory. Production should use secure hardware where available.
* Payments settled on peaq are public and can be correlated in time with private messages (see architecture draft, section 8).

## How to plug in the real pieces

1. **Real xxDK:** implement the bridge per `sidecar/README.md` (Go or WASM), report the real per-message limit in `ready`, then `SidecarTransport([...])`. Everything above the `Transport` interface stays unchanged.
2. **Real peaq lookup:** implement `PeaqRegistry.register/resolve/resolve_by_key_id` against the peaq chain (DID document / storage), including the "registered, bonded, in good standing" check as `active`.
3. **Measure:** run the same `sim.py` scenario with the real transport and record latency, delivery rate, real message limit and client footprint — the Phase 1 report.

## Suggested Phase 1 milestones (for a grant application)

1. Real xxDK bridge + `SidecarTransport` passing the existing transport tests against mainnet or a testnet.
2. peaq registry implementation resolving real DIDs on a peaq test network.
3. Measurement report: latency distribution, delivery rate (including multi-fragment messages), confirmed message size limit, CPU/RAM on a Raspberry-Pi-class device or in a browser/WASM runtime.
4. Reference demo: two machines exchanging signed telemetry end to end, with the policy engine keeping control traffic off the mixnet.
5. Updated threat model and an answer to each open question in the architecture draft.

## Layout

```
peaq_cmixx_poc/  identity.py registry.py envelope.py fragment.py policy.py transport.py channel.py sim.py
sidecar/         README.md (protocol)  fake_sidecar.py (test loopback)
tests/           test_poc.py
```
