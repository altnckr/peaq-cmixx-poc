# xxDK sidecar protocol

The Python PoC talks to cMixx through a small external process (the *sidecar* or
*bridge*), because xxDK is Go-based. The bridge can be a native Go program or,
if xxDK's WASM build is suitable, a Node/WASM process: the protocol below is
language-neutral. **The real sidecar is not included**: I could not
verify xxDK's current API from the environment this PoC was written in, so I
did not write calls I cannot check. Whoever implements it should take the exact
calls from the official xxDK documentation and examples.

`fake_sidecar.py` implements this protocol as a plain loopback. It is only for
testing the Python side.

## Transport

Newline-delimited JSON over the sidecar's stdin (requests) and stdout (events).
All binary fields are standard base64. Logs must go to stderr, never stdout.

## Messages

Python -> sidecar:

| op      | fields                          | meaning                                  |
|---------|---------------------------------|------------------------------------------|
| `hello` | -                               | start up, create or load a cMixx identity |
| `send`  | `id` (int), `contact`, `data`   | send `data` to the peer identified by `contact` |

Sidecar -> Python:

| op      | fields                                   | meaning                                  |
|---------|------------------------------------------|------------------------------------------|
| `ready` | `contact`, `max_message_bytes`           | answer to `hello`; `contact` is this endpoint's opaque address |
| `sent`  | `id`                                     | the message was accepted for sending     |
| `error` | `id`, `message`                          | the send failed                          |
| `recv`  | `data`                                   | an inbound message for this endpoint     |

`sent` means *accepted by the local xxDK client / submitted to the network*,
not "delivered to the peer". cMixx delivery is asynchronous.

## What the Go side must do

1. On `hello`: initialise an xxDK client (persistent state directory, network
   follower running), obtain this endpoint's reachable contact information,
   serialise it to bytes, and report the real per-message payload limit as
   `max_message_bytes` (the largest blob a single `send` may carry, i.e. one
   cMixx message payload; the PoC currently assumes ~384 bytes and the Python
   side reads this value from the bridge, so the real number wins).
2. On `send`: deserialise `contact`, submit `data` via xxDK, answer `sent` or
   `error` with the same `id`.
3. On any inbound message: emit `recv`.
4. Exit cleanly when stdin closes.

## Open questions (from the architecture draft, section 9)

* confirmation of the per-message limit (working assumption ~3078 bits / 384 bytes) and throughput per identity;
* mainnet latency and delivery reliability;
* client footprint on ARM / embedded hardware;
* fee model (xx coin) and whether sponsorship is possible;
* provisioning and rotation of long-lived machine identities.
