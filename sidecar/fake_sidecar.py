"""Loopback stand-in for the real xxDK sidecar (NOT a mixnet, NOT private).

Implements the JSON-lines protocol from sidecar/README.md. Messages sent to its
own contact are echoed back as ``recv``; messages to any other contact are
acknowledged and discarded. Used only to test ``SidecarTransport``.
"""
import base64
import json
import os
import sys


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    own = os.urandom(16)
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        op = msg.get("op")
        if op == "hello":
            emit({"op": "ready", "contact": base64.b64encode(own).decode(), "max_message_bytes": 384})
        elif op == "send":
            data = base64.b64decode(msg["data"])
            if len(data) > 384:
                emit({"op": "error", "id": msg["id"], "message": "too large"})
                continue
            emit({"op": "sent", "id": msg["id"]})
            if base64.b64decode(msg["contact"]) == own:
                emit({"op": "recv", "data": msg["data"]})


if __name__ == "__main__":
    main()
