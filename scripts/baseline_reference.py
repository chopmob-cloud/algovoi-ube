"""Run our conformance checks against the reference implementation, ube-foundation.

This is the baseline the conformance procedure requires before any claim about our
own code. What it establishes is narrow and worth stating: whether the reference
implementation satisfies the requirements NTI-1 sets out, on the same requests.
It says nothing about whether our harness is right.

The adapter is deliberately minimal. The published request shape differs from the
spec's examples, so the fields were discovered from the validator's own errors:
id, action, actor, nonce, timestamp, payload, capability, input, and optionally a
signature as a list of integers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from algovoi_ube.conformance import run_all  # noqa: E402


def build_adapter(engine, keypair):
    signature = list(keypair.sign_bytes(b"probe"))

    def decide(request: dict) -> str:
        capability = request.get("capability")
        if isinstance(capability, dict):
            cap_id = capability.get("capability_id", "cap-missing")
        elif isinstance(capability, str):
            cap_id = capability
        else:
            # The conformance requests that do not mention a capability still need
            # a live one, otherwise every check denies for "no cap" and each of
            # them passes for a reason that has nothing to do with what it tests.
            # T-1.1 is the case that proved this: an unsigned request was denied
            # only because the capability was absent, not because the signature
            # was.
            cap_id = "cap-fund-transfer"
        payload = {
            "id": str(request.get("request_id") or "req-1"),
            "action": request.get("action", "transfer_funds"),
            "actor": request.get("actor", "agent-1"),
            "nonce": 1,
            "timestamp": 1800000000,
            "payload": {},
            "capability": cap_id,
            "input": {"amount": request.get("amount", 10)},
        }
        if request.get("signed", False):
            payload["signature"] = signature
        answer = engine.evaluate(json.dumps(payload))
        return json.loads(answer).get("decision", "")

    return decide


def main() -> int:
    try:
        import ube_foundation as ube
    except ImportError:
        print("ube-foundation is not installed in this interpreter", file=sys.stderr)
        return 2

    engine = ube.TrustEngine()
    keypair = ube.PqcKeyPair()
    engine.grant("agent-1", "cap-fund-transfer")

    report = run_all(decide=build_adapter(engine, keypair))
    for check in report.checks:
        mark = "pass" if check.passed else "FAIL"
        print(f"  {check.ident:7s} {mark:5s} {check.description[:68]}")
        print(f"          {check.detail}")
    print()
    print(f"  {report.summary()}")

    # The specific case T-1.1 names, tested directly rather than through the
    # adapter, so the result cannot be an artefact of how we build the request.
    print()
    print("  direct check, no signature field at all:")
    base = {
        "id": "req-direct",
        "action": "transfer_funds",
        "actor": "agent-1",
        "nonce": 1,
        "timestamp": 1800000000,
        "payload": {},
        "capability": "cap-fund-transfer",
        "input": {},
    }
    print(f"    {engine.evaluate(json.dumps(base))}")
    for label, variant in (
        ("empty signature list", {**base, "signature": []}),
        ("garbage signature", {**base, "signature": [0] * 4627}),
        ("valid signature", {**base, "signature": list(keypair.sign_bytes(b"probe"))}),
    ):
        print(f"    {label:22s} {engine.evaluate(json.dumps(variant))}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
