#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the issue-#18 conformance vectors, deterministically.

NTI-1 issue #18 asked for shared test vectors: preimage reproducibility, tamper
detection, receipt granularity (truncation), and the duplicate-vote case. These
are written from source, with no randomness, so re-running reproduces the bytes
exactly. `tests/test_issue18_vectors.py` regenerates them to a temp directory and
asserts byte-identical output, and checks each one against the harness itself.

    python scripts/gen_issue18_vectors.py           # write conformance/issue-18/
    python scripts/gen_issue18_vectors.py --check    # fail if the tree is stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.canonical import canonicalize  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _event_hash_colon(event: dict) -> str:
    """The published NTI-1 colon-join scheme, used for the sample chains so the
    vectors drop into the current validator unchanged."""
    preimage = ":".join(
        [
            event["event_id"], event["agent_id"], event["request_hash"],
            event["decision"], event["reason"], event["timestamp"],
            event["parent_hash"],
        ]
    )
    return _sha(preimage.encode("utf-8"))


def _chain(n: int) -> list[dict]:
    events: list[dict] = []
    parent = "0" * 64
    for i in range(n):
        event = {
            "event_id": f"evt-{i + 1}", "agent_id": "agent-001",
            "request_hash": f"{i:064x}", "decision": "Allow",
            "reason": f"action {i + 1}", "timestamp": "2026-02-01T12:00:00Z",
            "parent_hash": parent,
        }
        event["event_hash"] = _event_hash_colon(event)
        parent = event["event_hash"]
        events.append(event)
    return events


def vectors() -> dict[str, dict]:
    event = {
        "event_id": "evt-1", "agent_id": "agent-001", "request_hash": "a" * 64,
        "decision": "Allow", "reason": "permitted under cap-x",
        "timestamp": "2026-02-01T12:00:00Z", "parent_hash": "0" * 64,
    }
    jcs = canonicalize(event)
    a = {"decision": "Allow", "reason": "x:y"}
    b = {"decision": "Allow:x", "reason": "y"}
    colon = lambda d: ":".join([d["decision"], d["reason"]])  # noqa: E731

    c3 = _chain(3)
    tampered = [dict(e) for e in c3]
    tampered[0]["decision"] = "Deny"

    return {
        "preimage_reproducibility": {
            "note": "event_hash preimage MUST be RFC 8785 (JCS) canonical JSON over "
                    "the ordered field set, not a delimiter join. "
                    "hash = SHA-256(JCS bytes).",
            "event": event,
            "jcs_canonical": jcs,
            "event_hash_sha256": _sha(jcs.encode("utf-8")),
            "delimiter_collision": {
                "a": a, "b": b,
                "colon_join_a": colon(a), "colon_join_b": colon(b),
                "colon_join_collides": colon(a) == colon(b),
                "jcs_a": canonicalize(a), "jcs_b": canonicalize(b),
                "jcs_collides": canonicalize(a) == canonicalize(b),
            },
        },
        "tamper_detection": {
            "note": "Editing any past event MUST fail verification.",
            "valid_chain": c3, "tampered_chain": tampered,
            "expected": {"valid_verifies": True, "tampered_verifies": False},
        },
        "truncation": {
            "note": "A truncated prefix still link-verifies, so completeness MUST be "
                    "anchored to an expected length/head (T-4.1). Link-checking alone "
                    "MUST NOT accept it as complete.",
            "full_chain": c3, "truncated_prefix": c3[:-1],
            "expected_length": len(c3),
            "expected": {"prefix_links_valid": True, "prefix_accepted_as_complete": False},
        },
        "duplicate_vote": {
            "note": "Section 3.3: no duplicate votes. Three votes from one voter_id "
                    "MUST NOT meet threshold 3.",
            "request": {
                "action": "transfer_funds", "multi_agent": True, "threshold": 3,
                "votes": [
                    {"voter_id": "a", "request_id": "q", "decision": "Allow",
                     "outcome_hash": "h", "signature": "s"},
                    {"voter_id": "a", "request_id": "q", "decision": "Allow",
                     "outcome_hash": "h", "signature": "s"},
                    {"voter_id": "a", "request_id": "q", "decision": "Allow",
                     "outcome_hash": "h", "signature": "s"},
                ],
            },
            "expected": {"decision": "Deny",
                         "reason": "duplicate voter_id does not satisfy threshold"},
        },
    }


def _render(name: str, payload: dict) -> str:
    return json.dumps(payload, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate issue-#18 conformance vectors")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if the committed tree is stale")
    args = parser.parse_args(argv)

    out_dir = ROOT / "vectors" / "issue-18"
    out_dir.mkdir(parents=True, exist_ok=True)
    stale = []
    for name, payload in vectors().items():
        text = _render(name, payload)
        path = out_dir / f"{name}.json"
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.write_text(text, encoding="utf-8")
    if args.check and stale:
        print(f"stale vectors: {', '.join(stale)} (run scripts/gen_issue18_vectors.py)",
              file=sys.stderr)
        return 1
    print("issue-18 vectors " + ("are current" if args.check else "written"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
