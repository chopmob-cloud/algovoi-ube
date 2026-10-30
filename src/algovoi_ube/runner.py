"""Run NTI-1 conformance against a reference implementation.

Two modes:

  --self-test       check this harness against its own known-good fixtures,
                    including the published NTI-1 conformance chain, so a
                    failure means the harness is wrong, not the target.

  --target URL      probe a live implementation's decision endpoint.

The reference implementation of NTI-1 is ``ube-foundation``, which is published
under PolyForm Shield, not an open licence. This harness therefore talks to it
over HTTP or imports it if present, and never vendors its code.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .chain import verify_chain
from .conformance import Report, run_all
from .failclosed import Lifecycle, State, resolve


def _published_chain() -> list[dict]:
    """The conformance chain from the NTI-1 repository, if it is to hand."""
    # The vectors live at the repository root, two levels above this module.
    for candidate in (
        Path(__file__).resolve().parents[2] / "vectors" / "nti_published_audit_log.json",
    ):
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8"))
    return []


def _self_test_decide(request: dict) -> str:
    """A deliberately correct decision function, to prove the checks can pass."""
    if not request.get("signed") or not request.get("signature", ""):
        return "Deny"
    capability = request.get("capability") or {}
    now = request.get("now")
    if capability and now is not None and capability.get("expires", 0) < now:
        return "Deny"
    if request.get("multi_agent"):
        votes = request.get("votes") or []
        threshold = request.get("threshold", 1)
        unique = {v.get("voter_id") for v in votes}
        if len(unique) < threshold:
            return "Deny"
    return "Allow"


def _self_test_events() -> list[dict]:
    """A chain of exactly 100 events, built with the documented hash scheme."""
    from .chain import GENESIS, event_hash

    events: list[dict] = []
    parent = GENESIS
    for index in range(100):
        event = {
            "event_id": f"evt-{index:04d}",
            "agent_id": "agent-self-test",
            "request_hash": f"{index:064x}",
            "decision": "Allow" if index % 2 == 0 else "Deny",
            "reason": "self test",
            "timestamp": f"2026-10-29T00:00:{index % 60:02d}Z",
            "parent_hash": parent,
        }
        event["event_hash"] = event_hash(event)
        parent = event["event_hash"]
        events.append(event)
    return events


def _failing_resolver():
    """A status source that cannot answer, to prove fail-closed halting works."""

    def fetch():
        raise TimeoutError("simulated registry timeout")

    return resolve(fetch)


def _lifecycle_probe():
    """Walk the LGD machine and confirm the halt path lands in PAUSE."""
    lifecycle = Lifecycle()
    lifecycle.to(State.GATE_PASSED)
    lifecycle.to(State.ACTIVE)
    lifecycle.halt()
    return lifecycle


def self_test() -> int:
    print("=== harness self test ===")
    events = _self_test_events()
    reloaded = _self_test_events()
    from .resume import WIRE_VALUES, decide_resume

    report = run_all(
        decide=_self_test_decide,
        events=events,
        reload_events=lambda: reloaded,
        resolve_status=_failing_resolver,
        decide_resume=decide_resume,
        wire_values=WIRE_VALUES,
    )
    for check in report.checks:
        mark = "pass" if check.passed else "FAIL"
        print(f"  {check.ident:7s} {mark:5s} {check.description}")
        if check.detail:
            print(f"          {check.detail}")
    print(f"\n  {report.summary()}")

    published = _published_chain()
    if published:
        status = verify_chain(published)
        print(f"\n  published NTI-1 conformance chain: {status.summary()}")

    lifecycle = _lifecycle_probe()
    ok = lifecycle.state is State.PAUSE
    print(f"  LGD halt path: {'pass' if ok else 'FAIL'} "
          f"({' -> '.join(s.value for s in lifecycle.history)})")

    # The resume edge, and the two exemption boundaries.
    from .failclosed import IllegalTransition, LEGAL

    edge_declared = State.RESUMED in LEGAL.get(State.REVERIFY, set())
    print(f"  REVERIFY -> RESUMED declared in the table: "
          f"{'pass' if edge_declared else 'FAIL'}")

    probe = _lifecycle_probe()
    withdrawn = False
    try:
        probe.resume(revocation_irreversible=True)
    except IllegalTransition:
        withdrawn = probe.state is State.REVERIFY
    print(f"  irreversible revocation withdraws the edge: "
          f"{'pass' if withdrawn else 'FAIL'}")

    return 0 if report.passed and ok and edge_declared and withdrawn else 1


def probe_target(base_url: str, timeout: int = 20) -> int:
    """Probe a live implementation that exposes a JSON decision endpoint."""
    url = base_url.rstrip("/") + "/decide"
    print(f"=== probing {url} ===")

    def decide(request: dict) -> str:
        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return str(payload.get("decision") or payload.get("verdict") or "")

    report = Report()
    try:
        run_all(decide=decide, events=None)
    except urllib.error.URLError as exc:
        print(f"  target unreachable: {exc}")
        return 2

    for check in report.checks:
        mark = "pass" if check.passed else "FAIL"
        print(f"  {check.ident:7s} {mark:5s} {check.detail}")
    print(f"\n  {report.summary()}")
    return 0 if report.passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NTI-1 conformance runner")
    parser.add_argument("--self-test", action="store_true", help="verify the harness itself")
    parser.add_argument("--target", default="", help="base URL of a live implementation")
    args = parser.parse_args(argv)

    if args.self_test or not args.target:
        return self_test()
    return probe_target(args.target)


if __name__ == "__main__":
    sys.exit(main())
