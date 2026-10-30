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
    from .voc import AgentGrader, HmacSigner, evaluate as voc_evaluate, resume_on_exemption

    voc_signer = HmacSigner(b"harness-self-test-key", key_id="self-test")
    from .mandate import GraderMandate, MandateRegistry, sign_mandate

    issuer_signer = HmacSigner(b"harness-issuer-key", key_id="issuer-self-test")
    self_mandate = GraderMandate(
        mandate_id="m-self-test",
        issuer_id="principal-self-test",
        issuer_role="risk-committee",
        grader_id="grader-self-test",
        issued_at="2026-10-30T09:00:00Z",
        not_after="2026-12-31T00:00:00Z",
        policies=("pol-value-limit",),
        principals=("principal-self-test",),
        max_value=10000,
        max_exemptions=50,
    )
    self_mandate_payload = sign_mandate(self_mandate, issuer_signer)
    self_mandate_registry = MandateRegistry()
    self_mandate_registry.register(self_mandate_payload)

    voc_grader = AgentGrader(
        grader_id="grader-self-test",
        grader_role="compliance-officer",
        signer=voc_signer,
        mandate=self_mandate,
        mandate_payload=self_mandate_payload,
        mandate_registry=self_mandate_registry,
    )

    def make_receipt() -> dict:
        return voc_grader.sign_exemption(
            receipt_id="r-self-test",
            issued_at="2026-10-30T16:00:00Z",
            request_id="req-self-test",
            policy_id="pol-value-limit",
            halt_cause="policy_violation",
            reason="self test exemption",
            delegation_id="d-self-test",
            principal_id="principal-self-test",
            valid_until="2026-10-30T18:00:00Z",
            value=100,
        )

    def voc_resume(*, outcome, receipt):
        return resume_on_exemption(outcome=outcome, receipt=receipt, signer=voc_signer)

    # The boundary this harness declares for itself. It has to be the posture
    # NTI permits, and T-9.1 checks it rather than trusting this comment.
    from .boundary import Boundary

    boundary_value = Boundary.SUB_CALL.value

    # The signature scheme, and a real signature length measured rather than
    # assumed. If the mandated core is not built, the check reports that rather
    # than passing on a placeholder.
    signature_algorithm = "HMAC-SHA256"
    signature_bytes = 32
    probe_registry = None
    try:
        from .pqsign import SIGNATURE_BYTES, Dilithium5Signer

        with Dilithium5Signer() as probe:
            signature_algorithm = probe.algorithm
            signed = probe.sign_digest(b"self test payload")
            signature_bytes = len(signed.split(":", 1)[1]) // 2 if ":" in signed else len(signed) // 2
            assert signature_bytes == SIGNATURE_BYTES
    except Exception as exc:  # noqa: BLE001
        print(f"  ML-DSA core: unavailable ({exc.__class__.__name__}), T-9.2 will fail")

    try:
        from .registry import MerkleRevocationRegistry

        probe_registry = MerkleRevocationRegistry()
    except Exception as exc:  # noqa: BLE001
        print(f"  registry: unavailable ({exc.__class__.__name__})")

    report = run_all(
        decide=_self_test_decide,
        events=events,
        reload_events=lambda: reloaded,
        resolve_status=_failing_resolver,
        decide_resume=decide_resume,
        wire_values=WIRE_VALUES,
        voc_evaluate=voc_evaluate,
        voc_resume=voc_resume,
        voc_receipt=make_receipt,
        boundary_declared=boundary_value,
        signature_algorithm=signature_algorithm,
        signature_bytes=signature_bytes,
        registry=probe_registry,
        grader_factory=lambda: AgentGrader(
            grader_id="grader-bare",
            grader_role="compliance-officer",
            signer=HmacSigner(b"bare-key", key_id="bare"),
        ),
        grader=voc_grader,
        grader_mandate=self_mandate,
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
