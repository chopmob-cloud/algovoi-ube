"""Tests for the NTI-1 conformance harness.

These test the harness, not NTI-1. Where a test uses the published conformance
chain it is checking that we recompute what the standard's own authors stored.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.boundary import Boundary, judge  # noqa: E402
from algovoi_ube.chain import (  # noqa: E402
    GENESIS,
    event_hash,
    request_hash,
    verify_chain,
)
from algovoi_ube.resume import Basis, RestoreEvidence, ResumeBasis  # noqa: E402
from algovoi_ube.conformance import run_all  # noqa: E402
from algovoi_ube.failclosed import (  # noqa: E402
    REASONS,
    IllegalTransition,
    IncompleteCheck,
    Lifecycle,
    State,
    resolve,
)

VECTORS = ROOT / "vectors"


# ---- chain ---------------------------------------------------------------


def test_published_chain_recomputes_exactly():
    """The NTI-1 authors' own conformance chain must verify under our formula."""
    events = json.loads((VECTORS / "nti_published_audit_log.json").read_text(encoding="utf-8"))
    status = verify_chain(events)
    assert status.ok, status.summary()
    assert status.length == 2


def test_published_event_hash_is_the_documented_colon_join():
    events = json.loads((VECTORS / "nti_published_audit_log.json").read_text(encoding="utf-8"))
    first = events[0]
    assert event_hash(first) == first["event_hash"]


def test_tampering_any_field_breaks_the_chain():
    events = json.loads((VECTORS / "nti_published_audit_log.json").read_text(encoding="utf-8"))
    for field in ("decision", "reason", "timestamp", "agent_id"):
        tampered = [dict(e) for e in events]
        tampered[0][field] = "tampered"
        assert not verify_chain(tampered).ok, f"tampering {field} went undetected"


def test_broken_parent_link_is_detected():
    events = json.loads((VECTORS / "nti_published_audit_log.json").read_text(encoding="utf-8"))
    events[1]["parent_hash"] = GENESIS  # no longer points at event 1
    events[1]["event_hash"] = event_hash(events[1])
    status = verify_chain(events)
    assert not status.ok
    assert "does not link" in " ".join(status.reasons)


def test_empty_request_hash_is_not_silently_accepted():
    """The published example hashes an empty string; ours must not."""
    assert request_hash({"action": "x"}) != request_hash({})
    assert request_hash("") != request_hash({})


# ---- fail closed ---------------------------------------------------------


def test_timeout_resolves_to_a_halt():
    def fetch():
        raise TimeoutError("registry down")

    result = resolve(fetch)
    assert result.halted
    assert "tryLater" in result.reason


def test_any_exception_halts_rather_than_passing():
    def fetch():
        raise ValueError("unexpected")

    result = resolve(fetch)
    assert result.halted
    assert "internal_error" in result.reason


def test_non_authoritative_source_halts():
    result = resolve(lambda: {"authoritative": False, "status": "active"})
    assert result.halted
    assert "not_authoritative" in result.reason


def test_empty_status_halts():
    result = resolve(lambda: {"status": ""})
    assert result.halted


def test_a_good_source_passes():
    result = resolve(lambda: {"authoritative": True, "status": "active"})
    assert not result.halted


def test_incomplete_check_rejects_an_unclassified_reason():
    with pytest.raises(ValueError):
        IncompleteCheck(reason="whoops")
    for reason in REASONS:
        assert IncompleteCheck(reason=reason).as_dict()["reason"] == reason


def test_incomplete_check_carries_the_three_observed_times():
    receipt = IncompleteCheck(
        reason="tryLater",
        observed_at="2026-10-29T18:00:00Z",
        t_observed="2026-10-29T18:00:00Z",
        t_effective="2026-10-29T17:59:59Z",
        registry_version="v42",
    ).as_dict()
    assert receipt["t_observed"] and receipt["t_effective"]
    assert receipt["registry_version"] == "v42"


# ---- lifecycle -----------------------------------------------------------


def test_halt_from_active_reaches_pause():
    life = Lifecycle()
    life.to(State.GATE_PASSED)
    life.to(State.ACTIVE)
    assert life.halt() is State.PAUSE
    assert life.history[-3:] == [State.ANOMALY, State.PAUSE][-3:] or State.PAUSE in life.history


def test_illegal_transition_is_refused():
    life = Lifecycle()
    with pytest.raises(IllegalTransition):
        life.to(State.ACTIVE)  # must pass through GATE_PASSED


def test_resume_walks_the_documented_path():
    life = Lifecycle()
    life.to(State.GATE_PASSED)
    life.to(State.ACTIVE)
    life.halt()
    life.resume(
        ResumeBasis(
            basis=Basis.EVIDENCE.value,
            evidence=RestoreEvidence(
                conditions=["registry reports the policy as satisfied"],
                verifier_role="compliance-officer",
                valid_until="2099-12-31T00:00:00Z",
            ),
        )
    )
    assert life.state is State.RESUMED
    assert State.ROLLBACK in life.history
    assert State.REVERIFY in life.history


# ---- boundary (Alan Karp's question) -------------------------------------


def test_invocation_boundary_does_not_interrupt():
    decision = judge(
        Boundary.INVOCATION,
        status_at_start="active",
        status_at_effect="revoked",
        status_at_end="revoked",
        in_flight=True,
    )
    assert decision.allowed is True
    assert decision.interrupted is False


def test_effect_boundary_halts_mid_execution():
    decision = judge(
        Boundary.EFFECT,
        status_at_start="active",
        status_at_effect="revoked",
        status_at_end="revoked",
        in_flight=True,
    )
    assert decision.allowed is False
    assert decision.interrupted is True


def test_completion_boundary_judges_at_the_end():
    decision = judge(
        Boundary.COMPLETION,
        status_at_start="active",
        status_at_effect="active",
        status_at_end="revoked",
    )
    assert decision.allowed is False


def test_a_revoked_start_denies_under_every_boundary():
    for boundary in Boundary:
        decision = judge(
            boundary,
            status_at_start="revoked",
            status_at_effect="revoked",
            status_at_end="revoked",
        )
        assert decision.allowed is False, boundary


# ---- conformance runner --------------------------------------------------


def good_decide(request: dict) -> str:
    if not request.get("signed"):
        return "Deny"
    capability = request.get("capability") or {}
    if capability and capability.get("expires", 0) < request.get("now", 0):
        return "Deny"
    if request.get("multi_agent"):
        votes = {v.get("voter_id") for v in request.get("votes") or []}
        if len(votes) < request.get("threshold", 1):
            return "Deny"
    return "Allow"


def bad_decide(request: dict) -> str:
    return "Allow"


def test_a_correct_implementation_passes_the_decision_checks():
    report = run_all(decide=good_decide)
    assert report.passed, report.summary()


def test_a_permissive_implementation_fails_them():
    report = run_all(decide=bad_decide)
    assert not report.passed
    assert {c.ident for c in report.failures} == {"T-1.1", "T-2.1", "T-3.1"}


def test_a_hundred_event_chain_passes_audit():
    from algovoi_ube.chain import event_hash as eh

    events, parent = [], GENESIS
    for i in range(100):
        ev = {
            "event_id": f"e{i}",
            "agent_id": "a",
            "request_hash": f"{i:064x}",
            "decision": "Allow",
            "reason": "test",
            "timestamp": "2026-10-29T00:00:00Z",
            "parent_hash": parent,
        }
        ev["event_hash"] = eh(ev)
        parent = ev["event_hash"]
        events.append(ev)

    report = run_all(events=events, reload_events=lambda: events)
    assert report.passed, report.summary()


def test_a_short_chain_fails_audit():
    report = run_all(events=[])
    assert not report.passed
    assert any(c.ident == "T-4.1" for c in report.failures)


# ---- the resume checks ---------------------------------------------------


def test_a_correct_resume_implementation_passes_the_new_checks():
    from algovoi_ube.resume import WIRE_VALUES, decide_resume

    report = run_all(decide_resume=decide_resume, wire_values=WIRE_VALUES)
    assert report.passed, report.summary()
    assert {c.ident for c in report.checks} == {
        "T-7.1", "T-7.2", "T-7.3", "T-7.4", "T-7.5", "T-7.6", "T-7.7",
        "T-7.8", "T-7.9", "T-7.10", "T-7.11",
    }


def test_a_permissive_resume_implementation_fails_them():
    """An implementation that resumes on a signature alone must be caught."""

    class Permissive:
        allowed = True
        wire_value = "resume"
        reason = "signature verified"

        def as_dict(self):
            return {}

    def decide_resume(**kwargs):
        return Permissive()

    report = run_all(decide_resume=decide_resume, wire_values=("allow", "deny", "pause", "resume", "revoked"))
    assert not report.passed
    assert "T-7.1" in {c.ident for c in report.failures}


# ---- the VOC checks ------------------------------------------------------


def test_a_correct_voc_implementation_passes():
    from algovoi_ube.mandate import GraderMandate, sign_mandate
    from algovoi_ube.voc import AgentGrader, HmacSigner, evaluate, resume_on_exemption

    signer = HmacSigner(b"k", key_id="k1")
    issuer = HmacSigner(b"issuer", key_id="issuer-1")
    mandate = GraderMandate(
        mandate_id="m-1", issuer_id="principal-1", issuer_role="risk-committee",
        grader_id="g", issued_at="2026-10-30T09:00:00Z",
        not_after="2026-12-31T00:00:00Z", policies=("p",),
        principals=("p1",), max_exemptions=10,
    )
    grader = AgentGrader(
        grader_id="g", grader_role="officer", signer=signer,
        mandate=mandate, mandate_payload=sign_mandate(mandate, issuer),
    )

    def receipt():
        return grader.sign_exemption(
            receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
            policy_id="p", halt_cause="policy_violation", reason="r",
            delegation_id="d", principal_id="p1", valid_until="2026-10-30T18:00:00Z",
        )

    report = run_all(
        voc_evaluate=evaluate,
        voc_resume=lambda *, outcome, receipt: resume_on_exemption(
            outcome=outcome, receipt=receipt, signer=signer
        ),
        voc_receipt=receipt,
    )
    assert report.passed, report.summary()
    assert {c.ident for c in report.checks} == {"T-8.1", "T-8.2", "T-8.3", "T-8.4"}


def test_a_rubber_stamp_voc_implementation_fails():
    """VOC that always allows, and resumes on any receipt, must be caught."""

    class RubberStamp:
        wire_value = "allow"
        paused = False
        receipt = None

    def evaluate(**kwargs):
        return RubberStamp()

    def resume(**kwargs):
        return RubberStamp()

    report = run_all(
        voc_evaluate=evaluate,
        voc_resume=resume,
        voc_receipt=lambda: {"justification": {"reason": "x"}},
    )
    assert not report.passed
    failed = {c.ident for c in report.failures}
    assert {"T-8.1", "T-8.2", "T-8.3", "T-8.4"} <= failed, failed
