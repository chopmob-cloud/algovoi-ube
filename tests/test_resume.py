"""Tests for the resume basis proposal raised on the AIW thread.

Each test names the claim it pins. The two that matter most are the ones that
would have passed silently before: a resume with no basis, and a resume after a
revocation. Both used to reach RESUMED because the edge was performed by a
direct assignment rather than declared in the transition table.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.failclosed import (  # noqa: E402
    LEGAL,
    IllegalTransition,
    Lifecycle,
    State,
)
from algovoi_ube.resume import (  # noqa: E402
    BASES,
    EXEMPTION_COVERS,
    EXEMPTION_DOES_NOT_COVER,
    WIRE_VALUES,
    Basis,
    RestoreEvidence,
    ResumeBasis,
    ResumeRefused,
    decide_resume,
    wire_value_of,
)


def paused_lifecycle() -> Lifecycle:
    life = Lifecycle()
    for state in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE):
        life.to(state)
    return life


def evidence_basis() -> ResumeBasis:
    return ResumeBasis(
        basis=Basis.EVIDENCE.value,
        covers="policy_violation",
        evidence=RestoreEvidence(
            conditions=["registry reports the policy as satisfied"],
            verifier_role="compliance-officer",
            valid_from="2020-01-01T00:00:00Z",
            valid_until="2099-12-31T00:00:00Z",
        ),
    )


def exemption_basis(covers: str = "policy_violation") -> ResumeBasis:
    return ResumeBasis(
        basis=Basis.EXEMPTION.value,
        covers=covers,
        exemption_reason="business critical release window",
        exemption_actor="manager@example.com",
    )


# ---- the edge that was missing -------------------------------------------


def test_reverify_to_resumed_is_declared_in_the_table():
    """The edge has to be a declared transition, not an assignment in a method."""
    assert State.RESUMED in LEGAL[State.REVERIFY]


def test_the_declared_edge_is_the_only_route_to_resumed():
    life = Lifecycle()
    for state in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE,
                  State.ROLLBACK, State.REVERIFY):
        life.to(state)
    assert life.state is State.REVERIFY
    # Going straight from REVERIFY is legal, but nothing skips into RESUMED from
    # an earlier state.
    for earlier in (State.ACTIVE, State.ANOMALY, State.PAUSE, State.ROLLBACK):
        probe = Lifecycle()
        probe.state = earlier
        with pytest.raises(IllegalTransition):
            probe.to(State.RESUMED)


def test_a_lifecycle_resume_with_no_basis_is_refused():
    """The third instance of the same fail-open, found by the scanner.

    ``Lifecycle.resume`` enforced the basis only when one was supplied, so
    calling the lifecycle directly with no basis walked PAUSE to RESUMED having
    established nothing about why the halt was lifted. That contradicted the F8
    claim that a resume must carry a complete basis.
    """
    life = paused_lifecycle()
    with pytest.raises(IllegalTransition) as excinfo:
        life.resume()
    assert "basis" in str(excinfo.value)
    assert life.state is not State.RESUMED


def test_irreversible_revocation_withdraws_the_edge_without_a_new_state():
    """The claim from message 0107 section 6, tested."""
    life = paused_lifecycle()
    with pytest.raises(IllegalTransition) as excinfo:
        life.resume(evidence_basis(), revocation_irreversible=True)
    # A refusal must leave no trace in the machine. It used to advance to
    # REVERIFY and then refuse, which left the object one table-legal transition
    # from the state it had just refused.
    assert life.state is State.PAUSE
    assert "unavailable" in str(excinfo.value)
    # No terminal REVOKED state was invented to express it.
    assert not hasattr(State, "REVOKED")


def test_the_table_is_not_a_second_route_to_resumed():
    """R1: walking the declared edge directly must be refused.

    The edge is declared so a governing regime can withdraw it, and enumerable so
    a conformance suite can see it. It is not a public transition: reaching
    RESUMED without a recorded basis is the fail-open, and guarding only
    resume() left the table as an unguarded parallel route to it.
    """
    life = paused_lifecycle()
    life.to(State.ROLLBACK)
    life.to(State.REVERIFY)
    with pytest.raises(IllegalTransition) as excinfo:
        life.to(State.RESUMED)
    assert "only through resume()" in str(excinfo.value)
    assert life.state is State.REVERIFY
    assert life.receipt == {}


def test_an_irreversible_refusal_cannot_be_completed_by_a_later_transition():
    """R2: the refusal used to park the chain one legal step from RESUMED."""
    life = paused_lifecycle()
    with pytest.raises(IllegalTransition):
        life.resume(evidence_basis(), revocation_irreversible=True)
    assert life.state is State.PAUSE
    # PAUSE has no path to RESUMED, directly or through the table.
    with pytest.raises(IllegalTransition):
        life.to(State.RESUMED)


def test_an_exemption_basis_must_record_a_reason_and_an_actor():
    """R3: an exemption with no substance is a basis that says nothing.

    JustificationReceipt in voc.py already requires a reason and an actor. The
    lifecycle accepting a weaker exemption than the receipt representation is the
    same disagreement that let an empty evidence basis through.
    """
    with pytest.raises(ResumeRefused):
        ResumeBasis(basis=Basis.EXEMPTION.value, covers="policy_violation")
    with pytest.raises(ResumeRefused):
        ResumeBasis(
            basis=Basis.EXEMPTION.value,
            covers="policy_violation",
            exemption_reason="business critical release window",
        )
    with pytest.raises(ResumeRefused):
        ResumeBasis(
            basis=Basis.EXEMPTION.value,
            covers="policy_violation",
            exemption_actor="manager@example.com",
        )
    # A complete exemption still works.
    assert exemption_basis().exemption_actor == "manager@example.com"


def test_resume_consults_the_table_rather_than_assigning_the_state(monkeypatch):
    """Withdraw the edge from the table and resume must refuse, not assign.

    This is the behavioural half of the structural test above. An implementation
    that reaches RESUMED by writing the attribute passes the structural check by
    declaring the edge and then ignores it, which is exactly the defect this
    repository had before the edge was moved into the table.
    """
    import algovoi_ube.failclosed as fc

    withdrawn = {k: set(v) for k, v in fc.LEGAL.items()}
    withdrawn[fc.State.REVERIFY] = set()
    monkeypatch.setattr(fc, "LEGAL", withdrawn)

    life = paused_lifecycle()
    with pytest.raises(IllegalTransition):
        life.resume(evidence_basis())
    assert life.state is fc.State.REVERIFY, (
        "resume reached RESUMED despite the edge being withdrawn, so it assigned "
        "the state instead of consulting the table"
    )


# ---- the basis -----------------------------------------------------------


def test_basis_is_a_closed_set():
    assert BASES == ("evidence", "exemption")
    with pytest.raises(ValueError):
        ResumeBasis(basis="because I said so")


def test_exemption_does_not_cover_revocation():
    assert "authority_revoked" in EXEMPTION_DOES_NOT_COVER
    with pytest.raises(ResumeRefused) as excinfo:
        exemption_basis("authority_revoked")
    assert "un-revoke" in str(excinfo.value) or "issuing authority" in str(excinfo.value)


def test_exemption_does_not_cover_undetermined_authority():
    assert "authority_not_determined" in EXEMPTION_DOES_NOT_COVER
    with pytest.raises(ResumeRefused) as excinfo:
        exemption_basis("authority_not_determined")
    assert "we do not know" in str(excinfo.value)


def test_exemption_covers_a_policy_violation():
    assert EXEMPTION_COVERS == ("policy_violation",)
    decision = decide_resume(signature_valid=True, basis=exemption_basis())
    assert decision.allowed
    assert decision.wire_value == "resume"
    assert decision.receipt["exemption"]["reason"] == "business critical release window"


def test_a_signature_alone_is_not_a_basis():
    """The fail open case: valid signature, nothing else. Must not resume."""
    decision = decide_resume(signature_valid=True, basis=None)
    assert decision.allowed is False
    assert decision.wire_value == "pause"
    assert "not a resume basis" in decision.reason


def test_evidence_basis_resumes():
    decision = decide_resume(signature_valid=True, basis=evidence_basis())
    assert decision.allowed
    assert decision.wire_value == "resume"
    assert "verified in full" in decision.reason


def test_evidence_basis_needs_a_real_restore_condition():
    with pytest.raises(ValueError) as excinfo:
        ResumeBasis(
            basis=Basis.EVIDENCE.value,
            evidence=RestoreEvidence(conditions=[], verifier_role="someone"),
        )
    assert "restore condition" in str(excinfo.value)


def test_evidence_basis_with_no_evidence_object_is_refused():
    """The fail-open the completeness check used to skip.

    An evidence basis asserts the restore condition was verified in full. A basis
    of "evidence" carrying no evidence object at all once constructed cleanly and
    then reached RESUMED on the signature alone, with the reason "the restore
    condition was verified in full" while nothing had been verified. That is the
    exact signature-only resume the basis field exists to refuse, so it is now
    rejected at construction rather than quietly allowed at use.
    """
    with pytest.raises(ValueError) as excinfo:
        ResumeBasis(basis=Basis.EVIDENCE.value)
    assert "restore condition" in str(excinfo.value)


def test_an_empty_evidence_basis_never_reaches_resumed():
    """The decision layer must never see an empty evidence basis as a resume.

    Construction is where it is refused now, so an empty evidence basis cannot be
    handed to decide_resume at all. Pinning the behaviour from the caller's side
    guards against the check being loosened again.
    """
    with pytest.raises(ValueError):
        ResumeBasis(basis=Basis.EVIDENCE.value)


def test_a_revoked_delegation_is_declined_even_with_a_valid_signature():
    """The worked example from the note to public-agentprotocol."""
    basis = ResumeBasis(
        basis=Basis.EVIDENCE.value,
        delegation_id="d-42",
        state_at_resume="REVOKED",
        evidence=RestoreEvidence(
            conditions=["condition was restored"],
            verifier_role="compliance-officer",
            valid_until="2099-12-31T00:00:00Z",
        ),
    )
    decision = decide_resume(signature_valid=True, basis=basis)
    assert decision.allowed is False
    assert decision.wire_value == "revoked"
    assert decision.receipt["basis_detail"]["delegation_id"] == "d-42"


def test_the_lifecycle_refuses_a_resume_with_a_forbidden_basis():
    """Two layers, and the first one is the constructor.

    A basis that exempts a revocation cannot be built at all, so the lifecycle is
    never handed one. The second layer still has to hold, so a basis whose
    delegation has gone is refused at the point of resume.
    """
    with pytest.raises(ResumeRefused):
        exemption_basis("authority_revoked")

    revoked = ResumeBasis(
        basis=Basis.EVIDENCE.value,
        delegation_id="d-42",
        state_at_resume="REVOKED",
        evidence=RestoreEvidence(
            conditions=["condition was restored"],
            verifier_role="compliance-officer",
            valid_until="2099-12-31T00:00:00Z",
        ),
    )
    life = paused_lifecycle()
    with pytest.raises(IllegalTransition):
        life.resume(revoked)
    assert life.state is State.PAUSE


def test_the_receivers_knowledge_outranks_the_basis_claim():
    """A document asserting its own delegation is fine is not evidence.

    The precedence used to be ``basis.state_at_resume or delegation_state``, so a
    basis claiming ACTIVE resumed into a delegation the receiver knew was
    REVOKED. The receiver's value now wins, and a contradiction is refused rather
    than resolved in the sender's favour.
    """
    claiming_active = ResumeBasis(
        basis=Basis.EXEMPTION.value,
        covers="policy_violation",
        exemption_reason="release window",
        exemption_actor="manager@example.com",
        delegation_id="d-42",
        state_at_resume="ACTIVE",
    )
    decision = decide_resume(
        signature_valid=True, basis=claiming_active, delegation_state="REVOKED"
    )
    assert decision.allowed is False
    assert "contradicts the verifier" in decision.reason

    # With nothing claimed, the receiver's own knowledge still refuses.
    silent = ResumeBasis(
        basis=Basis.EXEMPTION.value,
        covers="policy_violation",
        exemption_reason="release window",
        exemption_actor="manager@example.com",
        delegation_id="d-42",
    )
    assert decide_resume(
        signature_valid=True, basis=silent, delegation_state="REVOKED"
    ).allowed is False

    # And the claim alone, with no receiver knowledge, is still read.
    assert decide_resume(
        signature_valid=True, basis=claiming_active, delegation_state="ACTIVE"
    ).allowed is True


def test_an_expired_restore_window_is_refused():
    """valid_until was required and never compared to a clock."""
    from datetime import datetime, timezone

    stale = ResumeBasis(basis=Basis.EVIDENCE.value, evidence=RestoreEvidence(
        conditions=["condition restored"], verifier_role="officer",
        valid_from="2020-01-01T00:00:00Z", valid_until="2020-01-02T00:00:00Z"))
    decision = decide_resume(
        signature_valid=True, basis=stale,
        now=datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc),
    )
    assert decision.allowed is False
    assert "ended at" in decision.reason


def test_a_restore_window_that_has_not_begun_is_refused():
    from datetime import datetime, timezone

    early = ResumeBasis(basis=Basis.EVIDENCE.value, evidence=RestoreEvidence(
        conditions=["condition restored"], verifier_role="officer",
        valid_from="2099-01-01T00:00:00Z", valid_until="2099-12-31T00:00:00Z"))
    decision = decide_resume(
        signature_valid=True, basis=early,
        now=datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc),
    )
    assert decision.allowed is False
    assert "does not begin until" in decision.reason


def test_an_unreadable_restore_window_is_refused():
    from datetime import datetime, timezone

    broken = ResumeBasis(basis=Basis.EVIDENCE.value, evidence=RestoreEvidence(
        conditions=["condition restored"], verifier_role="officer",
        valid_until="not-a-timestamp"))
    decision = decide_resume(
        signature_valid=True, basis=broken,
        now=datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc),
    )
    assert decision.allowed is False
    assert "cannot be read" in decision.reason


def test_a_window_containing_the_clock_still_resumes():
    from datetime import datetime, timezone

    decision = decide_resume(
        signature_valid=True, basis=evidence_basis(),
        now=datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc),
    )
    assert decision.allowed is True


def test_the_lifecycle_records_the_basis_on_a_legal_resume():
    life = paused_lifecycle()
    life.resume(evidence_basis())
    assert life.state is State.RESUMED
    assert life.receipt["resume_basis"] == "evidence"


# ---- the one directional mapping ----------------------------------------


def test_wire_values_stay_closed():
    assert len(WIRE_VALUES) == 5


def test_a_pause_is_well_formed_without_a_receipt():
    """The refusal is complete on its own; the wire value may not need the receipt."""
    decision = decide_resume(signature_valid=True, basis=None)
    with_receipt = wire_value_of(decision, with_receipt=True)
    without_receipt = wire_value_of(decision, with_receipt=False)
    assert with_receipt == without_receipt == "pause"
    assert with_receipt in WIRE_VALUES


def test_a_receipt_may_name_the_wire_value_it_maps_onto():
    """One directional: the receipt can name the wire value, not the reverse."""
    decision = decide_resume(signature_valid=True, basis=None)
    assert decision.wire_value == "pause"
    # The receipt is optional, and its absence does not change the decision.
    assert "receipt" in decision.as_dict()
    assert decision.allowed is False
