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
            valid_from="2026-10-30T09:00:00Z",
            valid_until="2026-10-30T17:00:00Z",
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
    assert life.state is State.REVERIFY
    assert "unavailable" in str(excinfo.value)
    # No terminal REVOKED state was invented to express it.
    assert not hasattr(State, "REVOKED")


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
            valid_until="2026-10-30T17:00:00Z",
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
            valid_until="2026-10-30T17:00:00Z",
        ),
    )
    life = paused_lifecycle()
    with pytest.raises(IllegalTransition):
        life.resume(revoked)
    assert life.state is State.REVERIFY


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
