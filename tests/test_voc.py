"""Tests for Voluntary Oblivious Compliance and the automated agent grader.

Each test names the rule from issue 21 that it pins. The two that matter most are
that a revocation cannot be exempted and that a tampered receipt does not resume
anything, because those are the two ways this design could quietly become a
rubber stamp.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.canonical import canonicalize  # noqa: E402
from algovoi_ube.mandate import (  # noqa: E402
    GraderMandate,
    MandateRefused,
    MandateRegistry,
    sign_mandate,
    verify_mandate,
)
from algovoi_ube.voc import (  # noqa: E402
    EXEMPTION_COVERS,
    EXEMPTION_DOES_NOT_COVER,
    AgentGrader,
    ComplianceMode,
    Decision,
    GraderRefused,
    HmacSigner,
    JustificationReceipt,
    ReceiptRefused,
    evaluate,
    resume_on_exemption,
    verify_receipt,
)

SCHEMA = json.loads(
    (ROOT / "schemas" / "justification_receipt.schema.json").read_text(encoding="utf-8")
)

ISSUER_SIGNER = HmacSigner(b"issuer-key-not-a-secret", key_id="issuer-1")


def a_mandate(**overrides) -> GraderMandate:
    fields = dict(
        mandate_id="m-1",
        issuer_id="principal-acme",
        issuer_role="risk-committee",
        grader_id="grader-1",
        issued_at="2026-10-30T09:00:00Z",
        not_after="2026-12-31T00:00:00Z",
        policies=("pol-value-limit",),
        principals=("principal-acme",),
        max_value=10000,
        max_exemptions=50,
    )
    fields.update(overrides)
    return GraderMandate(**fields)


def signer() -> HmacSigner:
    return HmacSigner(b"test-key-not-a-secret", key_id="k1")


def grader(**kwargs) -> AgentGrader:
    mandate = kwargs.pop("mandate", a_mandate())
    payload = kwargs.pop("mandate_payload", sign_mandate(mandate, ISSUER_SIGNER))
    return AgentGrader(
        grader_id="grader-1",
        grader_role="compliance-officer",
        signer=signer(),
        mandate=mandate,
        mandate_payload=payload,
        **kwargs,
    )


def signed_receipt(g=None) -> dict:
    g = g or grader()
    return g.sign_exemption(
        receipt_id="r-1",
        issued_at="2026-10-30T16:00:00Z",
        request_id="req-42",
        policy_id="pol-value-limit",
        halt_cause="policy_violation",
        reason="release window, value limit accepted by on-call manager",
        delegation_id="d-42",
        principal_id="principal-acme",
        valid_until="2026-10-30T18:00:00Z",
        evidence_refs=["ticket-991"],
        chain_event_hash="a" * 64,
        value=500,
    )


# ---- the flow ------------------------------------------------------------


def test_strict_fails_closed_on_a_violation():
    outcome = evaluate(mode="STRICT", policy_allows=False)
    assert outcome.decision is Decision.DENY
    assert outcome.wire_value == "deny"
    assert outcome.paused is False
    assert outcome.receipt is None


def test_voc_pauses_and_requests_an_exemption():
    outcome = evaluate(mode="VOC", policy_allows=False)
    assert outcome.decision is Decision.PAUSE
    assert outcome.wire_value == "pause"
    assert outcome.paused is True


def test_an_allowed_action_needs_no_exemption_in_either_mode():
    for mode in ComplianceMode:
        outcome = evaluate(mode=mode, policy_allows=True)
        assert outcome.decision is Decision.ALLOW, mode


def test_an_unknown_compliance_mode_is_refused():
    with pytest.raises(ReceiptRefused):
        evaluate(mode="SOMETIMES", policy_allows=False)


def test_a_revocation_halts_in_both_modes():
    """VOC is an exception path for policy, not a bypass for revocation."""
    for mode in ComplianceMode:
        outcome = evaluate(
            mode=mode, policy_allows=False, halt_cause="authority_revoked"
        )
        assert outcome.decision in {Decision.DENY, Decision.PAUSE}, mode
        assert outcome.decision is not Decision.ALLOW
        assert outcome.decision is not Decision.RESUME


def test_an_undetermined_authority_halts_in_both_modes():
    for mode in ComplianceMode:
        outcome = evaluate(
            mode=mode, policy_allows=False, halt_cause="authority_not_determined"
        )
        assert outcome.decision is not Decision.ALLOW
        assert outcome.decision is not Decision.RESUME


# ---- the boundaries ------------------------------------------------------


def test_exemption_covers_exactly_one_cause():
    assert EXEMPTION_COVERS == ("policy_violation",)
    assert set(EXEMPTION_DOES_NOT_COVER) == {
        "authority_revoked",
        "authority_not_determined",
    }


@pytest.mark.parametrize("cause", ["authority_revoked", "authority_not_determined"])
def test_a_receipt_exempting_revocation_cannot_be_built(cause):
    with pytest.raises(ReceiptRefused) as excinfo:
        JustificationReceipt(
            receipt_id="r-2",
            issued_at="2026-10-30T16:00:00Z",
            request_id="req-1",
            policy_id="pol-1",
            halt_cause=cause,
            reason="please",
            grader_id="g",
            grader_role="r",
            delegation_id="d",
            principal_id="p",
        )
    assert cause in str(excinfo.value)


@pytest.mark.parametrize("cause", ["authority_revoked", "authority_not_determined"])
def test_the_grader_will_not_sign_those(cause):
    g = grader()
    with pytest.raises(GraderRefused):
        g.sign_exemption(
            receipt_id="r-3",
            issued_at="2026-10-30T16:00:00Z",
            request_id="req-1",
            policy_id="pol-1",
            halt_cause=cause,
            reason="please",
            delegation_id="d",
            principal_id="p",
        )
    assert g.signed_count == 0
    assert g.log[-1]["signed"] is False


def test_a_receipt_needs_a_reason_and_an_identity():
    with pytest.raises(ReceiptRefused):
        JustificationReceipt(
            receipt_id="r-4",
            issued_at="2026-10-30T16:00:00Z",
            request_id="req-1",
            policy_id="pol-1",
            halt_cause="policy_violation",
            reason="   ",
            grader_id="g",
            grader_role="r",
            delegation_id="d",
            principal_id="p",
        )


# ---- signing -------------------------------------------------------------


def test_a_signed_receipt_verifies():
    receipt = signed_receipt()
    assert verify_receipt(receipt, signer())
    assert receipt["resume_basis"] == "exemption"
    assert receipt["decision"] == "exemption"
    assert receipt["signature"]["value"]


def test_the_receipt_records_the_boundaries_it_was_issued_under():
    receipt = signed_receipt()
    assert receipt["exemption_covers"] == ["policy_violation"]
    assert set(receipt["exemption_does_not_cover"]) == {
        "authority_revoked",
        "authority_not_determined",
    }


def test_the_signature_covers_the_canonical_form_not_a_dict_order():
    receipt = signed_receipt()
    core = {k: v for k, v in receipt.items() if k != "signature"}
    # Re-ordering keys must not change what was signed.
    shuffled = dict(reversed(list(core.items())))
    assert canonicalize(core) == canonicalize(shuffled)


def test_editing_the_reason_after_signing_breaks_verification():
    receipt = signed_receipt()
    receipt["justification"]["reason"] = "something else entirely"
    assert verify_receipt(receipt, signer()) is False


def test_editing_the_halt_cause_after_signing_breaks_verification():
    receipt = signed_receipt()
    receipt["halt"]["cause"] = "authority_revoked"
    assert verify_receipt(receipt, signer()) is False


def test_a_receipt_signed_with_another_key_does_not_verify():
    other = HmacSigner(b"a-different-key", key_id="k2")
    assert verify_receipt(signed_receipt(), other) is False


# ---- resuming ------------------------------------------------------------


def test_a_paused_action_resumes_on_a_valid_receipt():
    paused = evaluate(mode="VOC", policy_allows=False)
    result = resume_on_exemption(outcome=paused, receipt=signed_receipt(), signer=signer())
    assert result.decision is Decision.RESUME
    assert result.wire_value == "resume"


def test_a_tampered_receipt_does_not_resume():
    paused = evaluate(mode="VOC", policy_allows=False)
    receipt = signed_receipt()
    receipt["justification"]["reason"] = "changed"
    result = resume_on_exemption(outcome=paused, receipt=receipt, signer=signer())
    assert result.decision is Decision.DENY
    assert "signature did not verify" in result.reason


def test_an_evidence_receipt_cannot_be_used_as_an_exemption():
    paused = evaluate(mode="VOC", policy_allows=False)
    receipt = signed_receipt()
    receipt["resume_basis"] = "evidence"
    result = resume_on_exemption(outcome=paused, receipt=receipt, signer=signer())
    assert result.decision is Decision.DENY


def test_nothing_resumes_when_nothing_was_paused():
    allowed = evaluate(mode="VOC", policy_allows=True)
    result = resume_on_exemption(
        outcome=allowed, receipt=signed_receipt(), signer=signer()
    )
    assert result.decision is Decision.DENY
    assert "no paused action" in result.reason


# ---- the grader as a control --------------------------------------------


def test_the_grader_has_a_ceiling_and_stops_at_it():
    g = grader(max_exemptions_per_window=2)
    signed_receipt(g)
    signed_receipt(g)
    with pytest.raises(GraderRefused) as excinfo:
        signed_receipt(g)
    assert "ceiling" in str(excinfo.value)
    assert g.signed_count == 2


def test_the_grader_keeps_an_auditable_log():
    g = grader()
    signed_receipt(g)
    with pytest.raises(GraderRefused):
        g.sign_exemption(
            receipt_id="r-x",
            issued_at="2026-10-30T16:00:00Z",
            request_id="req-9",
            policy_id="pol-1",
            halt_cause="authority_revoked",
            reason="no",
            delegation_id="d",
            principal_id="p",
        )
    assert [entry["signed"] for entry in g.log] == [True, False]


# ---- the schema agrees with the code ------------------------------------


def test_the_produced_receipt_satisfies_the_published_schema():
    receipt = signed_receipt()
    required = SCHEMA["required"]
    missing = [key for key in required if key not in receipt]
    assert not missing, missing

    # Every const and enum in the schema must hold for a real receipt.
    assert receipt["receipt_version"] == SCHEMA["properties"]["receipt_version"]["const"]
    assert receipt["decision"] == SCHEMA["properties"]["decision"]["const"]
    assert receipt["resume_basis"] == SCHEMA["properties"]["resume_basis"]["const"]
    assert (
        receipt["exemption_covers"]
        == SCHEMA["properties"]["exemption_covers"]["const"]
    )
    assert (
        receipt["exemption_does_not_cover"]
        == SCHEMA["properties"]["exemption_does_not_cover"]["const"]
    )
    allowed_causes = SCHEMA["properties"]["halt"]["properties"]["cause"]["enum"]
    assert receipt["halt"]["cause"] in allowed_causes
    assert allowed_causes == ["policy_violation"], (
        "the schema must not admit a cause an exemption cannot cover"
    )


def test_the_schema_admits_no_extra_properties():
    assert SCHEMA["additionalProperties"] is False
    for key in ("halt", "justification", "grader", "principal", "validity", "signature"):
        assert SCHEMA["properties"][key]["additionalProperties"] is False, key
