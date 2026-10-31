"""Tests for grader mandates.

The point of a mandate is that a signature proves which grader signed, not that it
was entitled to. These tests pin the four properties that make the difference:
issued by someone else, bounded in scope, bounded in time, and revocable with the
check made at use.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.mandate import (  # noqa: E402
    GraderMandate,
    MandateRefused,
    MandateRegistry,
    sign_mandate,
    verify_mandate,
)
from algovoi_ube.voc import (  # noqa: E402
    AgentGrader,
    GraderRefused,
    HmacSigner,
    evaluate,
    resume_on_exemption,
)

ISSUER = HmacSigner(b"issuer-key", key_id="issuer-1")
GRADER_KEY = HmacSigner(b"grader-key", key_id="grader-1")


def mandate(**overrides) -> GraderMandate:
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
        max_exemptions=5,
    )
    fields.update(overrides)
    return GraderMandate(**fields)


def sign(m: GraderMandate, *, policy="pol-value-limit", principal="principal-acme",
         value=500, now="2026-10-30T16:00:00Z", used=0):
    return m.permits(
        grader_id=m.grader_id, policy_id=policy, principal_id=principal,
        value=value, now=now, used=used,
    )


# ---- who authorised the grader -------------------------------------------


def test_a_grader_cannot_issue_its_own_mandate():
    """Self authorisation is not authority."""
    with pytest.raises(MandateRefused) as excinfo:
        mandate(issuer_id="grader-1", grader_id="grader-1")
    assert "own mandate" in str(excinfo.value)


def test_a_mandate_must_name_its_policies():
    with pytest.raises(MandateRefused) as excinfo:
        mandate(policies=())
    assert "policies" in str(excinfo.value)


def test_a_mandate_needs_an_issuer_and_a_grader():
    with pytest.raises(MandateRefused):
        mandate(issuer_id="")
    with pytest.raises(MandateRefused):
        mandate(grader_id="")


def test_a_mandate_is_signed_by_the_issuer_and_verifies():
    payload = sign_mandate(mandate(), ISSUER)
    assert verify_mandate(payload, ISSUER) is True


def test_a_mandate_signed_by_the_grader_does_not_verify_as_the_issuer():
    payload = sign_mandate(mandate(), ISSUER)
    assert verify_mandate(payload, GRADER_KEY) is False


def test_editing_a_mandate_breaks_its_signature():
    payload = sign_mandate(mandate(), ISSUER)
    payload["policies"] = ["pol-value-limit", "pol-everything"]
    assert verify_mandate(payload, ISSUER) is False


# ---- bounded scope -------------------------------------------------------


def test_a_policy_outside_the_mandate_is_refused():
    ok, why = sign(mandate(), policy="pol-other")
    assert ok is False
    assert "outside the mandate" in why


def test_a_principal_outside_the_mandate_is_refused():
    ok, why = sign(mandate(), principal="principal-other")
    assert ok is False
    assert "principals" in why


def test_a_value_over_the_ceiling_is_refused():
    ok, why = sign(mandate(), value=999999)
    assert ok is False
    assert "ceiling" in why


def test_a_different_grader_is_refused():
    ok, why = sign(mandate(), now="2026-10-30T16:00:00Z")
    m = mandate()
    ok, why = m.permits(
        grader_id="grader-2", policy_id="pol-value-limit",
        principal_id="principal-acme", value=1, now="2026-10-30T16:00:00Z",
    )
    assert ok is False
    assert "not grader-2" in why or "grader-1" in why


# ---- bounded time --------------------------------------------------------


def test_a_lapsed_mandate_is_refused():
    ok, why = sign(mandate(), now="2027-01-01T00:00:00Z")
    assert ok is False
    assert "lapsed" in why


def test_a_mandate_within_its_window_permits():
    ok, why = sign(mandate())
    assert ok is True, why


def test_the_exemption_count_is_bounded():
    ok, why = sign(mandate(max_exemptions=2), used=2)
    assert ok is False
    assert "exemptions" in why


# ---- revocation is checked at use ---------------------------------------


def test_a_revoked_mandate_stops_the_next_signature():
    registry = MandateRegistry()
    m = mandate()
    registry.register(sign_mandate(m, ISSUER))
    grader = AgentGrader(
        grader_id="grader-1", grader_role="compliance-officer", signer=GRADER_KEY,
        mandate=m, mandate_payload=sign_mandate(m, ISSUER), mandate_registry=registry,
    )

    first = grader.sign_exemption(
        receipt_id="r-1", issued_at="2026-10-30T16:00:00Z", request_id="q1",
        policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
        delegation_id="d", principal_id="principal-acme",
        valid_until="2026-10-30T18:00:00Z", value=100,
    )
    assert first["grader"]["mandate_id"] == "m-1"

    registry.revoke("m-1")
    with pytest.raises(GraderRefused) as excinfo:
        grader.sign_exemption(
            receipt_id="r-2", issued_at="2026-10-30T16:05:00Z", request_id="q2",
            policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
            delegation_id="d", principal_id="principal-acme",
            valid_until="2026-10-30T18:00:00Z", value=100,
        )
    assert "revoked" in str(excinfo.value)


def test_the_registry_counts_uses():
    registry = MandateRegistry()
    m = mandate(max_exemptions=1)
    registry.register(sign_mandate(m, ISSUER))
    grader = AgentGrader(
        grader_id="grader-1", grader_role="compliance-officer", signer=GRADER_KEY,
        mandate=m, mandate_payload=sign_mandate(m, ISSUER), mandate_registry=registry,
    )
    grader.sign_exemption(
        receipt_id="r-1", issued_at="2026-10-30T16:00:00Z", request_id="q1",
        policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
        delegation_id="d", principal_id="principal-acme",
        valid_until="2026-10-30T18:00:00Z", value=1,
    )
    assert registry.used("m-1") == 1
    with pytest.raises(GraderRefused):
        grader.sign_exemption(
            receipt_id="r-2", issued_at="2026-10-30T16:01:00Z", request_id="q2",
            policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
            delegation_id="d", principal_id="principal-acme",
            valid_until="2026-10-30T18:00:00Z", value=1,
        )


# ---- fail closed ---------------------------------------------------------


def test_a_grader_with_no_mandate_signs_nothing():
    grader = AgentGrader(
        grader_id="grader-1", grader_role="compliance-officer", signer=GRADER_KEY
    )
    with pytest.raises(GraderRefused) as excinfo:
        grader.sign_exemption(
            receipt_id="r-1", issued_at="2026-10-30T16:00:00Z", request_id="q",
            policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
            delegation_id="d", principal_id="principal-acme",
        )
    assert "no mandate" in str(excinfo.value)


def test_the_receipt_carries_the_authority_chain():
    m = mandate()
    payload = sign_mandate(m, ISSUER)
    grader = AgentGrader(
        grader_id="grader-1", grader_role="compliance-officer", signer=GRADER_KEY,
        mandate=m, mandate_payload=payload,
    )
    receipt = grader.sign_exemption(
        receipt_id="r-1", issued_at="2026-10-30T16:00:00Z", request_id="q",
        policy_id="pol-value-limit", halt_cause="policy_violation", reason="ok",
        delegation_id="d", principal_id="principal-acme",
        valid_until="2026-10-30T18:00:00Z", value=1,
    )
    assert receipt["grader"]["mandate_id"] == "m-1"
    assert receipt["grader"]["mandate_ref"]["issuer"]["issuer_id"] == "principal-acme"
    assert verify_mandate(receipt["grader"]["mandate_ref"], ISSUER) is True


def test_a_grader_cannot_exempt_outside_its_mandate_and_resume_anyway():
    """The end to end case: a valid receipt that the mandate never permitted."""
    grader = AgentGrader(
        grader_id="grader-1", grader_role="compliance-officer", signer=GRADER_KEY,
        mandate=mandate(policies=("pol-value-limit",)),
        mandate_payload=sign_mandate(mandate(policies=("pol-value-limit",)), ISSUER),
    )
    with pytest.raises(GraderRefused):
        grader.sign_exemption(
            receipt_id="r-1", issued_at="2026-10-30T16:00:00Z", request_id="q",
            policy_id="pol-delete-everything", halt_cause="policy_violation",
            reason="please", delegation_id="d", principal_id="principal-acme",
            valid_until="2026-10-30T18:00:00Z",
        )


def test_mandate_time_compare_handles_offsets_not_lexicographically():
    """Finding 3: `now > self.not_after` on raw strings mis-orders a +hh:mm
    offset. now = 12:00+05:00 is 07:00Z, before a 09:00Z not_after, so the
    mandate has NOT lapsed, even though the raw strings sort the other way.
    """
    m = mandate(not_after="2026-10-30T09:00:00Z")
    ok, reason = sign(m, now="2026-10-30T12:00:00+05:00")  # 07:00Z, still valid
    assert ok, reason
    assert "lapsed" not in reason
    # A genuinely later instant is still refused.
    expired_ok, expired_reason = sign(m, now="2026-10-30T12:00:00Z")
    assert not expired_ok and "lapsed" in expired_reason
    # An unreadable instant fails closed rather than passing.
    bad_ok, bad_reason = sign(m, now="not-a-timestamp")
    assert not bad_ok and "could not be read" in bad_reason
