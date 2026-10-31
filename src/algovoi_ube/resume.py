"""Resume basis: which door a resumed action came through.

This module implements the proposal raised on the W3C AIW thread on 30 October
(message 0107, then extended in the note sent to public-agentprotocol). The
argument is narrow and worth stating in one paragraph, because the code only
makes sense against it.

When a runtime halts an action and later resumes it, the record has to say what
the resume rested on. Signature verification alone is an authenticity check: it
says who signed, not whether the condition that caused the halt still holds. If a
valid signature is sufficient to reach RESUMED, then two very different runs end
in identical records, one where the halt condition was verified restored and one
where someone with authority accepted the risk and carried on. Both are legal.
Neither is a defect. But an auditor cannot tell them apart afterwards, and an
immutable record that cannot separate the two is immutable without being
informative.

So a resume carries a basis, drawn from a closed set:

    evidence   the registered restore condition was verified in full
    exemption  an accountability layer accepted the risk; the reason is
               recorded, not evaluated

Free text would not do. A hash chain proves the reason was not altered, it does
not make it countable, and the query that matters most, "every chain that
resumed after a revocation", cannot be answered from prose at all. A closed value
can be counted, alerted on, and recomputed by a third party who does not trust
the filer.

Two boundaries follow, and they are the load bearing part:

    exemption does not cover authority_revoked
        Revocation is the issuing authority's decision, not the executing side's.
        A manager on the executing side can accept a policy violation. He cannot
        un-revoke someone else's authority. If a signed exemption could open
        RESUMED after a revocation, revocation would be advisory for anyone who
        has a manager, and the manager would be the shortest path around the only
        mechanism the design has for taking authority away.

    exemption does not cover authority_not_determined
        That value means the registry could not be read, or the proof was against
        a stale root. It is an absence of information, not a judgement about
        information. A signature cannot convert "we do not know" into "we know",
        and a signed exemption must not be able to buy back the fail closed
        property.

Neither boundary adds a state, removes one, or changes the state space.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# The closed set. Adding a third value is a specification change, not a
# configuration option, which is the point of the proposal.
BASES = ("evidence", "exemption")


class Basis(str, Enum):
    EVIDENCE = "evidence"
    EXEMPTION = "exemption"


# What an exemption is allowed to cover, and what it is not.
EXEMPTION_COVERS = ("policy_violation",)
EXEMPTION_DOES_NOT_COVER = ("authority_revoked", "authority_not_determined")

# The five wire values the decision can take. The receipt carries the check
# outcome; nothing here needs a sixth value on the wire, and adding one is how a
# closed set stops being closed.
WIRE_VALUES = ("allow", "deny", "pause", "resume", "revoked")


class ResumeRefused(RuntimeError):
    """The basis does not permit RESUMED."""


@dataclass
class RestoreEvidence:
    """What an evidence based resume has to be able to show."""

    conditions: list[str] = field(default_factory=list)
    verifier_role: str = ""
    valid_from: str = ""
    valid_until: str = ""

    @property
    def complete(self) -> bool:
        return bool(self.conditions) and bool(self.verifier_role) and bool(self.valid_until)


@dataclass
class ResumeBasis:
    """The basis a resume rests on.

    Two shapes are accepted, because the thread left the choice open. The first
    is the original closed enumeration. The second carries the delegation state
    the resuming agent actually relied on, which is the extension proposed later
    and is what a receiver needs in order to decline a resume for a delegation
    that is already gone.

    Passing both is fine and is what a cautious sender should do: the enum says
    which door, the object says what was checked on the way through.
    """

    basis: str
    # Which halt the resume answers. A policy violation may be exempted; a
    # revocation or an undetermined authority may not.
    covers: str = "policy_violation"
    delegation_id: str = ""
    state_at_resume: str = ""
    evidence: RestoreEvidence | None = None
    exemption_reason: str = ""
    exemption_actor: str = ""

    def __post_init__(self) -> None:
        if self.basis not in BASES:
            raise ValueError(
                f"resume basis must be one of {BASES}, got {self.basis!r}. "
                "A free text basis cannot be counted, which is the whole reason "
                "the field exists."
            )
        if self.basis == Basis.EVIDENCE.value:
            # An evidence basis asserts that the registered restore condition was
            # verified in full. Omitting the evidence object entirely must not be
            # a way around that: a basis of "evidence" with nothing attached is a
            # signature-only resume wearing the evidence label, which is exactly
            # the fail-open this field exists to refuse. It is therefore required,
            # not merely checked when present.
            if self.evidence is None or not self.evidence.complete:
                raise ValueError(
                    "an evidence based resume needs at least one restore condition, "
                    "a verifier role and a validity window; a signature alone is an "
                    "authenticity check, not a restore condition check"
                )
        if self.basis == Basis.EXEMPTION.value:
            if self.covers in EXEMPTION_DOES_NOT_COVER:
                raise ResumeRefused(
                    f"exemption does not cover {self.covers}. "
                    + (
                        "Revocation is the issuing authority's decision; a manager on "
                        "the executing side cannot un-revoke someone else's authority."
                        if self.covers == "authority_revoked"
                        else "An absence of information is not a judgement about it; a "
                        "signature cannot convert 'we do not know' into 'we know'."
                    )
                )
            if self.covers not in EXEMPTION_COVERS:
                raise ResumeRefused(
                    f"exemption covers {EXEMPTION_COVERS}, not {self.covers!r}"
                )
            # An exemption is someone accepting a risk. Without a reason and an
            # accountable actor it records that a risk was accepted and nothing
            # about why or by whom, which is the same fail-open as a basis with
            # no substance: the field is present, the record says nothing.
            # JustificationReceipt already requires both, so the two
            # representations of an exemption must not disagree.
            if not self.exemption_reason.strip() or not self.exemption_actor.strip():
                raise ResumeRefused(
                    "an exemption basis must record why the risk was accepted and "
                    "who accepted it; an exemption with no reason and no "
                    "accountable actor is an accepted risk that nobody owns"
                )

    @property
    def permits_resume(self) -> bool:
        return True

    def as_dict(self) -> dict:
        payload: dict = {
            "resume_basis": self.basis,
            "exemption_covers": list(EXEMPTION_COVERS),
            "exemption_does_not_cover": list(EXEMPTION_DOES_NOT_COVER),
        }
        if self.delegation_id or self.state_at_resume:
            payload["basis_detail"] = {
                "delegation_id": self.delegation_id,
                "state_at_resume": self.state_at_resume,
            }
        if self.evidence is not None:
            payload["restore_evidence"] = {
                "conditions": list(self.evidence.conditions),
                "verifier_role": self.evidence.verifier_role,
                "valid_from": self.evidence.valid_from,
                "valid_until": self.evidence.valid_until,
            }
        if self.basis == Basis.EXEMPTION.value:
            # Recorded, not evaluated. The protocol does not read the opinion,
            # and this field is how the record proves it did not.
            payload["exemption"] = {
                "reason": self.exemption_reason,
                "actor": self.exemption_actor,
            }
        return payload


@dataclass
class ResumeDecision:
    allowed: bool
    wire_value: str
    reason: str
    receipt: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "wire_value": self.wire_value,
            "reason": self.reason,
            "receipt": self.receipt,
        }


def _parse_instant(value: str):
    """Parse an ISO 8601 instant, or None when it cannot be read."""
    if not isinstance(value, str) or not value:
        # A non-string (or empty) instant is unreadable, not a crash: callers
        # treat None as "refuse", which keeps the fail-closed contract.
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        from datetime import timezone

        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _window_refusal(valid_from: str, valid_until: str, now) -> str:
    """Return a refusal reason when ``now`` is outside the window, else "".

    A window that is present but unreadable is refused rather than ignored: an
    unparseable expiry cannot be shown to be in the future, and treating it as
    valid is how a required field becomes decoration.
    """
    start = _parse_instant(valid_from)
    end = _parse_instant(valid_until)
    if valid_until and end is None:
        return (
            "the validity window cannot be read, so the resume cannot be shown to "
            "fall inside it"
        )
    if valid_from and start is None:
        return (
            "the start of the validity window cannot be read, so the resume cannot "
            "be shown to fall inside it"
        )
    if end is not None and now > end:
        return (
            f"the validity window ended at {valid_until}, before the resume was "
            "evaluated; an expired window is not evidence that the condition holds now"
        )
    if start is not None and now < start:
        return (
            f"the validity window does not begin until {valid_from}, so the resume "
            "is early and the evidence does not yet apply"
        )
    return ""


def decide_resume(
    *,
    signature_valid: bool,
    basis: ResumeBasis | None,
    delegation_state: str = "",
    now=None,
) -> ResumeDecision:
    """Decide whether a resume token may reach RESUMED.

    This is the fail open versus fail closed case from the thread. A token whose
    signature verifies and which carries nothing else is refused, because
    signature verification cannot tell a restored condition from an accepted
    risk. That is deliberately stricter than the example the thread started
    from.

    ``delegation_state`` is what the *receiver* knows about the delegation. It
    outranks whatever the basis reports about itself: a document asserting its own
    delegation is fine is not evidence, and when the two disagree the resume is
    refused rather than resolved in the sender's favour.

    ``now`` is injected so an expiry check is testable; it defaults to the current
    instant in UTC.
    """
    if now is None:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

    if not signature_valid:
        return ResumeDecision(
            allowed=False,
            wire_value="deny",
            reason="the resume token's signature did not verify",
        )

    if basis is None:
        return ResumeDecision(
            allowed=False,
            wire_value="pause",
            reason=(
                "a valid signature alone is not a resume basis: it says who signed, "
                "not whether the halt condition still holds. The action stays paused."
            ),
        )

    # The delegation may already be gone. A receiver that checks only the
    # signature will resume into a revoked authority. What the receiver knows
    # outranks what the basis says about itself, and a contradiction is refused
    # rather than resolved by precedence: letting the submitted value win is how
    # a basis asserting ACTIVE resumes into a delegation the receiver knows is
    # REVOKED.
    claimed = (basis.state_at_resume or "").strip().upper()
    known = (delegation_state or "").strip().upper()
    if claimed and known and claimed != known:
        return ResumeDecision(
            allowed=False,
            wire_value="revoked",
            reason=(
                f"the basis reports the delegation is {claimed.lower()} while the "
                f"receiver reports {known.lower()}; a claim that contradicts the "
                "verifier's own knowledge is not evidence, so the action stays paused"
            ),
            receipt=basis.as_dict(),
        )
    state = known or claimed
    if state in {"REVOKED", "EXPIRED", "SUSPENDED"}:
        return ResumeDecision(
            allowed=False,
            wire_value="revoked",
            reason=(
                f"the delegation is {state.lower()} at resume time, "
                "so the resume is declined rather than taken on the signature"
            ),
            receipt=basis.as_dict(),
        )

    # An evidence basis asserts that the registered restore condition was verified
    # in full, which is a claim about a window. Checking the fields exist and
    # never comparing them to a clock makes valid_until decoration.
    if basis.basis == Basis.EVIDENCE.value and basis.evidence is not None:
        refusal = _window_refusal(
            basis.evidence.valid_from, basis.evidence.valid_until, now
        )
        if refusal:
            return ResumeDecision(
                allowed=False,
                wire_value="pause",
                reason=refusal,
                receipt=basis.as_dict(),
            )


    try:
        receipt = basis.as_dict()
    except ResumeRefused as exc:
        return ResumeDecision(
            allowed=False,
            wire_value="pause",
            reason=str(exc),
        )

    return ResumeDecision(
        allowed=True,
        wire_value="resume",
        reason=(
            "resumed on evidence: the restore condition was verified in full"
            if basis.basis == Basis.EVIDENCE.value
            else "resumed on exemption: an accountability layer accepted the risk "
            "and the reason is recorded, not evaluated"
        ),
        receipt=receipt,
    )


def wire_value_of(decision: ResumeDecision, *, with_receipt: bool) -> str:
    """The wire value, with or without the receipt attached.

    The mapping is one directional. A receipt may name the wire value it maps
    onto; the wire value must never depend on the receipt being present. A PAUSE
    with no receipt is still a well formed record, because the refusal is
    complete on its own.
    """
    return decision.wire_value
