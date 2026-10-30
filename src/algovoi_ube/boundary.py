"""The decision boundary: when is a delegation's status judged?

This is the question Alan Karp raised on the thread and nobody answered: is a
delegation judged at the time it is made, at the time the resource is invoked,
or when that invocation ends? His argument favours the moment of invocation,
because interrupting mid invocation can leave an application inconsistent, and
there is an unavoidable race between state changes and the steps of a call.

This module does not pretend to settle it. It makes the choice explicit and
checkable, which is the next best thing:

  INVOCATION  the status is frozen when the action starts. A revocation that
              arrives mid flight does not stop the action in progress; it stops
              the next one. Consistent with atomic execution, and honest about
              the window it leaves open.

  EFFECT      the status is rechecked at the moment of irreversible effect.
              Tighter, and it is what a mid execution halt needs, but it can
              abandon an action half done.

  COMPLETION  the status is judged when the invocation ends. Widest window of
              exposure; only defensible when the action is not reversible and
              the alternative is a worse inconsistency.

The boundary is declared once and recorded on every receipt, so an independent
observer can see which policy was in force rather than guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Boundary(str, Enum):
    INVOCATION = "invocation"
    EFFECT = "effect"
    COMPLETION = "completion"
    # NTI's own architecture. The AIW paper says a tool call cannot safely be
    # interrupted mid flight without corrupting external state, so the sidecar
    # lets the current atomic call finish and intercepts the next one. That is a
    # distinct posture from INVOCATION: the status is not frozen for the whole
    # session, it is re-read at every sub-call edge.
    SUB_CALL = "sub_call"


# Which boundaries may halt an action that is already running.
#
# EFFECT is listed because it is expressible and useful, but NTI-1 as written
# does not allow it for tool calls, so a target claiming NTI compliance must
# declare SUB_CALL or INVOCATION. The conformance check enforces that rather than
# trusting a declaration.
INTERRUPTING_BOUNDARIES = (Boundary.EFFECT,)
NTI_PERMITTED_BOUNDARIES = (Boundary.SUB_CALL, Boundary.INVOCATION, Boundary.COMPLETION)


@dataclass
class BoundaryDecision:
    boundary: Boundary
    allowed: bool
    reason: str
    # What happened to an action already under way when status changed.
    interrupted: bool = False
    # For the sub-call posture: whether the following call may proceed. This is
    # the field that makes NTI's refusal expressible without interrupting the
    # call already in flight.
    next_call_allowed: bool | None = None

    def as_dict(self) -> dict:
        payload = {
            "boundary": self.boundary.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "interrupted": self.interrupted,
        }
        if self.next_call_allowed is not None:
            payload["next_call_allowed"] = self.next_call_allowed
        return payload


def judge(
    boundary: Boundary,
    *,
    status_at_start: str,
    status_at_effect: str,
    status_at_end: str,
    in_flight: bool = False,
) -> BoundaryDecision:
    """Decide whether an action may proceed, given status at each moment.

    ``in_flight`` means the action has already begun. That flag is the whole
    point: a policy that only looks at the start cannot interrupt, and a policy
    that looks at the effect must say so when it does.
    """
    def ok(status: str) -> bool:
        return (status or "").strip().lower() in {"active", "valid", "allow", "allowed"}

    if boundary is Boundary.INVOCATION:
        allowed = ok(status_at_start)
        return BoundaryDecision(
            boundary=boundary,
            allowed=allowed,
            reason=(
                "status at invocation was active"
                if allowed
                else "status at invocation was not active"
            ),
            interrupted=False,
        )

    if boundary is Boundary.EFFECT:
        # An action already under way is stopped when the status changed before
        # the effect landed. That is the mid execution halt.
        if in_flight and not ok(status_at_effect):
            return BoundaryDecision(
                boundary=boundary,
                allowed=False,
                reason="status changed before the effect; halted mid execution",
                interrupted=True,
            )
        allowed = ok(status_at_effect)
        return BoundaryDecision(
            boundary=boundary,
            allowed=allowed,
            reason=(
                "status at effect was active"
                if allowed
                else "status at effect was not active"
            ),
            interrupted=False,
        )

    if boundary is Boundary.SUB_CALL:
        # NTI's posture. The atomic call in flight is never interrupted, because
        # doing so would corrupt external state. Instead the status is re-read at
        # the edge between calls: a change that arrives mid flight stops the
        # next call, not this one. The refusal is therefore recorded as a
        # boundary decision for the following payload rather than a halt.
        if in_flight:
            next_allowed = ok(status_at_effect)
            return BoundaryDecision(
                boundary=boundary,
                allowed=True,
                reason=(
                    "the atomic call in flight is allowed to finish; the status "
                    + ("is still active at the sub-call edge" if next_allowed
                       else "changed mid flight, so the next call will be refused")
                ),
                interrupted=False,
                next_call_allowed=next_allowed,
            )
        allowed = ok(status_at_start)
        return BoundaryDecision(
            boundary=boundary,
            allowed=allowed,
            reason=(
                "status at the sub-call edge was active"
                if allowed
                else "status at the sub-call edge was not active, so the call is refused"
            ),
            interrupted=False,
            next_call_allowed=allowed,
        )

    allowed = ok(status_at_end)
    return BoundaryDecision(
        boundary=boundary,
        allowed=allowed,
        reason=(
            "status at completion was active"
            if allowed
            else "status at completion was not active"
        ),
        interrupted=False,
    )


def describe(boundary: Boundary) -> str:
    """One line an operator can read, for the receipt."""
    return {
        Boundary.INVOCATION: (
            "judged at invocation: an action already running is not interrupted"
        ),
        Boundary.EFFECT: (
            "judged at the point of effect: an action is halted if status changes "
            "before the effect lands"
        ),
        Boundary.COMPLETION: (
            "judged at completion: the widest window, and the least protection"
        ),
        Boundary.SUB_CALL: (
            "judged at every sub-call edge: the call in flight always finishes, and "
            "a status change is refused at the next one"
        ),
    }[boundary]
