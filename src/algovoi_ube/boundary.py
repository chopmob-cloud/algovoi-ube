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


@dataclass
class BoundaryDecision:
    boundary: Boundary
    allowed: bool
    reason: str
    # What happened to an action already under way when status changed.
    interrupted: bool = False

    def as_dict(self) -> dict:
        return {
            "boundary": self.boundary.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "interrupted": self.interrupted,
        }


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
    }[boundary]
