"""Fail-closed status resolution and the five state machine.

NTI-1 section 6.1 says that when a registry cannot be reached, or cannot give
an authoritative answer, the runtime MUST emit an incomplete_check and halt
rather than proceed on stale authority. This module implements that rule and
refuses to guess.

It also runs the LGD lifecycle, so the halt lands somewhere real:

    REGISTERED -> GATE_PASSED -> ACTIVE -> ANOMALY -> PAUSE -> ROLLBACK
      -> REVERIFY -> RESUMED

The three legal incomplete_check reasons are the ones the specification names.
Anything else is rejected, because an unclassified failure is how a stale
authority quietly becomes a live one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

REASONS = ("tryLater", "not_authoritative", "internal_error")


class State(str, Enum):
    REGISTERED = "REGISTERED"
    GATE_PASSED = "GATE_PASSED"
    ACTIVE = "ACTIVE"
    ANOMALY = "ANOMALY"
    PAUSE = "PAUSE"
    ROLLBACK = "ROLLBACK"
    REVERIFY = "REVERIFY"
    RESUMED = "RESUMED"


# Only these transitions are legal. Anything else is a bug in the runtime, not
# a policy choice.
#
# REVERIFY -> RESUMED is declared explicitly rather than performed by a direct
# assignment. It is the edge that matters: where a governing regime makes a
# revocation irreversible, what becomes unavailable is this transition, not a new
# terminal state. Keeping it in the table is what makes that expressible.
LEGAL = {
    State.REGISTERED: {State.GATE_PASSED},
    State.GATE_PASSED: {State.ACTIVE},
    State.ACTIVE: {State.ANOMALY},
    State.ANOMALY: {State.PAUSE},
    State.PAUSE: {State.ROLLBACK},
    State.ROLLBACK: {State.REVERIFY},
    State.REVERIFY: {State.RESUMED},
    State.RESUMED: {State.ANOMALY},
}

#: Held only by resume(). The REVERIFY -> RESUMED edge is declared in LEGAL so a
#: governing regime can withdraw it, but walking it requires this token, so the
#: table is not a second, unguarded route to the state resume() guards.
_RESUME_TOKEN = object()


class IllegalTransition(RuntimeError):
    pass


@dataclass
class StatusResult:
    """The answer to "is this authority still good?"."""

    authoritative: bool
    status: str = ""
    reason: str = ""
    observed_at: str = ""

    @property
    def halted(self) -> bool:
        """An unanswerable question must not be read as permission."""
        return not self.authoritative or self.status.lower() not in {"active", "valid"}


@dataclass
class IncompleteCheck:
    """The receipt NTI-1 requires when status could not be resolved."""

    reason: str
    detail: str = ""
    observed_at: str = ""
    t_effective: str = ""
    t_observed: str = ""
    registry_version: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.reason not in REASONS:
            raise ValueError(
                f"reason must be one of {REASONS}, got {self.reason!r}. "
                "An unclassified failure must not be treated as permission."
            )

    def as_dict(self) -> dict:
        payload = {
            "type": "incomplete_check",
            "reason": self.reason,
            "detail": self.detail,
            "observed_at": self.observed_at,
            # NTI-1 asked for these three so a third party can judge whether a
            # halt was justified rather than take our word for it.
            "t_effective": self.t_effective,
            "t_observed": self.t_observed,
            "registry_version": self.registry_version,
        }
        payload.update(self.extra)
        return payload


def resolve(fetch) -> StatusResult:
    """Call a status source and fail closed on any failure.

    ``fetch`` returns a dict with at least ``status``, plus optionally
    ``authoritative`` and ``version``. Any exception becomes a halt with a
    classified reason, never a pass.
    """
    try:
        answer = fetch()
    except TimeoutError as exc:
        return StatusResult(False, "", f"tryLater: {exc}")
    except ConnectionError as exc:
        return StatusResult(False, "", f"tryLater: {exc}")
    except Exception as exc:  # noqa: BLE001 - any failure must halt
        return StatusResult(False, "", f"internal_error: {exc.__class__.__name__}: {exc}")

    if not isinstance(answer, dict):
        return StatusResult(False, "", "internal_error: status source returned no mapping")
    if answer.get("authoritative") is False:
        return StatusResult(False, "", "not_authoritative: source disclaimed authority")
    status = str(answer.get("status") or "").strip()
    if not status:
        return StatusResult(False, "", "not_authoritative: no status returned")
    return StatusResult(
        True,
        status,
        "",
        str(answer.get("observed_at") or ""),
    )


def incomplete_from(result: StatusResult, *, observed_at: str = "", version: str = "") -> IncompleteCheck:
    """Build the receipt for a halted check from a resolved status."""
    reason = "internal_error"
    detail = result.reason
    for candidate in REASONS:
        if detail.startswith(candidate):
            reason = candidate
            detail = detail[len(candidate) + 1 :].strip(" :")
            break
    if not result.authoritative and not result.reason:
        reason = "not_authoritative"
    return IncompleteCheck(
        reason=reason,
        detail=detail,
        observed_at=observed_at,
        t_observed=observed_at,
        t_effective=observed_at,
        registry_version=version,
    )


class Lifecycle:
    """The LGD state machine, with only legal transitions allowed."""

    def __init__(self, state: State = State.REGISTERED) -> None:
        self.state = state
        self.history: list[State] = [state]
        self.receipt: dict = {}

    def to(self, new_state: State, *, _resume_token: object | None = None) -> State:
        allowed = LEGAL.get(self.state, set())
        if new_state not in allowed:
            raise IllegalTransition(
                f"{self.state.value} -> {new_state.value} is not a legal transition "
                f"(allowed: {', '.join(sorted(s.value for s in allowed)) or 'none'})"
            )
        if new_state is State.RESUMED and _resume_token is not _RESUME_TOKEN:
            # The edge stays declared in the table, so it remains enumerable and
            # withdrawable, but it is not a public transition. Guarding only the
            # caller left the table as an unguarded parallel route to the state
            # the caller guards, which is the whole fail-open this repository
            # keeps rediscovering: a property enforced in one function rather
            # than at the point where the outcome is produced.
            raise IllegalTransition(
                "RESUMED is reachable only through resume() with a recorded basis; "
                "the REVERIFY -> RESUMED edge is declared so it can be withdrawn, "
                "not so it can be walked directly"
            )
        self.state = new_state
        self.history.append(new_state)
        return self.state

    def halt(self) -> State:
        """Take the halt path from wherever we are to PAUSE.

        ACTIVE -> ANOMALY -> PAUSE, and a resumed action that misbehaves goes
        straight back to ANOMALY. Anything before ACTIVE has not acted yet, so
        it simply never proceeds.
        """
        if self.state is State.ACTIVE:
            self.to(State.ANOMALY)
            self.to(State.PAUSE)
        elif self.state is State.RESUMED:
            self.to(State.ANOMALY)
            self.to(State.PAUSE)
        elif self.state is State.ANOMALY:
            self.to(State.PAUSE)
        elif self.state in {State.PAUSE, State.ROLLBACK, State.REVERIFY}:
            pass
        else:
            # Not yet acting: record the pause directly, since no action
            # started and there is nothing to roll back.
            self.state = State.PAUSE
            self.history.append(State.PAUSE)
        return self.state

    def resume(self, basis=None, *, revocation_irreversible: bool = False) -> State:
        """PAUSE -> ROLLBACK -> REVERIFY -> RESUMED.

        The last hop goes through the table like every other transition, so an
        undeclared edge is refused rather than assumed, and it requires a token
        only this method holds, so the table is not a second route to RESUMED.

        Every guard runs before the chain advances. Refusing after moving to
        REVERIFY left the object one table-legal transition away from the very
        state it had just refused, which made ``revocation_irreversible``
        defeatable with a single ``to(State.RESUMED)``. A refusal now leaves the
        chain in PAUSE, exactly where the caller left it.

        ``revocation_irreversible`` models the case where a governing regime
        makes revocation final (eIDAS Art. 28(4) is the instance in scope). What
        becomes unavailable is the REVERIFY -> RESUMED edge, and no extra state
        was needed to say so.

        ``basis`` is the resume basis from :mod:`algovoi_ube.resume`. It is
        required in substance, not only in signature: a call with no basis is
        refused, because a resume that records nothing about why the halt was
        lifted is indistinguishable from one where someone simply asserted the
        condition was fine.
        """
        if self.state is not State.PAUSE:
            raise IllegalTransition(f"cannot resume from {self.state.value}")

        if revocation_irreversible:
            raise IllegalTransition(
                "REVERIFY -> RESUMED is unavailable: the revocation is final under "
                "the governing regime, so the chain remains in PAUSE and no "
                "transition from here reaches RESUMED"
            )

        if basis is None:
            raise IllegalTransition(
                "resume refused: a resume must carry a basis (evidence or "
                "exemption); reaching RESUMED on no basis records nothing about "
                "why the halt was lifted"
            )

        from .resume import decide_resume

        decision = decide_resume(signature_valid=True, basis=basis)
        if not decision.allowed:
            raise IllegalTransition(f"resume refused on basis: {decision.reason}")

        self.to(State.ROLLBACK)
        self.to(State.REVERIFY)
        self.receipt = decision.receipt
        self.to(State.RESUMED, _resume_token=_RESUME_TOKEN)
        return self.state
