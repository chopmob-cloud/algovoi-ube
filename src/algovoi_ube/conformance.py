"""Conformance checks for NTI-1.

Section 5 of the specification lists five testable requirements. Each is
implemented here as a check that can be run against an implementation, and each
carries the clause it comes from so a failure points at the text rather than at
an opinion.

Nothing in this module decides whether NTI-1 is a good standard. It asks only
one question: does the implementation do what the document says it must.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .chain import verify_chain
from .failclosed import REASONS


@dataclass
class Check:
    ident: str
    clause: str
    description: str
    passed: bool = False
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "ident": self.ident,
            "clause": self.clause,
            "description": self.description,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    def summary(self) -> str:
        total = len(self.checks)
        good = total - len(self.failures)
        if self.passed:
            return f"all {total} checks passed"
        names = ", ".join(c.ident for c in self.failures)
        return f"{good} of {total} passed; failed: {names}"


def t_1_1(report: Report, decide: Callable[[dict], str]) -> Check:
    """T-1.1 Identity: an unsigned action must be denied."""
    check = report.add(
        Check(
            "T-1.1",
            "3.1 Pillar 1 and 5 T-1.1",
            "An action submitted with no signature MUST be denied",
        )
    )
    try:
        decision = decide(
            {"action": "transfer_funds", "amount": 10, "signed": False, "signature": ""}
        )
    except Exception as exc:  # noqa: BLE001
        check.detail = f"decide raised {exc.__class__.__name__}: {exc}"
        return check
    check.passed = str(decision).strip().lower() in {"deny", "denied"}
    check.detail = f"decision was {decision!r}"
    return check


def t_2_1(report: Report, decide: Callable[[dict], str], now: int = 1800000001) -> Check:
    """T-2.1 Governance: an expired capability must be denied."""
    check = report.add(
        Check(
            "T-2.1",
            "3.2 Pillar 2 and 5 T-2.1",
            "An action under an expired capability MUST be denied",
        )
    )
    try:
        decision = decide(
            {
                "action": "transfer_funds",
                "amount": 10,
                "signed": True,
                "capability": {
                    "capability_id": "cap-fund-transfer",
                    "expires": now - 1,
                    "value_limit": 50000,
                },
                "now": now,
            }
        )
    except Exception as exc:  # noqa: BLE001
        check.detail = f"decide raised {exc.__class__.__name__}: {exc}"
        return check
    check.passed = str(decision).strip().lower() in {"deny", "denied"}
    check.detail = f"decision was {decision!r} for a capability expired at {now - 1}"
    return check


def t_3_1(report: Report, decide: Callable[[dict], str]) -> Check:
    """T-3.1 Consensus: a multi agent action below threshold must be denied."""
    check = report.add(
        Check(
            "T-3.1",
            "3.3 Pillar 3 and 5 T-3.1",
            "A multi agent action without threshold agreement MUST be denied",
        )
    )
    try:
        decision = decide(
            {
                "action": "transfer_funds",
                "amount": 10,
                "signed": True,
                "multi_agent": True,
                "votes": [
                    {"voter_id": "a", "decision": "Allow"},
                    {"voter_id": "b", "decision": "Allow"},
                ],
                "threshold": 3,
            }
        )
    except Exception as exc:  # noqa: BLE001
        check.detail = f"decide raised {exc.__class__.__name__}: {exc}"
        return check
    check.passed = str(decision).strip().lower() in {"deny", "denied"}
    check.detail = f"decision was {decision!r} with 2 of 3 required votes"
    return check


def t_4_1(report: Report, events: list[dict]) -> Check:
    """T-4.1 Audit: after 100 actions the chain must be 100 events long and intact."""
    check = report.add(
        Check(
            "T-4.1",
            "3.4 Pillar 4 and 5 T-4.1",
            "After 100 executed actions the audit chain MUST contain 100 events and verify",
        )
    )
    check.passed = len(events) == 100 and verify_chain(events).ok
    status = verify_chain(events)
    check.detail = f"{len(events)} event(s); {status.summary()}"
    return check


def t_4_2(report: Report, events: list[dict]) -> Check:
    """Tampering with any past event must break verification.

    This is not one of the numbered tests, but Pillar 4 states it as a MUST, so
    it is checked rather than assumed.
    """
    check = report.add(
        Check(
            "T-4.2",
            "3.4 Pillar 4",
            "Editing any past audit event MUST cause verification to fail",
        )
    )
    if len(events) < 2:
        check.detail = "needs at least two events to test tampering"
        return check
    tampered = [dict(e) for e in events]
    tampered[0]["decision"] = "Deny" if tampered[0].get("decision") == "Allow" else "Allow"
    status = verify_chain(tampered)
    check.passed = not status.ok
    check.detail = "tampering was detected" if check.passed else "tampering went undetected"
    return check


def t_5_1(report: Report, reload_events: Callable[[], list[dict]]) -> Check:
    """T-5.1 Persistence: the chain must survive a restart and still verify."""
    check = report.add(
        Check(
            "T-5.1",
            "3.5 Pillar 5 and 5 T-5.1",
            "After a restart the audit chain MUST be preserved and still verify",
        )
    )
    try:
        events = reload_events()
    except Exception as exc:  # noqa: BLE001
        check.detail = f"reload raised {exc.__class__.__name__}: {exc}"
        return check
    status = verify_chain(events)
    check.passed = bool(events) and status.ok
    check.detail = f"{len(events)} event(s) after reload; {status.summary()}"
    return check


def t_6_1(report: Report, resolve_status: Callable[[], object]) -> Check:
    """Section 6.1: an unreachable registry must produce a classified halt."""
    check = report.add(
        Check(
            "T-6.1",
            "6.1 Fail-Closed Semantics",
            "An unreachable status source MUST halt with an incomplete_check reason "
            f"from {REASONS}",
        )
    )
    try:
        result = resolve_status()
    except Exception as exc:  # noqa: BLE001
        check.detail = f"resolver raised {exc.__class__.__name__} instead of halting"
        return check
    halted = getattr(result, "halted", None)
    if halted is None:
        check.detail = "resolver did not return a StatusResult"
        return check
    check.passed = halted is True
    check.detail = "halted as required" if check.passed else "did not halt on failure"
    return check


def run_all(
    decide: Callable[[dict], str] | None = None,
    events: list[dict] | None = None,
    reload_events: Callable[[], list[dict]] | None = None,
    resolve_status: Callable[[], object] | None = None,
) -> Report:
    """Run every check the given inputs support."""
    report = Report()
    if decide is not None:
        t_1_1(report, decide)
        t_2_1(report, decide)
        t_3_1(report, decide)
    if events is not None:
        t_4_1(report, events)
        t_4_2(report, events)
    if reload_events is not None:
        t_5_1(report, reload_events)
    if resolve_status is not None:
        t_6_1(report, resolve_status)
    return report
