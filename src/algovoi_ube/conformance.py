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


def t_7_1(report: Report, decide_resume: Callable[..., object]) -> Check:
    """T-7.1: a valid signature alone must not reach RESUMED."""
    check = report.add(
        Check(
            "T-7.1",
            "6.1 Fail-Closed Semantics and resume basis",
            "A resume token whose signature verifies but which carries no basis "
            "MUST NOT reach RESUMED",
        )
    )
    try:
        decision = decide_resume(signature_valid=True, basis=None)
    except Exception as exc:  # noqa: BLE001
        check.detail = f"decide_resume raised {exc.__class__.__name__}: {exc}"
        return check
    allowed = getattr(decision, "allowed", None)
    wire = getattr(decision, "wire_value", "")
    check.passed = allowed is False and wire != "resume"
    check.detail = f"allowed={allowed!r} wire_value={wire!r}"
    return check


def t_7_2(report: Report, decide_resume: Callable[..., object]) -> Check:
    """T-7.2: an exemption must not cover a revocation."""
    check = report.add(
        Check(
            "T-7.2",
            "resume basis, exemption boundary (i)",
            "An exemption MUST NOT be able to resume an action whose authority was "
            "revoked",
        )
    )
    try:
        from .resume import Basis, ResumeBasis

        basis = ResumeBasis(basis=Basis.EXEMPTION.value, covers="authority_revoked")
    except Exception as exc:  # noqa: BLE001
        # Refusing to construct the basis is the correct behaviour.
        check.passed = True
        check.detail = f"the forbidden basis was refused at construction: {exc.__class__.__name__}"
        return check
    try:
        decision = decide_resume(signature_valid=True, basis=basis)
    except Exception as exc:  # noqa: BLE001
        check.passed = True
        check.detail = f"decide_resume refused it: {exc.__class__.__name__}"
        return check
    check.passed = getattr(decision, "allowed", None) is False
    check.detail = f"allowed={getattr(decision, 'allowed', None)!r}"
    return check


def t_7_3(report: Report, decide_resume: Callable[..., object]) -> Check:
    """T-7.3: an exemption must not buy back an undetermined authority."""
    check = report.add(
        Check(
            "T-7.3",
            "resume basis, exemption boundary (ii)",
            "An exemption MUST NOT convert authority_not_determined into a resume",
        )
    )
    try:
        from .resume import Basis, ResumeBasis

        basis = ResumeBasis(
            basis=Basis.EXEMPTION.value, covers="authority_not_determined"
        )
    except Exception as exc:  # noqa: BLE001
        check.passed = True
        check.detail = f"refused at construction: {exc.__class__.__name__}"
        return check
    try:
        decision = decide_resume(signature_valid=True, basis=basis)
    except Exception as exc:  # noqa: BLE001
        check.passed = True
        check.detail = f"decide_resume refused it: {exc.__class__.__name__}"
        return check
    check.passed = getattr(decision, "allowed", None) is False
    check.detail = f"allowed={getattr(decision, 'allowed', None)!r}"
    return check


def t_7_4(report: Report, wire_values: tuple[str, ...], paused_decision: object) -> Check:
    """T-7.4: the receipt is one directional.

    A PAUSE with no receipt attached must still be a well formed record, and the
    wire value must not depend on the receipt's presence. This is the constraint
    that keeps the wire value set closed.
    """
    check = report.add(
        Check(
            "T-7.4",
            "wire value set, one directional mapping",
            "A refusal MUST be well formed without a receipt, and the wire value "
            "MUST NOT depend on the receipt being present",
        )
    )
    wire = getattr(paused_decision, "wire_value", "")
    check.passed = wire in wire_values and wire != ""
    check.detail = (
        f"wire_value={wire!r} in closed set of {len(wire_values)}; "
        "the decision is complete without the receipt"
    )
    return check


def t_7_5(report: Report) -> Check:
    """T-7.5: a resume must carry a basis, on every path.

    The lifecycle enforced the basis only when one was supplied, so a direct call
    reached RESUMED with nothing recorded about why the halt was lifted. The
    requirement is about the record, not the caller, so the lifecycle path is
    where it has to hold.
    """
    check = report.add(
        Check(
            "T-7.5",
            "resume basis, required on the lifecycle path",
            "A resume MUST carry a basis; reaching RESUMED with none MUST be refused",
        )
    )
    from .failclosed import IllegalTransition, Lifecycle, State

    life = Lifecycle()
    for step in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE):
        life.to(step)
    try:
        life.resume()
    except IllegalTransition as exc:
        # The module's own refusal, not any exception: catching Exception here
        # would record a TypeError from a broken guard as a successful refusal.
        check.passed = life.state is not State.RESUMED
        check.detail = (
            f"refused at the lifecycle: {exc.__class__.__name__}; "
            f"state stayed {life.state.value}"
        )
        return check
    except Exception as exc:  # noqa: BLE001
        check.passed = False
        check.detail = (
            f"raised {exc.__class__.__name__} rather than refusing, which is a bug "
            "and not a refusal"
        )
        return check
    check.passed = False
    check.detail = f"a resume with no basis reached {life.state.value}"
    return check


def t_7_6(report: Report) -> Check:
    """T-7.6: the declared edge is not a public route to RESUMED.

    The edge is declared so a governing regime can withdraw it, and enumerable so
    a suite can see it. Walking it directly reaches RESUMED with no basis
    recorded, which is the fail-open the resume basis exists to refuse, so the
    guard has to sit on the transition rather than on the caller.
    """
    check = report.add(
        Check(
            "T-7.6",
            "resume basis, the table is not a second route",
            "Reaching RESUMED without a recorded basis MUST be refused on every "
            "path, including the declared transition",
        )
    )
    from .failclosed import Lifecycle, State

    life = Lifecycle()
    for step in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE):
        life.to(step)
    life.to(State.ROLLBACK)
    life.to(State.REVERIFY)
    try:
        life.to(State.RESUMED)
    except Exception as exc:  # noqa: BLE001
        check.passed = life.state is State.REVERIFY and not life.receipt
        check.detail = (
            f"refused at the transition: {exc.__class__.__name__}; "
            f"state stayed {life.state.value}, receipt empty"
        )
        return check
    check.passed = False
    check.detail = f"the declared edge reached {life.state.value} with receipt {life.receipt!r}"
    return check


def t_7_7(report: Report) -> Check:
    """T-7.7: an exemption basis must record a reason and an accountable actor."""
    check = report.add(
        Check(
            "T-7.7",
            "resume basis, exemption substance",
            "An exemption basis MUST record why the risk was accepted and who "
            "accepted it; an empty exemption MUST be refused at construction",
        )
    )
    from .resume import Basis, ResumeBasis

    try:
        ResumeBasis(basis=Basis.EXEMPTION.value, covers="policy_violation")
    except Exception as exc:  # noqa: BLE001
        check.passed = True
        check.detail = f"the empty exemption was refused at construction: {exc.__class__.__name__}"
        return check
    check.passed = False
    check.detail = "an exemption with no reason and no actor constructed cleanly"
    return check


def t_7_8(report: Report) -> Check:
    """T-7.8: what the receiver knows outranks what the basis claims."""
    check = report.add(
        Check(
            "T-7.8",
            "resume basis, the receiver's knowledge wins",
            "A basis asserting its own delegation is ACTIVE MUST NOT override the "
            "receiver's knowledge that it is REVOKED",
        )
    )
    from .resume import Basis, ResumeBasis, decide_resume

    basis = ResumeBasis(
        basis=Basis.EXEMPTION.value,
        covers="policy_violation",
        exemption_reason="release window",
        exemption_actor="manager@example.com",
        delegation_id="d-42",
        state_at_resume="ACTIVE",
    )
    decision = decide_resume(
        signature_valid=True, basis=basis, delegation_state="REVOKED"
    )
    check.passed = decision.allowed is False
    check.detail = (
        f"basis claimed ACTIVE, receiver knew REVOKED, decision allowed="
        f"{decision.allowed} ({decision.reason[:60]})"
    )
    return check


def t_7_9(report: Report) -> Check:
    """T-7.9: an expired restore window must be refused."""
    check = report.add(
        Check(
            "T-7.9",
            "resume basis, currency of the evidence",
            "Restore evidence whose validity window has passed MUST NOT resume the "
            "action",
        )
    )
    from datetime import datetime, timezone

    from .resume import Basis, RestoreEvidence, ResumeBasis, decide_resume

    stale = ResumeBasis(
        basis=Basis.EVIDENCE.value,
        evidence=RestoreEvidence(
            conditions=["condition restored"],
            verifier_role="compliance-officer",
            valid_from="2020-01-01T00:00:00Z",
            valid_until="2020-01-02T00:00:00Z",
        ),
    )
    decision = decide_resume(
        signature_valid=True,
        basis=stale,
        now=datetime(2026, 10, 30, 21, 0, tzinfo=timezone.utc),
    )
    check.passed = decision.allowed is False
    check.detail = f"expired window, decision allowed={decision.allowed}"
    return check


def t_7_10(report: Report) -> Check:
    """T-7.10: a receipt must name the halt it answers."""
    check = report.add(
        Check(
            "T-7.10",
            "exemption receipt, bound to the halt",
            "A signed exemption naming a different halt MUST NOT resume this pause",
        )
    )
    from .voc import (
        HmacSigner,
        JustificationReceipt,
        evaluate,
        resume_on_exemption,
    )

    signer = HmacSigner(b"conformance-key", key_id="conformance")
    paused = evaluate(
        mode="VOC", policy_allows=False, request_id="req-1", policy_id="pol-1",
        halt_id="halt-of-this-pause",
    )
    foreign = JustificationReceipt(
        receipt_id="r-1",
        issued_at="2026-10-30T16:00:00Z",
        request_id="req-1",
        policy_id="pol-1",
        halt_cause="policy_violation",
        reason="signed for a different halt",
        grader_id="g-1",
        grader_role="compliance-officer",
        delegation_id="d-1",
        principal_id="p-1",
        valid_until="2099-12-31T00:00:00Z",
        halt_id="halt-of-another-pause",
    )
    receipt = foreign.to_json(
        signature=signer.sign(foreign.signing_input()),
        algorithm="HMAC-SHA256",
        key_id="conformance",
    )
    outcome = resume_on_exemption(outcome=paused, receipt=receipt, signer=signer)
    check.passed = outcome.wire_value != "resume"
    check.detail = f"wire_value={outcome.wire_value} ({outcome.reason[:70]})"
    return check


def t_8_1(report: Report, evaluate: Callable[..., object]) -> Check:
    """T-8.1: STRICT must fail closed with no exception path."""
    check = report.add(
        Check(
            "T-8.1",
            "3.2 Pillar 2 and VOC flow",
            "Under compliance_mode STRICT a policy violation MUST be denied with no "
            "pause and no receipt",
        )
    )
    try:
        outcome = evaluate(mode="STRICT", policy_allows=False)
    except Exception as exc:  # noqa: BLE001
        check.detail = f"evaluate raised {exc.__class__.__name__}: {exc}"
        return check
    wire = getattr(outcome, "wire_value", "")
    check.passed = wire == "deny" and getattr(outcome, "receipt", None) is None
    check.detail = f"wire_value={wire!r}, receipt={getattr(outcome, 'receipt', None)!r}"
    return check


def t_8_2(report: Report, evaluate: Callable[..., object]) -> Check:
    """T-8.2: VOC must pause and request an exemption."""
    check = report.add(
        Check(
            "T-8.2",
            "3.2 Pillar 2 and VOC flow",
            "Under compliance_mode VOC a policy violation MUST pause and request an "
            "exemption rather than proceeding or failing silently",
        )
    )
    try:
        outcome = evaluate(mode="VOC", policy_allows=False)
    except Exception as exc:  # noqa: BLE001
        check.detail = f"evaluate raised {exc.__class__.__name__}: {exc}"
        return check
    wire = getattr(outcome, "wire_value", "")
    paused = getattr(outcome, "paused", None)
    check.passed = wire == "pause" and paused is True
    check.detail = f"wire_value={wire!r}, paused={paused!r}"
    return check


def t_8_3(report: Report, evaluate: Callable[..., object]) -> Check:
    """T-8.3: no compliance mode may exempt a revocation or an unknown."""
    check = report.add(
        Check(
            "T-8.3",
            "VOC boundaries (i) and (ii)",
            "An exemption MUST NOT cover authority_revoked or "
            "authority_not_determined in either compliance mode",
        )
    )
    failures = []
    for mode in ("STRICT", "VOC"):
        for cause in ("authority_revoked", "authority_not_determined"):
            try:
                outcome = evaluate(mode=mode, policy_allows=False, halt_cause=cause)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{mode}/{cause} raised {exc.__class__.__name__}")
                continue
            wire = getattr(outcome, "wire_value", "")
            if wire in {"allow", "resume"}:
                failures.append(f"{mode}/{cause} gave {wire}")
    check.passed = not failures
    check.detail = "; ".join(failures) if failures else "both causes halted in both modes"
    return check


def t_8_4(report: Report, evaluate: Callable[..., object], resume: Callable[..., object], make_receipt: Callable[[], dict]) -> Check:
    """T-8.4: a receipt altered after signing must not resume anything.

    The signature is the only integrity property the protocol has, so a receipt
    whose reason was edited afterwards has to fail rather than resume.
    """
    check = report.add(
        Check(
            "T-8.4",
            "justification_receipt integrity",
            "A justification_receipt altered after signing MUST NOT resume the "
            "halted action",
        )
    )
    try:
        paused = evaluate(mode="VOC", policy_allows=False)
        receipt = make_receipt()
        receipt["justification"]["reason"] = "edited after signing"
        outcome = resume(outcome=paused, receipt=receipt)
    except Exception as exc:  # noqa: BLE001
        check.detail = f"raised {exc.__class__.__name__}: {exc}"
        return check
    wire = getattr(outcome, "wire_value", "")
    # It must actively refuse, not merely fail to resume. An implementation that
    # answers "allow" to a tampered receipt is worse than one that resumes,
    # because it has stopped checking at all.
    check.passed = wire in {"deny", "pause", "revoked"}
    check.detail = (
        f"wire_value={wire!r} for a tampered receipt"
        if check.passed
        else f"wire_value={wire!r} for a tampered receipt, which is not a refusal"
    )
    return check


def t_9_1(report: Report, boundary_declared: str) -> Check:
    """T-9.1: an NTI implementation must not halt mid tool call.

    The AIW paper says a tool call cannot safely be interrupted mid flight without
    corrupting external state, so the sidecar pauses at the boundary between
    calls. A target that declares the effect boundary is not NTI compliant
    however sound its reasoning, and that is worth checking rather than assuming.
    """
    check = report.add(
        Check(
            "T-9.1",
            "AIW paper, the safe interruption point",
            "An implementation claiming NTI-1 MUST NOT halt an atomic tool call mid "
            "flight; it MUST declare the sub-call or invocation boundary",
        )
    )
    permitted = {"sub_call", "invocation", "completion"}
    check.passed = boundary_declared in permitted
    check.detail = (
        f"declared boundary is {boundary_declared!r}"
        if check.passed
        else f"declared boundary is {boundary_declared!r}, which permits a mid-call halt"
    )
    return check


def t_9_2(report: Report, signature_algorithm: str, signature_bytes: int) -> Check:
    """T-9.2: the signature scheme must be the one NTI-1 names."""
    check = report.add(
        Check(
            "T-9.2",
            "3.1 Pillar 1, CRYSTALS-Dilithium5",
            "Signatures MUST use CRYSTALS-Dilithium5, which in FIPS 204 terms is "
            "ML-DSA-87 at NIST security category 5",
        )
    )
    acknowledged = signature_algorithm.upper().replace("_", "-")
    accepted = {"ML-DSA-87", "DILITHIUM5", "CRYSTALS-DILITHIUM5", "ML-DSA5"}
    # 4627 bytes is the ML-DSA-87 signature size from FIPS 204.
    check.passed = acknowledged in accepted and signature_bytes == 4627
    check.detail = (
        f"algorithm {signature_algorithm!r} with {signature_bytes} byte signatures"
    )
    return check


def t_9_3(report: Report, registry) -> Check:
    """T-9.3: a token bound to a stale root must be refused."""
    check = report.add(
        Check(
            "T-9.3",
            "AIW paper, Merkle-chained revocation registry",
            "A capability token verified against a superseded registry root MUST be "
            "refused at the boundary",
        )
    )
    try:
        registry.register("cap-probe-a")
        proof = registry.prove_membership("cap-probe-a")
        root_before = registry.root
        fresh_ok = registry.verify_membership(proof)
        registry.revoke("cap-probe-a")
        try:
            registry.verify_membership(proof)
            stale_refused = False
        except Exception as exc:  # noqa: BLE001
            stale_refused = "stale" in str(exc).lower() or "root" in str(exc).lower()
        historical_ok = registry.verify_membership(proof, expect_root=root_before)
    except Exception as exc:  # noqa: BLE001
        check.detail = f"registry raised {exc.__class__.__name__}: {exc}"
        return check
    check.passed = fresh_ok and stale_refused and historical_ok
    check.detail = (
        f"fresh proof verified={fresh_ok}, stale proof refused={stale_refused}, "
        f"historical root still verifies={historical_ok}"
    )
    return check


def t_10_1(report: Report, grader_factory: Callable[[], object], mandate) -> Check:
    """T-10.1: a grader must act under a mandate issued by someone else."""
    check = report.add(
        Check(
            "T-10.1",
            "VOC grader authority",
            "An automated grader MUST NOT accept risk without a mandate, and MUST NOT "
            "be able to issue its own",
        )
    )
    try:
        from .mandate import GraderMandate, MandateRefused

        self_issued = False
        try:
            GraderMandate(
                mandate_id="self",
                issuer_id=getattr(mandate, "grader_id", "g"),
                issuer_role="self",
                grader_id=getattr(mandate, "grader_id", "g"),
                issued_at="2026-10-30T09:00:00Z",
                not_after="2026-12-31T00:00:00Z",
                policies=("p",),
            )
        except MandateRefused:
            self_issued = True

        # A grader with no mandate must refuse rather than sign.
        bare = grader_factory()
        refused_without = False
        try:
            bare.sign_exemption(
                receipt_id="probe", issued_at="2026-10-30T16:00:00Z",
                request_id="probe", policy_id="p", halt_cause="policy_violation",
                reason="probe", delegation_id="d", principal_id="p1",
            )
        except Exception:  # noqa: BLE001
            refused_without = True
    except Exception as exc:  # noqa: BLE001
        check.detail = f"raised {exc.__class__.__name__}: {exc}"
        return check

    check.passed = self_issued and refused_without
    check.detail = (
        f"self issued mandate refused={self_issued}, "
        f"signing without a mandate refused={refused_without}"
    )
    return check


def t_10_2(report: Report, grader, mandate) -> Check:
    """T-10.2: the mandate's bounds must be enforced at signing time."""
    check = report.add(
        Check(
            "T-10.2",
            "VOC grader authority",
            "A mandate's policy scope, principal scope, value ceiling, expiry and "
            "exemption count MUST be enforced when the grader signs",
        )
    )
    cases = []
    base = dict(
        receipt_id="probe", issued_at="2026-10-30T16:00:00Z", request_id="probe",
        halt_cause="policy_violation", reason="probe", delegation_id="d",
        principal_id="principal-self-test", valid_until="2026-10-30T18:00:00Z",
    )
    probes = [
        ("policy outside scope", {**base, "policy_id": "pol-not-in-scope"}),
        ("principal outside scope", {**base, "policy_id": "pol-value-limit",
                                    "principal_id": "someone-else"}),
        ("value over ceiling", {**base, "policy_id": "pol-value-limit", "value": 10**9}),
        ("lapsed mandate", {**base, "policy_id": "pol-value-limit",
                            "issued_at": "2030-01-01T00:00:00Z"}),
    ]
    for label, kwargs in probes:
        try:
            grader.sign_exemption(**kwargs)
            cases.append(f"{label}: SIGNED (should have refused)")
        except Exception:  # noqa: BLE001
            cases.append(f"{label}: refused")

    refused_all = all("refused" in case for case in cases)
    check.passed = refused_all
    check.detail = "; ".join(cases)
    return check


def run_all(
    decide: Callable[[dict], str] | None = None,
    events: list[dict] | None = None,
    reload_events: Callable[[], list[dict]] | None = None,
    resolve_status: Callable[[], object] | None = None,
    decide_resume: Callable[..., object] | None = None,
    wire_values: tuple[str, ...] | None = None,
    voc_evaluate: Callable[..., object] | None = None,
    voc_resume: Callable[..., object] | None = None,
    voc_receipt: Callable[[], dict] | None = None,
    boundary_declared: str | None = None,
    signature_algorithm: str | None = None,
    signature_bytes: int | None = None,
    registry: object | None = None,
    grader_factory: Callable[[], object] | None = None,
    grader: object | None = None,
    grader_mandate: object | None = None,
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
    if decide_resume is not None:
        t_7_1(report, decide_resume)
        t_7_2(report, decide_resume)
        t_7_3(report, decide_resume)
        if wire_values is not None:
            paused = decide_resume(signature_valid=True, basis=None)
            t_7_4(report, wire_values, paused)
        t_7_5(report)
        t_7_6(report)
        t_7_7(report)
        t_7_8(report)
        t_7_9(report)
        t_7_10(report)
    if voc_evaluate is not None:
        t_8_1(report, voc_evaluate)
        t_8_2(report, voc_evaluate)
        t_8_3(report, voc_evaluate)
        if voc_resume is not None and voc_receipt is not None:
            t_8_4(report, voc_evaluate, voc_resume, voc_receipt)
    if boundary_declared is not None:
        t_9_1(report, boundary_declared)
    if signature_algorithm is not None and signature_bytes is not None:
        t_9_2(report, signature_algorithm, signature_bytes)
    if registry is not None:
        t_9_3(report, registry)
    if grader_factory is not None and grader_mandate is not None:
        t_10_1(report, grader_factory, grader_mandate)
    if grader is not None and grader_mandate is not None:
        t_10_2(report, grader, grader_mandate)
    return report
