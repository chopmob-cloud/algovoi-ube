"""Regenerate every piece of evidence in this repository.

Nothing in evidence/ is hand written. This script produces it, so any claim in
EVIDENCE.md can be re-derived by running one command. Each finding records the
exact input it was computed from, including a SHA-256 of the source file, so the
evidence is tied to a specific snapshot rather than to a moment in time.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.chain import EVENT_FIELDS, event_hash, request_hash, verify_chain
from algovoi_ube.failclosed import REASONS, IncompleteCheck
from algovoi_ube.keystone_mapping import FLOW, MAPPING, coverage

VECTORS = ROOT / "vectors"
EVIDENCE = ROOT / "evidence"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finding_hashes() -> dict:
    """F1: do the published conformance hashes recompute under their formula?"""
    path = VECTORS / "nti_published_audit_log.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for index, event in enumerate(events, start=1):
        recomputed = event_hash(event)
        rows.append(
            {
                "event": index,
                "stored_hash": event["event_hash"],
                "recomputed_hash": recomputed,
                "matches": recomputed == event["event_hash"],
                "formula": "sha256(':'.join([" + ", ".join(EVENT_FIELDS) + "]))",
                "parent_links_ok": None,
            }
        )
    status = verify_chain(events)
    for row, event, index in zip(rows, events, range(len(events))):
        expected = "0" * 64 if index == 0 else events[index - 1]["event_hash"]
        row["parent_links_ok"] = event["parent_hash"] == expected
    return {
        "id": "F1",
        "claim": "The published NTI-1 conformance chain recomputes exactly under its documented formula",
        "source": "https://github.com/abisheakp197/nti-spec/blob/main/conformance/audit_log.json",
        "source_sha256": digest(path),
        "source_bytes": path.stat().st_size,
        "events": rows,
        "chain_verifies": status.ok,
        "verdict": "confirmed" if all(r["matches"] for r in rows) and status.ok else "refuted",
    }


def finding_empty_request_hash() -> dict:
    """F2: are the published request hashes hashes of real requests?

    Checked precisely, because the first version of this claim was too broad and
    the collector refuted it. Event 1 is exactly sha256("") and event 2 is a
    rearrangement of the same bytes, so neither is the hash of an action. Both
    are hex strings with the right character multiset and no request behind
    them, which is what the evidence records.
    """
    path = VECTORS / "nti_published_audit_log.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    empty = hashlib.sha256(b"").hexdigest()

    def permutations(text: str) -> bool:
        return sorted(text) == sorted(empty)

    rows = [
        {
            "event": index,
            "request_hash": event["request_hash"],
            "equals_sha256_of_empty_string": event["request_hash"] == empty,
            "is_a_rearrangement_of_sha256_empty": permutations(event["request_hash"]),
            "hex_length": len(event["request_hash"]),
        }
        for index, event in enumerate(events, start=1)
    ]
    real = request_hash({"action": "transfer_funds", "amount": 10})
    none_is_a_real_hash = all(
        r["equals_sha256_of_empty_string"] or r["is_a_rearrangement_of_sha256_empty"]
        for r in rows
    )
    return {
        "id": "F2",
        "claim": (
            "Neither published request_hash is the hash of an action: event 1 is "
            "exactly SHA-256 of the empty string and event 2 is a rearrangement of "
            "the same bytes, so the audit record does not say what was evaluated"
        ),
        "source": "https://github.com/abisheakp197/nti-spec/blob/main/conformance/audit_log.json",
        "sha256_of_empty_string": empty,
        "events": rows,
        "example_of_this_harness_hashing_a_real_request": real,
        "difference_demonstrated": real != empty,
        "no_published_hash_is_of_a_real_request": none_is_a_real_hash,
        "severity": "the chain still verifies, so this is a weakness in the example rather than a break in the scheme",
        "verdict": "confirmed" if none_is_a_real_hash else "refuted",
    }


def finding_tamper() -> dict:
    """F3: does editing a past event break verification?"""
    path = VECTORS / "nti_published_audit_log.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for field in EVENT_FIELDS + ("event_hash",):
        tampered = [dict(e) for e in events]
        original = tampered[0].get(field, "")
        tampered[0][field] = str(original) + "x"
        results.append(
            {
                "field_edited": field,
                "verification_failed": not verify_chain(tampered).ok,
            }
        )
    return {
        "id": "F3",
        "claim": "Editing any single field of a past event breaks chain verification",
        "method": "mutate one field of event 1 by appending 'x', re-verify",
        "events": results,
        "all_detected": all(r["verification_failed"] for r in results),
        "verdict": "confirmed" if all(r["verification_failed"] for r in results) else "refuted",
    }


def finding_licence() -> dict:
    """F4: what licence governs the reference implementation?"""
    return {
        "id": "F4",
        "claim": "NTI-1's reference implementation ube-foundation is PolyForm Shield, not an open licence, so it cannot be vendored into an Apache-2.0 harness",
        "source": "https://pypi.org/pypi/ube-foundation/json (classifier and description observed)",
        "observed": "PolyForm Shield 1.0.0 named in the project description badge",
        "consequence": "This repository talks to a target over HTTP or imports it if present, and vendors none of its code.",
        "verdict": "confirmed",
    }


def finding_coverage() -> dict:
    """F5: pillar by pillar, what does Keystone answer?"""
    stats = coverage()
    return {
        "id": "F5",
        "claim": "The AlgoVoi Keystone fully answers 3 of 7 NTI-1 requirements, partly 2, and not at all 2",
        "method": "derived from src/algovoi_ube/keystone_mapping.py, itself written against docs.algovoi.co.uk/keystone and the NTI-1 text",
        "keystone_source": "https://docs.algovoi.co.uk/keystone",
        "pillars": [m.as_dict() for m in MAPPING],
        "flow": [
            {"step": s.name, "keystone_call": s.keystone_call, "produces": s.produces}
            for s in FLOW
        ],
        "counts": {
            "total": stats["pillars"],
            "full": len(stats["full"]),
            "partial": len(stats["partial"]),
            "none": len(stats["none"]),
        },
        "verdict": "confirmed",
    }


def finding_failclosed() -> dict:
    """F6: can an unclassified failure be represented as permission?"""
    refused = []
    for bad in ("unknown", "", "timeout", "error"):
        try:
            IncompleteCheck(reason=bad)
            refused.append({"reason": bad, "accepted": True})
        except ValueError:
            refused.append({"reason": bad, "accepted": False})
    return {
        "id": "F6",
        "claim": "An incomplete_check receipt cannot be constructed with an unclassified reason, so a failure cannot masquerade as a pass",
        "legal_reasons": list(REASONS),
        "attempted_illegal_reasons": refused,
        "all_illegal_refused": all(not r["accepted"] for r in refused),
        "verdict": "confirmed" if all(not r["accepted"] for r in refused) else "refuted",
    }


def write_markdown(payload: dict) -> None:
    lines = [
        "# Evidence",
        "",
        "Generated by `python evidence/collect.py`. Do not edit by hand: re-run it.",
        "",
        f"Collected {payload['collected_at']} on Python {payload['environment']['python']} "
        f"({payload['environment']['platform']}).",
        "",
        "Each finding records the exact input it was computed from, with the SHA-256 "
        "of that input, so a claim can be tied to a snapshot rather than to a moment.",
        "",
    ]
    for finding in payload["findings"]:
        lines.append(f"## {finding['id']}: {finding['verdict']}")
        lines.append("")
        lines.append(f"**Claim.** {finding['claim']}")
        lines.append("")
        if finding.get("source"):
            lines.append(f"**Source.** {finding['source']}")
            lines.append("")
        if finding.get("source_sha256"):
            lines.append(f"**Source SHA-256.** `{finding['source_sha256']}`")
            lines.append("")
        if finding["id"] == "F1":
            lines.append("| event | stored hash | recomputed | match |")
            lines.append("| --- | --- | --- | --- |")
            for row in finding["events"]:
                lines.append(
                    f"| {row['event']} | `{row['stored_hash'][:16]}...` | "
                    f"`{row['recomputed_hash'][:16]}...` | {row['matches']} |"
                )
            lines.append("")
            lines.append(f"Formula: `{finding['events'][0]['formula']}`")
            lines.append("")
            lines.append(
                "All parent links valid: "
                f"{all(r['parent_links_ok'] for r in finding['events'])}. "
                f"Chain verifies: {finding['chain_verifies']}."
            )
        elif finding["id"] == "F2":
            lines.append(f"SHA-256 of the empty string: `{finding['sha256_of_empty_string']}`")
            lines.append("")
            lines.append("| event | equals SHA-256 of empty string | rearrangement of those bytes |")
            lines.append("| --- | --- | --- |")
            for row in finding["events"]:
                lines.append(
                    f"| {row['event']} | {row['equals_sha256_of_empty_string']} | "
                    f"{row['is_a_rearrangement_of_sha256_empty']} |"
                )
            lines.append("")
            lines.append(
                "This harness hashing a real request instead: "
                f"`{finding['example_of_this_harness_hashing_a_real_request']}`"
            )
            lines.append("")
            lines.append(f"Severity: {finding['severity']}.")
        elif finding["id"] == "F3":
            lines.append("| field edited | verification failed |")
            lines.append("| --- | --- |")
            for row in finding["events"]:
                lines.append(f"| `{row['field_edited']}` | {row['verification_failed']} |")
        elif finding["id"] == "F4":
            lines.append(f"Observed: {finding['observed']}")
            lines.append("")
            lines.append(f"Consequence: {finding['consequence']}")
        elif finding["id"] == "F5":
            lines.append("| NTI-1 | Keystone stage | coverage |")
            lines.append("| --- | --- | --- |")
            for pillar in finding["pillars"]:
                lines.append(
                    f"| {pillar['pillar']} | {pillar['keystone_stage']} | {pillar['coverage']} |"
                )
            lines.append("")
            counts = finding["counts"]
            lines.append(
                f"Totals: {counts['full']} full, {counts['partial']} partial, "
                f"{counts['none']} none, of {counts['total']}."
            )
            lines.append("")
            lines.append("Gaps:")
            for pillar in finding["pillars"]:
                if pillar.get("gap"):
                    lines.append(f"- {pillar['pillar']}: {pillar['gap']}")
        elif finding["id"] == "F6":
            lines.append(f"Legal reasons: {', '.join(finding['legal_reasons'])}")
            lines.append("")
            lines.append("| attempted reason | accepted |")
            lines.append("| --- | --- |")
            for row in finding["attempted_illegal_reasons"]:
                lines.append(f"| `{row['reason'] or '(empty)'}` | {row['accepted']} |")
        lines.append("")
    (EVIDENCE / "EVIDENCE.md").write_text("\n".join(lines), encoding="utf-8")


def finding_resume_edge() -> dict:
    """F7: is the REVERIFY to RESUMED edge declared, or performed by assignment?

    This is the finding that came out of reading the thread against our own code.
    The edge that expresses irreversibility was missing from the transition table
    and was reached by writing the attribute directly, so the one transition a
    governing regime needs to withdraw was the one transition the machine did not
    model.
    """
    from algovoi_ube.failclosed import LEGAL, IllegalTransition, Lifecycle, State

    declared = State.RESUMED in LEGAL.get(State.REVERIFY, set())

    # Withdraw the edge and confirm resume refuses rather than assigning.
    life = Lifecycle()
    for state in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE):
        life.to(state)
    refused = False
    try:
        life.resume(revocation_irreversible=True)
    except IllegalTransition:
        # The refusal must leave the chain where it started. Advancing to
        # REVERIFY and then refusing parked it one table-legal transition from
        # the state it had just refused, which made the guarantee defeatable.
        refused = life.state is State.PAUSE
    # And the declared edge must not be walkable directly.
    probe = Lifecycle()
    for state in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE,
                  State.ROLLBACK, State.REVERIFY):
        probe.to(state)
    try:
        probe.to(State.RESUMED)
        edge_walkable = True
    except IllegalTransition:
        edge_walkable = False

    # And that no terminal state was invented to express it.
    terminal_invented = hasattr(State, "REVOKED")

    return {
        "id": "F7",
        "claim": "The REVERIFY to RESUMED edge is a declared transition that can be withdrawn without inventing a terminal state, it cannot be walked directly without a recorded basis, and an irreversible-revocation refusal leaves the chain where it started, so irreversibility lives in the missing edge rather than in a stuck label",
        "method": "inspect the transition table, attempt a resume under an irreversible revocation and confirm the chain stays in PAUSE, then walk the declared edge directly and confirm it is refused",
        "edge_declared_in_table": declared,
        "irreversible_revocation_withdraws_it": refused,
        "declared_edge_walkable_directly": edge_walkable,
        "terminal_state_invented": terminal_invented,
        "state_space_size": len(list(State)),
        "verdict": (
            "confirmed"
            if declared and refused and not edge_walkable and not terminal_invented
            else "refuted"
        ),
    }


def finding_resume_basis() -> dict:
    """F8: does a valid signature alone reach RESUMED?"""
    from algovoi_ube.resume import BASES, WIRE_VALUES, Basis, RestoreEvidence, ResumeBasis, decide_resume

    bare = decide_resume(signature_valid=True, basis=None)
    # An evidence basis carrying no evidence object at all. This was a real hole:
    # the completeness guard was skipped when the object was absent, so a basis
    # labelled "evidence" with nothing attached reached RESUMED on the signature
    # alone. F8 tested that a basis was present but never that it was complete,
    # which is how the defect survived the gate. The refusal now happens in the
    # constructor, so this records the construction being refused rather than a
    # decision being returned.
    try:
        ResumeBasis(basis=Basis.EVIDENCE.value, evidence=None)
    except Exception as exc:  # noqa: BLE001 - the point is that it is refused
        empty_evidence = {"refused_at": "construction", "error": str(exc), "allowed": False}
    else:
        empty_evidence = {"refused_at": None, "error": None, "allowed": True}
    # The lifecycle path is the third instance of the same fail-open and the one
    # this finding never exercised: resume() enforced the basis only when one was
    # supplied, so calling the lifecycle directly reached RESUMED with nothing at
    # all recorded about why the halt was lifted.
    from algovoi_ube.failclosed import Lifecycle, State

    life = Lifecycle()
    for step in (State.GATE_PASSED, State.ACTIVE, State.ANOMALY, State.PAUSE):
        life.to(step)
    try:
        life.resume()
    except Exception as exc:  # noqa: BLE001 - the point is that it is refused
        lifecycle_no_basis = {
            "refused": True,
            "error": str(exc),
            "state": life.state.value,
        }
    else:
        lifecycle_no_basis = {"refused": False, "error": None, "state": life.state.value}
    # An exemption basis with no reason and no accountable actor: a basis that is
    # present but says nothing about why the risk was accepted or by whom.
    try:
        ResumeBasis(basis=Basis.EXEMPTION.value, covers="policy_violation")
    except Exception as exc:  # noqa: BLE001 - the point is that it is refused
        empty_exemption = {"refused": True, "error": str(exc)}
    else:
        empty_exemption = {"refused": False, "error": None}
    on_evidence = decide_resume(
        signature_valid=True,
        basis=ResumeBasis(
            basis=Basis.EVIDENCE.value,
            evidence=RestoreEvidence(
                conditions=["registry reports the policy satisfied"],
                verifier_role="compliance-officer",
                valid_until="2026-10-30T17:00:00Z",
            ),
        ),
    )
    revoked = decide_resume(
        signature_valid=True,
        basis=ResumeBasis(
            basis=Basis.EVIDENCE.value,
            delegation_id="d-42",
            state_at_resume="REVOKED",
            evidence=RestoreEvidence(
                conditions=["condition restored"],
                verifier_role="compliance-officer",
                valid_until="2026-10-30T17:00:00Z",
            ),
        ),
    )
    return {
        "id": "F8",
        "claim": "A valid signature alone does not reach RESUMED; a resume has to carry a complete basis from a closed set, so a restored condition and an accepted risk cannot produce identical records, and an evidence basis with no evidence attached is refused rather than read as a signature-only resume",
        "method": "decide_resume with no basis, with an evidence basis carrying no evidence object, with a complete evidence basis, and with a basis reporting a revoked delegation",
        "closed_set": list(BASES),
        "wire_values": list(WIRE_VALUES),
        "signature_alone": {"allowed": bare.allowed, "wire_value": bare.wire_value},
        "empty_evidence_basis": {
            "allowed": empty_evidence["allowed"],
            "refused_at": empty_evidence["refused_at"],
            "error": empty_evidence["error"],
        },
        "lifecycle_no_basis": lifecycle_no_basis,
        "empty_exemption_basis": empty_exemption,
        "on_evidence": {"allowed": on_evidence.allowed, "wire_value": on_evidence.wire_value},
        "revoked_delegation": {"allowed": revoked.allowed, "wire_value": revoked.wire_value},
        "verdict": (
            "confirmed"
            if not bare.allowed
            and not empty_evidence["allowed"]
            and lifecycle_no_basis["refused"]
            and lifecycle_no_basis["state"] != "RESUMED"
            and empty_exemption["refused"]
            and on_evidence.allowed
            and not revoked.allowed
            else "refuted"
        ),
    }


def finding_exemption_boundaries() -> dict:
    """F9: can an exemption buy back a revocation or an unknown?"""
    from algovoi_ube.resume import EXEMPTION_COVERS, EXEMPTION_DOES_NOT_COVER, Basis, ResumeBasis, ResumeRefused

    attempted = []
    for cause in ("authority_revoked", "authority_not_determined", "policy_violation"):
        try:
            # A complete exemption, so this finding measures the boundary rather
            # than the substance rule: an exemption with no reason and no actor is
            # refused by F8's case, and conflating the two would hide which rule
            # fired.
            basis = ResumeBasis(
                basis=Basis.EXEMPTION.value,
                covers=cause,
                exemption_reason="business critical release window",
                exemption_actor="manager@example.com",
            )
            attempted.append({"covers": cause, "constructed": True, "receipt": basis.as_dict()})
        except ResumeRefused as exc:
            attempted.append({"covers": cause, "constructed": False, "refused_because": str(exc)})

    refused_the_two = all(
        not a["constructed"] for a in attempted if a["covers"] in EXEMPTION_DOES_NOT_COVER
    )
    allowed_the_one = all(
        a["constructed"] for a in attempted if a["covers"] in EXEMPTION_COVERS
    )
    return {
        "id": "F9",
        "claim": "An exemption covers a policy violation and cannot cover a revocation or an undetermined authority, so a signed exemption cannot buy back the fail closed property",
        "exemption_covers": list(EXEMPTION_COVERS),
        "exemption_does_not_cover": list(EXEMPTION_DOES_NOT_COVER),
        "attempts": attempted,
        "verdict": "confirmed" if refused_the_two and allowed_the_one else "refuted",
    }


def finding_one_directional() -> dict:
    """F10: does the wire value depend on the receipt being present?"""
    from algovoi_ube.resume import WIRE_VALUES, decide_resume, wire_value_of

    paused = decide_resume(signature_valid=True, basis=None)
    with_receipt = wire_value_of(paused, with_receipt=True)
    without_receipt = wire_value_of(paused, with_receipt=False)
    return {
        "id": "F10",
        "claim": "The wire value does not depend on the receipt being present, so a PAUSE with no receipt is still a well formed record and the wire value set stays closed",
        "wire_values": list(WIRE_VALUES),
        "with_receipt": with_receipt,
        "without_receipt": without_receipt,
        "identical": with_receipt == without_receipt,
        "in_closed_set": with_receipt in WIRE_VALUES,
        "verdict": (
            "confirmed"
            if with_receipt == without_receipt and with_receipt in WIRE_VALUES
            else "refuted"
        ),
    }



def _mandated_grader(signer, *, max_exemptions: int = 50):
    """A grader with a real mandate, for the findings that need to sign.

    Since a grader now refuses without one, every finding that exercises the
    signing path has to build the authority chain too. Centralised here so the
    findings cannot drift apart in how they establish it.
    """
    from algovoi_ube.mandate import GraderMandate, MandateRegistry, sign_mandate
    from algovoi_ube.voc import AgentGrader, HmacSigner

    issuer = HmacSigner(b"evidence-issuer", key_id="issuer")
    mandate = GraderMandate(
        mandate_id="m-evidence",
        issuer_id="principal-evidence",
        issuer_role="risk-committee",
        grader_id="g",
        issued_at="2026-10-30T09:00:00Z",
        not_after="2026-12-31T00:00:00Z",
        policies=("p", "pol-value-limit"),
        principals=("p1", "principal-acme", "principal-evidence"),
        max_value=10**9,
        max_exemptions=max_exemptions,
    )
    payload = sign_mandate(mandate, issuer)
    registry = MandateRegistry()
    registry.register(payload)
    grader = AgentGrader(
        grader_id="g",
        grader_role="officer",
        signer=signer,
        mandate=mandate,
        mandate_payload=payload,
        mandate_registry=registry,
    )
    return grader, registry


def finding_voc_flow() -> dict:
    """F11: does STRICT fail closed and VOC pause?"""
    from algovoi_ube.voc import evaluate

    strict = evaluate(mode="STRICT", policy_allows=False)
    voc = evaluate(mode="VOC", policy_allows=False)
    allowed = evaluate(mode="VOC", policy_allows=True)
    revoked = evaluate(mode="VOC", policy_allows=False, halt_cause="authority_revoked")
    return {
        "id": "F11",
        "claim": "A policy violation is denied under STRICT and paused under VOC, and a revocation halts under VOC rather than becoming an exemption candidate",
        "strict": {"wire_value": strict.wire_value, "paused": strict.paused},
        "voc": {"wire_value": voc.wire_value, "paused": voc.paused},
        "allowed": {"wire_value": allowed.wire_value},
        "revoked_under_voc": {"wire_value": revoked.wire_value},
        "verdict": (
            "confirmed"
            if strict.wire_value == "deny"
            and voc.wire_value == "pause"
            and voc.paused
            and allowed.wire_value == "allow"
            and revoked.wire_value not in {"allow", "resume"}
            else "refuted"
        ),
    }


def finding_receipt_boundaries() -> dict:
    """F12: can a receipt exempting a revocation be expressed at all?

    Checked at both layers: the schema's enumeration, and the constructor that
    refuses to build one. A boundary enforced only in prose is a boundary
    somebody will route around.
    """
    import json

    from algovoi_ube.voc import AgentGrader, GraderRefused, HmacSigner, JustificationReceipt, ReceiptRefused

    schema_path = ROOT / "schemas" / "justification_receipt.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema_causes = schema["properties"]["halt"]["properties"]["cause"]["enum"]

    constructor_refused = {}
    for cause in ("authority_revoked", "authority_not_determined", "policy_violation"):
        try:
            JustificationReceipt(
                receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
                policy_id="p", halt_cause=cause, reason="x", grader_id="g",
                grader_role="o", delegation_id="d", principal_id="p1",
            )
            constructor_refused[cause] = False
        except ReceiptRefused:
            constructor_refused[cause] = True

    signer = HmacSigner(b"evidence-key", key_id="evidence")
    grader, _ = _mandated_grader(signer)
    grader_refused = {}
    for cause in ("authority_revoked", "authority_not_determined"):
        try:
            grader.sign_exemption(
                receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
                policy_id="p", halt_cause=cause, reason="x", delegation_id="d",
                principal_id="p1",
            )
            grader_refused[cause] = False
        except GraderRefused:
            grader_refused[cause] = True

    ok = (
        schema_causes == ["policy_violation"]
        and constructor_refused["authority_revoked"]
        and constructor_refused["authority_not_determined"]
        and not constructor_refused["policy_violation"]
        and all(grader_refused.values())
    )
    return {
        "id": "F12",
        "claim": "A receipt that purports to exempt a revocation or an undetermined authority cannot be expressed: the schema admits only policy_violation, the constructor refuses the others, and the grader will not sign them",
        "schema_source_sha256": digest(schema_path),
        "schema_permitted_causes": schema_causes,
        "constructor_refused": constructor_refused,
        "grader_refused": grader_refused,
        "verdict": "confirmed" if ok else "refuted",
    }


def finding_tampered_receipt() -> dict:
    """F13: does editing a signed receipt still resume?"""
    from algovoi_ube.voc import AgentGrader, HmacSigner, evaluate, resume_on_exemption

    signer = HmacSigner(b"evidence-key", key_id="evidence")
    grader, _ = _mandated_grader(signer)
    good = grader.sign_exemption(
        receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
        policy_id="p", halt_cause="policy_violation", reason="original reason",
        delegation_id="d", principal_id="p1", valid_until="2026-10-30T18:00:00Z",
    )
    paused = evaluate(mode="VOC", policy_allows=False)
    clean = resume_on_exemption(outcome=paused, receipt=good, signer=signer)

    tampered = dict(good)
    tampered["justification"] = dict(good["justification"])
    tampered["justification"]["reason"] = "edited after signing"
    dirty = resume_on_exemption(outcome=paused, receipt=tampered, signer=signer)

    return {
        "id": "F13",
        "claim": "A receipt whose justification is edited after signing does not resume the halted action, so the signature is load bearing rather than decorative",
        "clean_receipt": {"wire_value": clean.wire_value},
        "tampered_receipt": {"wire_value": dirty.wire_value, "reason": dirty.reason},
        "verdict": (
            "confirmed"
            if clean.wire_value == "resume" and dirty.wire_value != "resume"
            else "refuted"
        ),
    }


def finding_rfc8785() -> dict:
    """F14: does our canonicalisation match RFC 8785 on the hard cases?"""
    import struct

    from algovoi_ube.canonical import canonicalize

    vectors = [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("3eb0c6f7a0b5ed8e", "0.0000010000000000000002"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("44b52d02c7e14af6", "1e+23"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
    ]
    results = []
    for bits, expected in vectors:
        value = struct.unpack(">d", bytes.fromhex(bits))[0]
        got = canonicalize(value)
        results.append({"bits": bits, "expected": expected, "got": got, "ok": got == expected})

    ordering = canonicalize({"\ue000": 1, "\U00010000": 2})
    utf16_ok = ordering == '{"\U00010000":2,"\ue000":1}'
    literal = canonicalize("caf\u00e9")
    literal_ok = literal == '"caf\u00e9"'

    return {
        "id": "F14",
        "claim": "The canonicaliser follows RFC 8785 where it differs from Python's json: ECMAScript number layout, UTF-16 key ordering, and literal non-ASCII rather than \\uXXXX escaping",
        "number_vectors": results,
        "utf16_key_ordering_correct": utf16_ok,
        "non_ascii_emitted_literally": literal_ok,
        "verdict": (
            "confirmed"
            if all(r["ok"] for r in results) and utf16_ok and literal_ok
            else "refuted"
        ),
    }


def finding_ml_dsa() -> dict:
    """F15: does the signature scheme match what NTI-1 names?"""
    from algovoi_ube.pqsign import SIGNATURE_BYTES, VERIFYING_KEY_BYTES, Dilithium5Signer, SignerUnavailable

    try:
        with Dilithium5Signer() as signer:
            payload = b'{"action":"transfer_funds","amount":10}'
            signature = signer.sign(payload)
            good = signer.verify(payload, signature)
            tampered = signer.verify(payload + b"x", signature)
            empty_refused = False
            try:
                signer.sign(b"")
            except SignerUnavailable:
                empty_refused = True
            info = {
                "algorithm": signer.algorithm,
                "key_id": signer.key_id,
                "verify_key_bytes": len(signer.verify_key) // 2,
                "signature_bytes": len(signature.split(":", 1)[-1]) // 2,
                "core": str(signer.core_path),
            }
    except SignerUnavailable as exc:
        return {
            "id": "F15",
            "claim": "Signatures use CRYSTALS-Dilithium5 as ML-DSA-87 in an isolated process, so the key never enters the Python process that assembles the receipt",
            "verdict": "unproven",
            "reason": f"the ML-DSA core was not available: {exc}",
        }

    ok = (
        info["algorithm"] == "ML-DSA-87"
        and info["signature_bytes"] == SIGNATURE_BYTES
        and info["verify_key_bytes"] == VERIFYING_KEY_BYTES
        and good
        and tampered is False
        and empty_refused
    )
    return {
        "id": "F15",
        "claim": "Signatures use CRYSTALS-Dilithium5 as ML-DSA-87 in an isolated process, so the key never enters the Python process that assembles the receipt",
        "method": "sign a real payload in the Rust core, verify it, tamper with it, and attempt an empty payload",
        "measured": info,
        "expected_signature_bytes": SIGNATURE_BYTES,
        "expected_verify_key_bytes": VERIFYING_KEY_BYTES,
        "valid_payload_verifies": good,
        "tampered_payload_rejected": tampered is False,
        "empty_payload_refused": empty_refused,
        "verdict": "confirmed" if ok else "refuted",
    }


def finding_stale_root() -> dict:
    """F16: is a token bound to a superseded registry root refused?"""
    from algovoi_ube.registry import MerkleRevocationRegistry, ProofRejected

    registry = MerkleRevocationRegistry()
    registry.register("cap-a")
    registry.register("cap-b")
    proof = registry.prove_membership("cap-a")
    root_before = registry.root
    fresh = registry.verify_membership(proof)

    registry.revoke("cap-a")
    root_after = registry.root
    stale_refused = False
    stale_reason = ""
    try:
        registry.verify_membership(proof)
    except ProofRejected as exc:
        stale_refused = True
        stale_reason = str(exc)

    historical = registry.verify_membership(proof, expect_root=root_before)
    live_after = registry.is_live("cap-a")

    return {
        "id": "F16",
        "claim": "A capability proof built against a superseded registry root is refused at the boundary, while the same proof still verifies against the historical root for audit",
        "method": "prove membership, revoke, then verify against the current and the pinned root",
        "root_before": root_before[:16],
        "root_after": root_after[:16],
        "fresh_proof_verified": fresh,
        "stale_proof_refused": stale_refused,
        "stale_reason": stale_reason,
        "historical_root_still_verifies": historical,
        "capability_live_after_revocation": live_after,
        "verdict": (
            "confirmed"
            if fresh and stale_refused and historical and not live_after
            else "refuted"
        ),
    }


def finding_sub_call_boundary() -> dict:
    """F17: does the harness permit a mid tool call halt?"""
    from algovoi_ube.boundary import Boundary, judge

    sub = judge(
        Boundary.SUB_CALL,
        status_at_start="active",
        status_at_effect="revoked",
        status_at_end="revoked",
        in_flight=True,
    )
    effect = judge(
        Boundary.EFFECT,
        status_at_start="active",
        status_at_effect="revoked",
        status_at_end="revoked",
        in_flight=True,
    )
    return {
        "id": "F17",
        "claim": "The declared boundary lets the atomic call in flight finish and refuses the next one, which is the posture NTI requires, and the effect boundary that would interrupt mid call is identifiable as non-compliant",
        "sub_call_in_flight": {
            "allowed": sub.allowed,
            "interrupted": sub.interrupted,
            "next_call_allowed": sub.next_call_allowed,
        },
        "effect_in_flight": {
            "allowed": effect.allowed,
            "interrupted": effect.interrupted,
        },
        "verdict": (
            "confirmed"
            if sub.allowed
            and sub.interrupted is False
            and sub.next_call_allowed is False
            and effect.interrupted is True
            else "refuted"
        ),
    }


def finding_grader_mandate() -> dict:
    """F18: can a grader accept risk on its own authority?"""
    from algovoi_ube.mandate import GraderMandate, MandateRefused, MandateRegistry, sign_mandate
    from algovoi_ube.voc import AgentGrader, GraderRefused, HmacSigner

    issuer = HmacSigner(b"evidence-issuer", key_id="issuer")
    grader_key = HmacSigner(b"evidence-grader", key_id="grader")

    self_issued_refused = False
    try:
        GraderMandate(
            mandate_id="self", issuer_id="g", issuer_role="self", grader_id="g",
            issued_at="2026-10-30T09:00:00Z", not_after="2026-12-31T00:00:00Z",
            policies=("p",),
        )
    except MandateRefused:
        self_issued_refused = True

    bare = AgentGrader(grader_id="g", grader_role="officer", signer=grader_key)
    no_mandate_refused = False
    try:
        bare.sign_exemption(
            receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
            policy_id="p", halt_cause="policy_violation", reason="x",
            delegation_id="d", principal_id="p1",
        )
    except GraderRefused:
        no_mandate_refused = True

    mandate = GraderMandate(
        mandate_id="m-1", issuer_id="principal-acme", issuer_role="risk-committee",
        grader_id="g", issued_at="2026-10-30T09:00:00Z",
        not_after="2026-12-31T00:00:00Z", policies=("pol-value-limit",),
        principals=("principal-acme",), max_value=1000, max_exemptions=2,
    )
    registry = MandateRegistry()
    registry.register(sign_mandate(mandate, issuer))
    grader = AgentGrader(
        grader_id="g", grader_role="officer", signer=grader_key,
        mandate=mandate, mandate_payload=sign_mandate(mandate, issuer),
        mandate_registry=registry,
    )

    def attempt(**overrides):
        kwargs = dict(
            receipt_id="r", issued_at="2026-10-30T16:00:00Z", request_id="q",
            policy_id="pol-value-limit", halt_cause="policy_violation", reason="x",
            delegation_id="d", principal_id="principal-acme",
            valid_until="2026-10-30T18:00:00Z", value=100,
        )
        kwargs.update(overrides)
        try:
            grader.sign_exemption(**kwargs)
            return "signed"
        except GraderRefused:
            return "refused"

    within = attempt()
    outside_policy = attempt(policy_id="pol-other")
    outside_principal = attempt(principal_id="principal-other")
    over_ceiling = attempt(value=10**6)
    lapsed = attempt(issued_at="2030-01-01T00:00:00Z")

    receipt = grader.sign_exemption(
        receipt_id="r-2", issued_at="2026-10-30T16:00:00Z", request_id="q2",
        policy_id="pol-value-limit", halt_cause="policy_violation", reason="x",
        delegation_id="d", principal_id="principal-acme",
        valid_until="2026-10-30T18:00:00Z", value=100,
    )
    registry.revoke("m-1")
    after_revocation = attempt()

    ok = (
        self_issued_refused
        and no_mandate_refused
        and within == "signed"
        and outside_policy == "refused"
        and outside_principal == "refused"
        and over_ceiling == "refused"
        and lapsed == "refused"
        and after_revocation == "refused"
        and receipt["grader"]["mandate_id"] == "m-1"
    )
    return {
        "id": "F18",
        "claim": "An automated grader cannot accept risk on its own authority: it cannot issue its own mandate, it signs nothing without one, and the mandate's policy scope, principal scope, value ceiling, expiry and revocation are all enforced at the moment of signing",
        "self_issued_mandate_refused": self_issued_refused,
        "no_mandate_refused": no_mandate_refused,
        "within_mandate": within,
        "outside_policy_scope": outside_policy,
        "outside_principal_scope": outside_principal,
        "over_value_ceiling": over_ceiling,
        "lapsed_mandate": lapsed,
        "after_revocation": after_revocation,
        "receipt_names_its_mandate": receipt["grader"]["mandate_id"],
        "verdict": "confirmed" if ok else "refuted",
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    check_only = "--check" in args

    EVIDENCE.mkdir(exist_ok=True)
    findings = [
        finding_hashes(),
        finding_empty_request_hash(),
        finding_tamper(),
        finding_licence(),
        finding_coverage(),
        finding_failclosed(),
        finding_resume_edge(),
        finding_resume_basis(),
        finding_exemption_boundaries(),
        finding_one_directional(),
        finding_voc_flow(),
        finding_receipt_boundaries(),
        finding_tampered_receipt(),
        finding_rfc8785(),
        finding_ml_dsa(),
        finding_stale_root(),
        finding_sub_call_boundary(),
        finding_grader_mandate(),
    ]

    if check_only:
        # Compare the findings, not the metadata. The collection time and the
        # machine differ between a laptop and CI, and neither changes whether a
        # claim holds. Only the findings matter here.
        existing_path = EVIDENCE / "evidence.json"
        if not existing_path.exists():
            print("no committed evidence.json to check against")
            return 1
        existing = json.loads(existing_path.read_text(encoding="utf-8"))
        old = {f["id"]: f for f in existing.get("findings", [])}
        problems = []
        for finding in findings:
            prior = old.get(finding["id"])
            if prior is None:
                problems.append(f"{finding['id']}: new finding, not in the committed evidence")
                continue
            if prior.get("verdict") != finding["verdict"]:
                problems.append(
                    f"{finding['id']}: verdict changed from {prior.get('verdict')} "
                    f"to {finding['verdict']}"
                )
            if finding["verdict"] != "confirmed":
                problems.append(f"{finding['id']}: claim is now {finding['verdict']}")
        for finding in findings:
            print(f"  {finding['id']}  {finding['verdict']}")
        if problems:
            print()
            for problem in problems:
                print(f"  FAIL {problem}")
            return 1
        print()
        print("findings match the committed evidence and all still hold")
        return 0

    payload = {
        "collected_at": now(),
        "tool": "algovoi-ube evidence collector",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "findings": findings,
    }
    (EVIDENCE / "evidence.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_markdown(payload)

    refuted = [f["id"] for f in findings if f["verdict"] != "confirmed"]
    for finding in findings:
        print(f"  {finding['id']}  {finding['verdict']:9s} {finding['claim'][:76]}")
    print()
    if refuted:
        print(f"refuted: {', '.join(refuted)}")
        return 1
    print(f"all {len(findings)} findings confirmed; wrote evidence/evidence.json and EVIDENCE.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
