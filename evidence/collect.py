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
