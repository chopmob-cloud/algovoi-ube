"""Keystone as the fulfilment path for the NTI-1 process flow.

Exploration, not advocacy. This module states, pillar by pillar, what NTI-1
requires, which Keystone reference answers it, and what is left over. Where
Keystone does not cover a clause, it says so rather than stretching the mapping.

The two chains are not the same shape, and that is the useful finding:

    NTI-1       identity -> policy -> (BFT consensus) -> audit chain -> persist
    Keystone    passport -> mandate -> policy_bound -> decision -> execution -> trust_query

NTI's audit chain is a single append-only event log. Keystone's is a chain of
content-addressed references where each link hashes the one before it, so a
decision cannot be re-attributed and an execution cannot be claimed by another
decision. Keystone is strictly stronger evidence per action and weaker at
multi-agent consensus, which NTI states as a MUST for high-value actions.

Every claim below is checkable against docs.algovoi.co.uk/keystone and the
NTI-1 text; nothing here is asserted from memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PillarMap:
    ident: str
    requirement: str
    keystone_stage: str
    coverage: str  # full, partial, none
    note: str = ""
    gap: str = ""

    def as_dict(self) -> dict:
        return {
            "pillar": self.ident,
            "nti_requirement": self.requirement,
            "keystone_stage": self.keystone_stage,
            "coverage": self.coverage,
            "note": self.note,
            "gap": self.gap,
        }


MAPPING: tuple[PillarMap, ...] = (
    PillarMap(
        "3.1",
        "Principal-bound identity; actions signed by a key delegated by the principal",
        "passport_ref",
        "full",
        "The Agent Passport is the identity tier of the keystone chain, and the "
        "passport_ref is a load-bearing field of every downstream reference, so "
        "identity is bound into the decision rather than attached to it.",
    ),
    PillarMap(
        "3.2",
        "Every action evaluated against policy; capability caveats Expires, "
        "MaxExecutions, ValueLimit, PathRestricted; deny must not execute",
        "mandate_ref, policy_bound_ref",
        "full",
        "The mandate is authority and the policy binding fixes the policy in "
        "force. Because policy_bound_ref is hashed into decision_ref, an action "
        "cannot be authorised under one policy and executed under another.",
    ),
    PillarMap(
        "3.3",
        "BFT consensus for high-value multi-agent actions; threshold signature "
        "collection over (voter_id, request_id, decision, outcome_hash, signature)",
        "none",
        "none",
        "Keystone composes one chain per action and does not define a voting or "
        "threshold protocol. This is the one pillar it does not answer.",
        gap=(
            "Needs a threshold signature layer above the keystone: collect votes "
            "over the decision_ref, then require the threshold before the "
            "execution tier is reached."
        ),
    ),
    PillarMap(
        "3.4",
        "Tamper-evident audit trail, SHA-256 chained, every evaluated action "
        "recorded with decision and reason",
        "decision_ref, execution_ref",
        "full",
        "decision_ref records what was authorised and execution_ref records what "
        "actually happened and binds back to that decision. A verifier can "
        "confirm the executed action is consistent with the decision rather than "
        "merely correlated with it.",
    ),
    PillarMap(
        "3.5",
        "State and audit trail persist across restarts with self-verifying "
        "integrity; exportable and importable",
        "keystone chain plus trust_query_ref",
        "partial",
        "The chain is content-addressed, so reloading it re-verifies every link "
        "by recomputation with no issuer contact. Keystone does not itself "
        "define a persistence store or an export format.",
        gap="Needs a store of record and an export envelope; the chain verifies "
        "independently once landed.",
    ),
    PillarMap(
        "6.1",
        "Fail-closed on unreachable or non-authoritative registry; incomplete_check "
        "with reason tryLater, not_authoritative or internal_error",
        "none",
        "partial",
        "Keystone provides the *evidence* that authority lapsed, because the "
        "mandate and revocation state carry their own references and validity "
        "windows. It does not define the runtime halt behaviour.",
        gap=(
            "The halt is a runtime decision, which this repo implements. The "
            "clean split is: Keystone proves the state, the sidecar acts on it."
        ),
    ),
    PillarMap(
        "7",
        "Interoperability with the ASL Conformance Kit over AF_UNIX sockets",
        "none",
        "none",
        "Keystone is transport-agnostic and says nothing about sandboxing.",
        gap="Unchanged by any keystone decision; this is an adapter concern.",
    ),
)


@dataclass
class FlowStep:
    """One step of the NTI process flow, and how Keystone fulfils it."""

    name: str
    nti_action: str
    keystone_call: str
    produces: str


FLOW: tuple[FlowStep, ...] = (
    FlowStep(
        "identity",
        "Establish the principal-bound identity of the agent",
        "passport_ref from the Agent Passport tier",
        "passport_ref",
    ),
    FlowStep(
        "authority",
        "Record what the agent may spend or do",
        "mandate_ref from the Payment Mandate tier",
        "mandate_ref",
    ),
    FlowStep(
        "policy",
        "Fix the policy in force for this action",
        "policy_bound_ref from the Policy Binding tier",
        "policy_bound_ref",
    ),
    FlowStep(
        "consensus",
        "Collect the BFT threshold for a high-value action",
        "not in Keystone; a threshold signing layer over decision_ref",
        "vote set (external)",
    ),
    FlowStep(
        "decision",
        "The pre-action decision, ALLOW or DENY",
        "build_keystone(verdict=...) produces decision_ref",
        "decision_ref",
    ),
    FlowStep(
        "execution",
        "What the agent actually did, bound to the decision",
        "build_keystone(outcome=...) produces execution_ref",
        "execution_ref",
    ),
    FlowStep(
        "verdict",
        "One verdict over the whole ordered chain",
        "trust_query_ref",
        "trust_query_ref",
    ),
)


def coverage() -> dict:
    """How much of NTI-1 Keystone answers, counted rather than claimed."""
    full = [m for m in MAPPING if m.coverage == "full"]
    partial = [m for m in MAPPING if m.coverage == "partial"]
    none = [m for m in MAPPING if m.coverage == "none"]
    return {
        "pillars": len(MAPPING),
        "full": [m.ident for m in full],
        "partial": [m.ident for m in partial],
        "none": [m.ident for m in none],
        "gaps": [m.gap for m in MAPPING if m.gap],
    }


def report() -> str:
    lines = ["NTI-1 against the AlgoVoi Keystone", ""]
    for m in MAPPING:
        mark = {"full": "yes", "partial": "partly", "none": "no"}[m.coverage]
        lines.append(f"{m.ident:5s} {mark:7s} {m.keystone_stage}")
        if m.note:
            lines.append(f"      {m.note}")
        if m.gap:
            lines.append(f"      gap: {m.gap}")
    stats = coverage()
    lines.append("")
    lines.append(
        f"{len(stats['full'])} of {stats['pillars']} pillars fully answered, "
        f"{len(stats['partial'])} partly, {len(stats['none'])} not at all."
    )
    return "\n".join(lines)
