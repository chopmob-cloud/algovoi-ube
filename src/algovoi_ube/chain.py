"""Hash and chain primitives.

The audit chain follows the NTI-1 conformance example exactly, because a
conformance harness has to recompute what the implementation stored rather than
invent its own scheme. The scheme is:

    event_hash = sha256(":".join([event_id, agent_id, request_hash, decision,
                                  reason, timestamp, parent_hash]))

Fields are joined in that fixed order. The parent of the first event is 64
zeros. Everything here is stdlib, so the harness runs anywhere Python does.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# The field order is part of the wire format, not an implementation detail.
EVENT_FIELDS = (
    "event_id",
    "agent_id",
    "request_hash",
    "decision",
    "reason",
    "timestamp",
    "parent_hash",
)

GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    """A stable serialisation for hashing request payloads."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_hash(payload: Any) -> str:
    """Hash the request itself.

    Hashing an empty string, as the published conformance example does, makes
    the audit record say nothing about which action was evaluated. This hashes
    the canonical form of the actual request.
    """
    if isinstance(payload, (bytes, bytearray)):
        return sha256_bytes(bytes(payload))
    if isinstance(payload, str):
        # A bare string is hashed as its canonical JSON, so an empty payload is
        # distinguishable from "the empty string was the request".
        return sha256_text(canonical_json(payload))
    return sha256_text(canonical_json(payload))


def event_hash(event: dict) -> str:
    """Recompute the hash of an audit event, in the documented field order."""
    missing = [f for f in EVENT_FIELDS if f not in event]
    if missing:
        raise ValueError(f"event missing fields: {', '.join(missing)}")
    payload = ":".join(str(event[f]) for f in EVENT_FIELDS)
    return sha256_text(payload)


@dataclass
class AuditEvent:
    event_id: str
    agent_id: str
    request_hash: str
    decision: str
    reason: str
    timestamp: str
    parent_hash: str = GENESIS
    event_hash: str = ""

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "request_hash": self.request_hash,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "parent_hash": self.parent_hash,
            "event_hash": self.event_hash,
        }


@dataclass
class ChainStatus:
    ok: bool
    length: int = 0
    first_broken: int | None = None
    reasons: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            return f"chain intact, {self.length} event(s)"
        where = f" at event {self.first_broken}" if self.first_broken is not None else ""
        return f"chain broken{where}: " + "; ".join(self.reasons[:3])


def verify_chain(events: list[dict]) -> ChainStatus:
    """Recompute every hash and every parent link.

    Tampering with any past event must fail here: either its own hash no longer
    matches, or the next event's parent no longer matches its predecessor.
    """
    if not events:
        return ChainStatus(ok=True, length=0)

    reasons: list[str] = []
    previous = GENESIS
    for index, event in enumerate(events, start=1):
        try:
            recomputed = event_hash(event)
        except ValueError as exc:
            return ChainStatus(
                ok=False, length=len(events), first_broken=index, reasons=[str(exc)]
            )
        if recomputed != event.get("event_hash"):
            return ChainStatus(
                ok=False,
                length=len(events),
                first_broken=index,
                reasons=[f"event {index} hash does not match its contents"],
            )
        if event.get("parent_hash") != previous:
            return ChainStatus(
                ok=False,
                length=len(events),
                first_broken=index,
                reasons=[f"event {index} does not link to its predecessor"],
            )
        previous = recomputed
    if len(reasons) == 0:
        return ChainStatus(ok=True, length=len(events))
    return ChainStatus(ok=False, length=len(events), reasons=reasons)
