"""AuditNode, VoteRecord, ResumeReceipt -- NTI-1 Pillars 3 and 4."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ResumeBasis(str, Enum):
    EVIDENCE = "evidence"
    EXEMPTION = "exemption"


EXEMPTION_COVERS = "policy_violation"
EXEMPTION_DOES_NOT_COVER = frozenset({"authority_revoked", "authority_not_determined"})


@dataclass
class ResumeReceipt:
    agent_id: str
    request_id: str
    resume_basis: ResumeBasis
    reason: str = ""
    exemption_covers: str = ""
    signature_hex: str = ""

    def __post_init__(self) -> None:
        if self.resume_basis == ResumeBasis.EXEMPTION:
            if not self.exemption_covers:
                raise ValueError("exemption resume_basis requires exemption_covers")
            if self.exemption_covers in EXEMPTION_DOES_NOT_COVER:
                raise ValueError(
                    f"exemption cannot cover {self.exemption_covers!r}: "
                    "authority_revoked and authority_not_determined are not resumable on exemption"
                )

    def to_dict(self) -> dict:
        d = {
            "agent_id": self.agent_id,
            "request_id": self.request_id,
            "resume_basis": self.resume_basis.value,
            "reason": self.reason,
        }
        if self.resume_basis == ResumeBasis.EXEMPTION:
            d["exemption_covers"] = self.exemption_covers
            d["exemption_does_not_cover"] = list(EXEMPTION_DOES_NOT_COVER)
        return d


@dataclass
class VoteRecord:
    """BFT vote payload for NTI-1 Pillar 3."""
    voter_id: str
    request_id: str
    decision: str
    outcome_hash: str
    signature_hex: str = ""

    def to_dict(self) -> dict:
        return {
            "voter_id": self.voter_id,
            "request_id": self.request_id,
            "decision": self.decision,
            "outcome_hash": self.outcome_hash,
            "signature": self.signature_hex,
        }


class BFTQuorum:
    """Threshold vote collector. Rejects duplicate voter_ids."""

    def __init__(self, threshold: float = 2 / 3) -> None:
        self.threshold = threshold
        self._votes: dict[str, VoteRecord] = {}

    def cast(self, vote: VoteRecord) -> None:
        if vote.voter_id in self._votes:
            raise ValueError(f"duplicate vote from {vote.voter_id!r}")
        self._votes[vote.voter_id] = vote

    def reached(self, quorum_size: int) -> bool:
        required = int(quorum_size * self.threshold) + 1
        allows = sum(1 for v in self._votes.values() if v.decision == "Allow")
        return allows >= required

    def outcome_hash_agrees(self, expected: str) -> bool:
        return all(v.outcome_hash == expected for v in self._votes.values())
