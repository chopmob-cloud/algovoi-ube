"""SHA-256 append-only hash chain -- NTI-1 Pillar 4."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from .jcs_canon import sha256_canonical

GENESIS_PARENT = "0" * 64


def action_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass
class ChainNode:
    agent_id: str
    action_hash: str
    decision: str
    reason: str
    sequence: int
    parent_hash: str
    event_hash: str = field(init=False, default="")

    def ordered_fields(self) -> dict:
        return {
            "action_hash": self.action_hash,
            "agent_id": self.agent_id,
            "decision": self.decision,
            "parent_hash": self.parent_hash,
            "reason": self.reason,
            "sequence": self.sequence,
        }

    def compute_hash(self) -> str:
        return sha256_canonical(self.ordered_fields())

    def verify(self) -> bool:
        return self.event_hash == self.compute_hash()

    def __post_init__(self) -> None:
        self.event_hash = self.compute_hash()


class HashChain:
    def __init__(self) -> None:
        self._nodes: list[ChainNode] = []

    def append(self, agent_id: str, action_hash_val: str, decision: str, reason: str) -> ChainNode:
        parent = self._nodes[-1].event_hash if self._nodes else GENESIS_PARENT
        seq = len(self._nodes)
        node = ChainNode(
            agent_id=agent_id,
            action_hash=action_hash_val,
            decision=decision,
            reason=reason,
            sequence=seq,
            parent_hash=parent,
        )
        self._nodes.append(node)
        return node

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def head(self) -> Optional[ChainNode]:
        return self._nodes[-1] if self._nodes else None

    def verify_integrity(self, expected_length: Optional[int] = None) -> bool:
        if expected_length is not None and len(self._nodes) != expected_length:
            return False
        for i, node in enumerate(self._nodes):
            if not node.verify():
                return False
            expected_parent = GENESIS_PARENT if i == 0 else self._nodes[i - 1].event_hash
            if node.parent_hash != expected_parent:
                return False
        return True
