"""ActionEnvelope -- NTI-1 replay-safe signed action request."""
from __future__ import annotations
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from ..crypto.dilithium import sign as dil_sign, verify as dil_verify
from ..crypto.jcs_canon import canonicalize


@dataclass
class ActionEnvelope:
    action_id: str
    agent_id: str
    principal_id: str
    action_type: str
    payload_hash: str
    timestamp: str
    nonce: str
    signature_hex: str = ""

    def _signable(self) -> bytes:
        return canonicalize({
            "action_id": self.action_id,
            "action_type": self.action_type,
            "agent_id": self.agent_id,
            "nonce": self.nonce,
            "payload_hash": self.payload_hash,
            "principal_id": self.principal_id,
            "timestamp": self.timestamp,
        })

    def sign(self, sk: bytes) -> None:
        self.signature_hex = dil_sign(sk, self._signable()).hex()

    def verify(self, pk: bytes) -> bool:
        if not self.signature_hex:
            return False
        return dil_verify(pk, self._signable(), bytes.fromhex(self.signature_hex))

    @classmethod
    def new(
        cls,
        agent_id: str,
        principal_id: str,
        action_type: str,
        payload: bytes,
        sk: bytes,
        timestamp: Optional[str] = None,
    ) -> "ActionEnvelope":
        ts = timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
        env = cls(
            action_id=str(uuid.uuid4()),
            agent_id=agent_id,
            principal_id=principal_id,
            action_type=action_type,
            payload_hash=hashlib.sha256(payload).hexdigest(),
            timestamp=ts,
            nonce=str(uuid.uuid4()),
        )
        env.sign(sk)
        return env

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "action_type": self.action_type,
            "payload_hash": self.payload_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "signature": self.signature_hex,
        }
