"""AtomicIdentity -- NTI-1 Pillar 1 base object."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AtomicIdentity:
    principal_id: str
    public_key_hex: str
    algorithm: str = "CRYSTALS-Dilithium5"
    created_at: str = ""
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    @classmethod
    def new(cls, principal_id: str, public_key: bytes, expires_at: Optional[str] = None) -> "AtomicIdentity":
        return cls(principal_id=principal_id, public_key_hex=public_key.hex(), expires_at=expires_at)

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)

    def is_expired(self, at: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        now = at or datetime.now(timezone.utc)
        exp = datetime.fromisoformat(self.expires_at)
        return now >= exp

    def to_dict(self) -> dict:
        d = {
            "principal_id": self.principal_id,
            "public_key": self.public_key_hex,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AtomicIdentity":
        return cls(
            principal_id=d["principal_id"],
            public_key_hex=d["public_key"],
            algorithm=d.get("algorithm", "CRYSTALS-Dilithium5"),
            created_at=d.get("created_at", ""),
            expires_at=d.get("expires_at"),
        )
