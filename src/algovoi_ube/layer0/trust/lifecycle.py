"""KeyLifecycle -- NTI-1 Pillar 1 key rotation and revocation with audit trail."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from ..crypto.dilithium import keygen
from ..objects.identity import AtomicIdentity
from .registry import PrincipalRegistry


@dataclass
class RotationLogEntry:
    principal_id: str
    old_key_hex: str
    new_key_hex: str
    action: str  # "rotate" or "revoke"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    auditable: bool = True


class KeyLifecycle:
    """Manages key generation, rotation, and revocation for principals."""

    def __init__(self, registry: PrincipalRegistry) -> None:
        self._registry = registry
        self.rotation_log: list[RotationLogEntry] = []

    def generate(self, principal_id: str, expires_at: Optional[str] = None) -> tuple[AtomicIdentity, bytes]:
        pk, sk = keygen()
        identity = AtomicIdentity.new(principal_id, pk, expires_at=expires_at)
        self._registry.register(identity)
        return identity, sk

    def rotate(self, principal_id: str) -> tuple[AtomicIdentity, bytes]:
        old_identity = self._registry.lookup(principal_id)
        old_key_hex = old_identity.public_key_hex
        pk, sk = keygen()
        new_identity = AtomicIdentity.new(principal_id, pk)
        self._registry.register(new_identity)
        self.rotation_log.append(RotationLogEntry(
            principal_id=principal_id,
            old_key_hex=old_key_hex,
            new_key_hex=new_identity.public_key_hex,
            action="rotate",
        ))
        return new_identity, sk

    def revoke(self, principal_id: str) -> None:
        identity = self._registry.lookup(principal_id)
        old_key_hex = identity.public_key_hex
        self._registry.revoke(principal_id)
        self.rotation_log.append(RotationLogEntry(
            principal_id=principal_id,
            old_key_hex=old_key_hex,
            new_key_hex="",
            action="revoke",
        ))
