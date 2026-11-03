"""Principal registry -- NTI-1 Pillar 1 runtime trust anchor."""
from __future__ import annotations
from ..objects.identity import AtomicIdentity


class RegistryError(Exception):
    pass


class PrincipalRegistry:
    def __init__(self) -> None:
        self._store: dict[str, AtomicIdentity] = {}

    def register(self, identity: AtomicIdentity) -> None:
        self._store[identity.principal_id] = identity

    def lookup(self, principal_id: str) -> AtomicIdentity:
        if principal_id not in self._store:
            raise RegistryError(f"unknown principal: {principal_id!r}")
        return self._store[principal_id]

    def public_key(self, principal_id: str) -> bytes:
        return self.lookup(principal_id).public_key_bytes

    def revoke(self, principal_id: str) -> None:
        if principal_id not in self._store:
            raise RegistryError(f"principal not found: {principal_id!r}")
        del self._store[principal_id]

    def __contains__(self, principal_id: str) -> bool:
        return principal_id in self._store
