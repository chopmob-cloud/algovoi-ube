"""MerkleAccumulator + MerkleRevocationRegistry -- NTI-1 Pillar 1 fail-closed revocation."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OutageReason(str, Enum):
    TRY_LATER = "tryLater"


class IncompleteCheckError(Exception):
    """Raised when registry cannot complete check (fail-closed)."""
    def __init__(self, msg: str, reason: OutageReason = OutageReason.TRY_LATER) -> None:
        super().__init__(msg)
        self.reason = reason


def _merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return "0" * 64
    layer = [bytes.fromhex(h) for h in leaves]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(layer[i] + layer[i + 1]).digest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0].hex()


class MerkleAccumulator:
    """Positive accumulator: check() returns True if the item was added and not removed."""

    def __init__(self) -> None:
        self._members: dict[str, str] = {}
        self._available: bool = True

    def add(self, key: str) -> None:
        leaf = hashlib.sha256(key.encode()).hexdigest()
        self._members[key] = leaf

    def remove(self, key: str) -> None:
        self._members.pop(key, None)

    def check(self, key: str) -> bool:
        if not self._available:
            raise IncompleteCheckError(
                "accumulator unavailable -- fail-closed: deny all",
                reason=OutageReason.TRY_LATER,
            )
        return key in self._members

    @property
    def root(self) -> str:
        leaves = sorted(self._members.values())
        return _merkle_root(leaves)

    def simulate_outage(self, unavailable: bool) -> None:
        self._available = not unavailable


class MerkleRevocationRegistry:
    """Negative registry: is_revoked() returns True if the principal was explicitly revoked."""

    def __init__(self) -> None:
        self._revoked: dict[str, str] = {}
        self._available: bool = True

    def revoke(self, principal_id: str, reason: str = "revoked") -> None:
        leaf = hashlib.sha256(principal_id.encode()).hexdigest()
        self._revoked[principal_id] = leaf

    def is_revoked(self, principal_id: str) -> bool:
        if not self._available:
            raise IncompleteCheckError(
                "revocation registry unavailable -- fail-closed: deny all",
                reason=OutageReason.TRY_LATER,
            )
        return principal_id in self._revoked

    def merkle_root(self) -> str:
        if not self._available:
            raise IncompleteCheckError(
                "revocation registry unavailable -- fail-closed: deny all",
                reason=OutageReason.TRY_LATER,
            )
        leaves = sorted(self._revoked.values())
        return _merkle_root(leaves)

    def simulate_outage(self) -> None:
        self._available = False

    def restore(self) -> None:
        self._available = True
