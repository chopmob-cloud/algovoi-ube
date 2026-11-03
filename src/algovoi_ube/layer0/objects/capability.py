"""CapabilityGrant and caveat evaluation -- NTI-1 Pillar 2."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class CaveatDenied(Exception):
    pass


@dataclass
class CaveatExpires:
    expires: str

    def check(self, now: Optional[datetime] = None) -> None:
        t = now or datetime.now(timezone.utc)
        exp = datetime.fromisoformat(self.expires)
        if t >= exp:
            raise CaveatDenied(f"capability expired at {self.expires}")


@dataclass
class CaveatMaxExecutions:
    max_executions: int
    _count: int = field(default=0, repr=False)

    def check(self) -> None:
        if self._count >= self.max_executions:
            raise CaveatDenied(f"max_executions={self.max_executions} reached")
        self._count += 1


@dataclass
class CaveatValueLimit:
    value_limit: float
    unit: str = ""

    def check(self, value: float) -> None:
        if value > self.value_limit:
            raise CaveatDenied(f"value {value} exceeds limit {self.value_limit} {self.unit}")


@dataclass
class CaveatPathRestricted:
    allowed_paths: list[str]

    def check(self, path: str) -> None:
        for pattern in self.allowed_paths:
            if re.fullmatch(pattern, path):
                return
        raise CaveatDenied(f"path {path!r} not in allowed_paths")


@dataclass
class CapabilityGrant:
    grant_id: str
    principal_id: str
    agent_id: str
    capabilities: list[str]
    caveats: list = field(default_factory=list)
    issued_at: str = ""
    signature_hex: str = ""

    def evaluate(
        self,
        action_type: str,
        path: str = "",
        value: float = 0.0,
        now: Optional[datetime] = None,
    ) -> str:
        if action_type not in self.capabilities:
            raise CaveatDenied(f"action_type {action_type!r} not in capabilities")
        for caveat in self.caveats:
            if isinstance(caveat, CaveatExpires):
                caveat.check(now)
            elif isinstance(caveat, CaveatMaxExecutions):
                caveat.check()
            elif isinstance(caveat, CaveatValueLimit):
                caveat.check(value)
            elif isinstance(caveat, CaveatPathRestricted):
                caveat.check(path)
        return "Allow"

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "capabilities": self.capabilities,
            "issued_at": self.issued_at,
        }
