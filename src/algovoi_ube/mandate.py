"""Who authorised the grader, and how far that authority reaches.

The VOC flow has a hole that the receipt does not close. A grader signs an
exemption, the sidecar verifies the signature, and the action resumes. But a valid
signature only proves which grader signed. It says nothing about whether that
grader was ever entitled to accept that risk, for that principal, under that
policy, or at all.

Without a mandate, "an automated agent grader accepted the risk" is a statement
about a key, not about authority. A deployment could point the grader at a
permissive policy and every receipt would still verify. That is the same defect
the resume basis work fixed one layer down, appearing one layer up: authenticity
standing in for authorisation.

So a grader acts under a mandate, and the mandate is itself a signed, bounded,
revocable object with four properties that matter:

  Issued by someone else.
      A grader MUST NOT be able to issue its own mandate. Self authorisation is
      not authority, and a design where the grader mints its own warrant has no
      separation of duties at all.

  Bounded in scope.
      A mandate names the policies it may exempt, the principals it may act for,
      and a value ceiling. An unbounded mandate is a blanket waiver with extra
      steps.

  Bounded in time.
      A mandate has an end. An authority without an expiry cannot be reviewed
      because it never lapses.

  Revocable, and checked at use.
      Revoking a mandate must stop the next signature, not the one after the next
      review. The check happens when the grader signs, not when it was set up.

The chain in a receipt is then: principal authorises grader via mandate, grader
signs exemption, sidecar verifies both. An auditor can answer "who allowed this
automation to say yes" without reading any free text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .canonical import canonicalize

__all__ = [
    "GraderMandate",
    "MandateRegistry",
    "MandateRefused",
    "MandateScope",
    "sign_mandate",
    "verify_mandate",
]


class MandateRefused(RuntimeError):
    """The mandate does not permit the action asked of it."""


class MandateScope(str, Enum):
    """What a mandate permits, in the only terms that can be checked."""

    EXEMPTION = "exemption"


@dataclass
class GraderMandate:
    """A bounded, signed grant of authority to an automated grader.

    Field by field, and why each is load bearing:

    ``issuer_id`` and ``issuer_role``
        Who is accountable for the automation. Not the grader: the person or body
        that decided to delegate yes-saying to a machine.

    ``grader_id``
        The specific grader. A mandate for "any grader" is a mandate for whoever
        turns up.

    ``policies``
        The closed list of policy ids this grader may exempt. Empty means none,
        never all, because a default of all is how a scope check becomes
        decorative.

    ``principals``
        The principals whose risk may be accepted. A grader for one tenant must
        not be able to accept risk for another.

    ``max_value``
        A ceiling on the value of what may be exempted. Zero means no monetary
        limit is expressible, which is honest rather than unlimited.

    ``not_after``
        When the authority lapses. Required, because an authority that never
        lapses is never reviewed.

    ``max_exemptions``
        How many times it may be exercised. A mandate that can be used without
        limit is a policy change wearing a mandate's clothes.
    """

    mandate_id: str
    issuer_id: str
    issuer_role: str
    grader_id: str
    issued_at: str
    not_after: str
    policies: tuple[str, ...] = ()
    principals: tuple[str, ...] = ()
    max_value: int = 0
    max_exemptions: int = 0
    scope: str = MandateScope.EXEMPTION.value
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("mandate_id", "issuer_id", "issuer_role", "grader_id",
                     "issued_at", "not_after"):
            if not str(getattr(self, name) or "").strip():
                raise MandateRefused(f"a mandate needs a non-empty {name}")
        if self.issuer_id == self.grader_id:
            raise MandateRefused(
                "a grader cannot issue its own mandate: self authorisation is not "
                "authority, and it removes the separation of duties the mandate exists "
                "to provide"
            )
        if not self.policies:
            raise MandateRefused(
                "a mandate must name the policies it may exempt. An empty scope "
                "silently meaning all of them is how a scope check becomes decoration"
            )
        if self.scope != MandateScope.EXEMPTION.value:
            raise MandateRefused(
                f"a grader mandate covers {MandateScope.EXEMPTION.value}, not {self.scope!r}"
            )
        if self.max_exemptions < 0 or self.max_value < 0:
            raise MandateRefused("limits cannot be negative")

    def claims(self) -> dict:
        return {
            "mandate_id": self.mandate_id,
            "issuer": {"issuer_id": self.issuer_id, "issuer_role": self.issuer_role},
            "grader_id": self.grader_id,
            "issued_at": self.issued_at,
            "not_after": self.not_after,
            "scope": self.scope,
            "policies": list(self.policies),
            "principals": list(self.principals),
            "max_value": self.max_value,
            "max_exemptions": self.max_exemptions,
            "notes": self.notes,
        }

    def signing_input(self) -> bytes:
        return canonicalize(self.claims()).encode("utf-8")

    def permits(
        self,
        *,
        grader_id: str,
        policy_id: str,
        principal_id: str,
        value: int,
        now: str,
        used: int = 0,
    ) -> tuple[bool, str]:
        """The check the grader makes before it signs anything.

        Returns a decision and a reason, so a refusal is auditable rather than a
        bare exception.
        """
        if grader_id != self.grader_id:
            return False, f"the mandate is for {self.grader_id}, not {grader_id}"
        if now > self.not_after:
            return False, f"the mandate lapsed at {self.not_after}"
        if policy_id not in self.policies:
            return False, f"{policy_id} is outside the mandate's scope"
        if self.principals and principal_id not in self.principals:
            return False, f"{principal_id} is outside the mandate's principals"
        if self.max_value and value > self.max_value:
            return False, (
                f"value {value} exceeds the mandate ceiling of {self.max_value}"
            )
        if self.max_exemptions and used >= self.max_exemptions:
            return False, (
                f"the mandate permits {self.max_exemptions} exemptions and {used} "
                "have been used"
            )
        return True, "within the mandate"


def sign_mandate(mandate: GraderMandate, signer) -> dict:
    """Sign a mandate with the issuer's key.

    ``signer`` is any object with ``sign`` and ``verify``, so the issuer's key can
    be held wherever the deployment keeps it. It must not be the grader's key, and
    the constructor has already refused the case where the two identities match.
    """
    signature = signer.sign(mandate.signing_input())
    payload = mandate.claims()
    payload["signature"] = {
        "alg": getattr(signer, "algorithm", ""),
        "key_id": getattr(signer, "key_id", ""),
        "value": signature,
    }
    return payload


def verify_mandate(payload: dict, signer) -> bool:
    """Check that a mandate is intact and was signed by the issuer's key."""
    try:
        mandate = GraderMandate(
            mandate_id=payload["mandate_id"],
            issuer_id=payload["issuer"]["issuer_id"],
            issuer_role=payload["issuer"]["issuer_role"],
            grader_id=payload["grader_id"],
            issued_at=payload["issued_at"],
            not_after=payload["not_after"],
            policies=tuple(payload.get("policies") or ()),
            principals=tuple(payload.get("principals") or ()),
            max_value=int(payload.get("max_value") or 0),
            max_exemptions=int(payload.get("max_exemptions") or 0),
            scope=payload.get("scope", MandateScope.EXEMPTION.value),
            notes=payload.get("notes", ""),
        )
    except (KeyError, MandateRefused, ValueError):
        return False
    signature = (payload.get("signature") or {}).get("value", "")
    return signer.verify(mandate.signing_input(), signature)


@dataclass
class MandateRegistry:
    """The mandates in force, and how many times each has been used.

    Kept separate from the revocation registry on purpose. That one answers "is
    this capability live", this one answers "was this authority ever granted, and
    is it still". Conflating them is the same mistake as conflating the audit chain
    with the accumulator.
    """

    _mandates: dict[str, dict] = field(default_factory=dict)
    _used: dict[str, int] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)
    _history: list[dict] = field(default_factory=list)

    def register(self, payload: dict) -> str:
        mandate_id = payload.get("mandate_id", "")
        if not mandate_id:
            raise MandateRefused("a mandate payload needs a mandate_id")
        if mandate_id in self._mandates:
            raise MandateRefused(f"mandate {mandate_id!r} is already registered")
        self._mandates[mandate_id] = payload
        self._used[mandate_id] = 0
        self._history.append({"mandate_id": mandate_id, "event": "register"})
        return mandate_id

    def revoke(self, mandate_id: str) -> None:
        if mandate_id not in self._mandates:
            raise MandateRefused(f"mandate {mandate_id!r} is not registered")
        self._revoked.add(mandate_id)
        self._history.append({"mandate_id": mandate_id, "event": "revoke"})

    def get(self, mandate_id: str) -> dict:
        if mandate_id not in self._mandates:
            raise MandateRefused(f"mandate {mandate_id!r} is not registered")
        return self._mandates[mandate_id]

    def is_revoked(self, mandate_id: str) -> bool:
        return mandate_id in self._revoked

    def used(self, mandate_id: str) -> int:
        return self._used.get(mandate_id, 0)

    def record_use(self, mandate_id: str) -> int:
        if mandate_id in self._revoked:
            raise MandateRefused(
                f"mandate {mandate_id!r} has been revoked, so it cannot be exercised"
            )
        self._used[mandate_id] = self._used.get(mandate_id, 0) + 1
        self._history.append({"mandate_id": mandate_id, "event": "use"})
        return self._used[mandate_id]

    @property
    def history(self) -> list[dict]:
        return list(self._history)
