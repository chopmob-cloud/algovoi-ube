"""Voluntary Oblivious Compliance, and the automated agent grader.

This implements the model raised on the AIW thread and tracked as NTI-1 issue 21.
The problem it answers is stated best in Alan Karp's own words: a human in the
loop for every exception produces "Mother, may I" fatigue, and a human who
approves everything is not a control. The proposal is to keep the human
accountable but move the repetitive judgement to an automated grader, and to make
the protocol record which door each resume came through.

The flow, and the reasons for each step:

  STRICT   A policy violation fails closed. No pause, no receipt, no exception.
           This is the default, and a deployment has to opt out of it explicitly.

  VOC      A policy violation raises ANOMALY and pauses. The sidecar requests an
           exemption. Nothing proceeds until a receipt arrives.

  Receipt  The grader signs a justification receipt. The protocol verifies the
           signature and records the receipt, and deliberately does not read the
           opinion inside it. The protocol's job is to record that it did not
           form a view, because an unrecorded absence of judgement is invisible
           to an auditor.

  Boundaries
           An exemption covers a policy violation and nothing else. It cannot
           cover a revocation, because revocation is the issuing authority's
           decision and a grader on the executing side cannot un-revoke it. It
           cannot cover an undetermined authority, because that is an absence of
           information and a signature cannot turn not knowing into knowing.
           Both are refused at construction, so a forbidden receipt cannot be
           built, let alone signed.

What this module does not do is decide whether the exemption was wise. That is
the accountability layer's job, and the point of the receipt is that the layer
can be reviewed afterwards without the protocol having pre-judged it.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from .canonical import canonicalize

__all__ = [
    "AgentGrader",
    "ComplianceMode",
    "Decision",
    "GraderRefused",
    "HaltCause",
    "HmacSigner",
    "JustificationReceipt",
    "ReceiptRefused",
    "evaluate",
]

# The wire values. A receipt may name the value it maps onto; the value never
# depends on the receipt being present.
WIRE_VALUES = ("allow", "deny", "pause", "resume", "revoked")

EXEMPTION_COVERS = ("policy_violation",)
EXEMPTION_DOES_NOT_COVER = ("authority_revoked", "authority_not_determined")


class ComplianceMode(str, Enum):
    """The caveat that decides what happens when policy says no."""

    STRICT = "STRICT"
    VOC = "VOC"


class HaltCause(str, Enum):
    POLICY_VIOLATION = "policy_violation"
    AUTHORITY_REVOKED = "authority_revoked"
    AUTHORITY_NOT_DETERMINED = "authority_not_determined"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PAUSE = "pause"
    RESUME = "resume"
    REVOKED = "revoked"


class ReceiptRefused(ValueError):
    """The receipt cannot be constructed as asked."""


class GraderRefused(RuntimeError):
    """The grader declined to sign."""


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


class HmacSigner:
    """A stand-in signer for the harness.

    The specification mandates a post-quantum signature (CRYSTALS-Dilithium5).
    This is HMAC-SHA256 with a shared key, which is enough to test the protocol
    shape, the canonicalisation and the boundary enforcement, and is not a
    substitute for the real algorithm. Anything signing real receipts must use
    the mandated scheme; the seam is the ``sign`` and ``verify`` pair, so
    swapping it changes nothing else.
    """

    def __init__(self, key: bytes, key_id: str = "hmac-demo-key") -> None:
        if not key:
            raise ValueError("a signer needs a key")
        self._key = key
        self.key_id = key_id
        self.algorithm = "HMAC-SHA256"

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature or "")


class Dilithium5Signer:
    """The mandated signer, backed by the isolated ML-DSA core.

    Same surface as :class:`HmacSigner`, so the VOC flow does not care which one
    it is given. This is the one that satisfies NTI-1, which names
    CRYSTALS-Dilithium5; HMAC exists only so the protocol shape can be tested on
    a machine without a Rust toolchain.

    The signature is over SHA-256 of the payload, and the algorithm name says so,
    because ML-DSA-87 signatures are 4627 bytes and a receipt is best hashed
    before signing at that size.
    """

    def __init__(self, core_path: str | Path | None = None, seed_hex: str = "") -> None:
        from .pqsign import Dilithium5Signer as Core

        self._core = Core(core_path=core_path or _find_core(), seed_hex=seed_hex)
        self.key_id = self._core.key_id
        self.algorithm = "ML-DSA-87"

    @property
    def verify_key(self) -> str:
        return self._core.verify_key

    def sign(self, payload: bytes) -> str:
        return self._core.sign_digest(payload)

    def verify(self, payload: bytes, signature: str) -> bool:
        return self._core.verify_digest(payload, signature)

    def close(self) -> None:
        self._core.close()

    def __enter__(self) -> "Dilithium5Signer":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _find_core(explicit: str | Path | None = None) -> Path:
    from .pqsign import find_core

    return find_core(explicit)


# --------------------------------------------------------------------------
# the receipt
# --------------------------------------------------------------------------


@dataclass
class JustificationReceipt:
    """The signed record of an accepted exemption.

    Field names follow the issue. ``resume_basis`` is fixed to ``exemption`` by
    construction: an evidence based resume is a different object, and mixing the
    two is what the resume basis proposal exists to prevent.
    """

    receipt_id: str
    issued_at: str
    request_id: str
    policy_id: str
    halt_cause: str
    reason: str
    grader_id: str
    grader_role: str
    delegation_id: str
    principal_id: str
    valid_until: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    chain_event_hash: str = ""
    receipt_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.halt_cause in EXEMPTION_DOES_NOT_COVER:
            raise ReceiptRefused(
                f"an exemption cannot cover {self.halt_cause}. "
                + (
                    "Revocation is the issuing authority's decision, and a grader "
                    "on the executing side cannot undo someone else's revocation."
                    if self.halt_cause == "authority_revoked"
                    else "An absence of information is not a judgement about it; a "
                    "signature cannot convert not knowing into knowing."
                )
            )
        if self.halt_cause not in EXEMPTION_COVERS:
            raise ReceiptRefused(
                f"an exemption covers {EXEMPTION_COVERS}, not {self.halt_cause!r}"
            )
        for name in ("receipt_id", "issued_at", "request_id", "policy_id", "reason",
                     "grader_id", "grader_role", "delegation_id", "principal_id"):
            if not str(getattr(self, name) or "").strip():
                raise ReceiptRefused(f"a receipt needs a non-empty {name}")

    def claims(self) -> dict:
        """The part the signature covers, before the signature is attached."""
        return {
            "receipt_version": self.receipt_version,
            "receipt_id": self.receipt_id,
            "issued_at": self.issued_at,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "halt": {
                "cause": self.halt_cause,
                "policy_id": self.policy_id,
                "reason": self.reason,
            },
            "decision": "exemption",
            "resume_basis": "exemption",
            "exemption_covers": list(EXEMPTION_COVERS),
            "exemption_does_not_cover": list(EXEMPTION_DOES_NOT_COVER),
            "justification": {
                "reason": self.reason,
                "evidence_refs": list(self.evidence_refs),
            },
            "grader": {"grader_id": self.grader_id, "grader_role": self.grader_role},
            "principal": {
                "principal_id": self.principal_id,
                "delegation_id": self.delegation_id,
            },
            "validity": {"not_after": self.valid_until},
            "chain_event_hash": self.chain_event_hash,
        }

    def signing_input(self) -> bytes:
        """Canonical bytes. Both sides must produce these exactly."""
        return canonicalize(self.claims()).encode("utf-8")

    def to_json(self, signature: str = "", algorithm: str = "", key_id: str = "") -> dict:
        payload = self.claims()
        payload["signature"] = {
            "alg": algorithm,
            "key_id": key_id,
            "value": signature,
        }
        return payload


# --------------------------------------------------------------------------
# the grader
# --------------------------------------------------------------------------


@dataclass
class AgentGrader:
    """The automated layer that holds authority to sign an exemption.

    The protocol records the exemption; the grader is what makes it an
    accountable decision rather than a hole. Four limits are enforced here
    because an unbounded grader is just an auto-approver:

      it acts only under a mandate issued by someone else, so a grader cannot
      appoint itself and the separation of duties survives;

      the mandate bounds which policies it may exempt, which principals it may
      act for, and the value it may accept;

      it has a ceiling on how many exemptions it will sign in a window, so a
      misconfiguration cannot quietly become a blanket waiver;

      it records what it was asked and what it answered, so the count is
      auditable rather than inferred.
    """

    grader_id: str
    grader_role: str
    signer: HmacSigner
    max_exemptions_per_window: int = 100
    window: str = ""
    mandate: object | None = None
    mandate_payload: dict = field(default_factory=dict)
    mandate_registry: object | None = None
    _signed: int = 0
    _log: list[dict] = field(default_factory=list)

    def _budget_left(self) -> int:
        return max(0, self.max_exemptions_per_window - self._signed)

    def _check_mandate(
        self, *, policy_id: str, principal_id: str, value: int, now: str
    ) -> tuple[bool, str]:
        """The authority check, before any signature is produced.

        A grader with no mandate refuses. That is deliberately fail closed: an
        unmade decision about who authorised the automation must not read as
        permission, which is the same rule the rest of this repository applies to
        an unreachable registry.
        """
        if self.mandate is None:
            return False, (
                "no mandate: an automated grader cannot accept risk on its own "
                "authority, so nothing is signed"
            )
        if self.mandate_registry is not None:
            mandate_id = getattr(self.mandate, "mandate_id", "")
            if self.mandate_registry.is_revoked(mandate_id):
                return False, f"mandate {mandate_id} has been revoked"
            used = self.mandate_registry.used(mandate_id)
        else:
            used = self._signed
        return self.mandate.permits(
            grader_id=self.grader_id,
            policy_id=policy_id,
            principal_id=principal_id,
            value=value,
            now=now,
            used=used,
        )

    def sign_exemption(
        self,
        *,
        receipt_id: str,
        issued_at: str,
        request_id: str,
        policy_id: str,
        halt_cause: str,
        reason: str,
        delegation_id: str,
        principal_id: str,
        valid_until: str = "",
        evidence_refs: list[str] | None = None,
        chain_event_hash: str = "",
        value: int = 0,
    ) -> dict:
        if halt_cause in EXEMPTION_DOES_NOT_COVER:
            self._log.append(
                {"request_id": request_id, "halt_cause": halt_cause, "signed": False,
                 "why": "outside the exemption's authority"}
            )
            raise GraderRefused(
                f"{halt_cause} is not something an exemption can cover, so the "
                "grader will not sign it and the action stays halted"
            )

        permitted, why = self._check_mandate(
            policy_id=policy_id, principal_id=principal_id, value=value, now=issued_at
        )
        if not permitted:
            self._log.append(
                {"request_id": request_id, "halt_cause": halt_cause, "signed": False,
                 "why": why}
            )
            raise GraderRefused(f"the mandate does not permit this exemption: {why}")

        if self._budget_left() <= 0:
            self._log.append(
                {"request_id": request_id, "halt_cause": halt_cause, "signed": False,
                 "why": "exemption ceiling reached"}
            )
            raise GraderRefused(
                f"this grader has signed {self._signed} exemptions in this window "
                f"(ceiling {self.max_exemptions_per_window}); the action stays paused"
            )

        receipt = JustificationReceipt(
            receipt_id=receipt_id,
            issued_at=issued_at,
            request_id=request_id,
            policy_id=policy_id,
            halt_cause=halt_cause,
            reason=reason,
            grader_id=self.grader_id,
            grader_role=self.grader_role,
            delegation_id=delegation_id,
            principal_id=principal_id,
            valid_until=valid_until,
            evidence_refs=list(evidence_refs or []),
            chain_event_hash=chain_event_hash,
        )
        signature = self.signer.sign(receipt.signing_input())
        self._signed += 1
        if self.mandate_registry is not None:
            self.mandate_registry.record_use(getattr(self.mandate, "mandate_id", ""))
        self._log.append(
            {"request_id": request_id, "halt_cause": halt_cause, "signed": True,
             "receipt_id": receipt_id, "mandate_id": getattr(self.mandate, "mandate_id", "")}
        )
        payload = receipt.to_json(
            signature=signature, algorithm=self.signer.algorithm, key_id=self.signer.key_id
        )
        # The receipt names the mandate it was signed under, so an auditor can
        # answer "who allowed this automation to say yes" without reading prose.
        payload["grader"]["mandate_id"] = getattr(self.mandate, "mandate_id", "")
        payload["grader"]["mandate_ref"] = self.mandate_payload
        return payload

    @property
    def signed_count(self) -> int:
        return self._signed

    @property
    def log(self) -> list[dict]:
        return list(self._log)


def verify_receipt(receipt: dict, signer: HmacSigner) -> bool:
    """Check the signature without reading the opinion.

    Rebuilds the signed claims from the receipt, canonicalises them the same way
    the grader did, and compares. A receipt whose fields were altered after
    signing fails here, which is the only integrity property the protocol needs.
    """
    try:
        core = JustificationReceipt(
            receipt_id=receipt["receipt_id"],
            issued_at=receipt["issued_at"],
            request_id=receipt["request_id"],
            policy_id=receipt["policy_id"],
            halt_cause=receipt["halt"]["cause"],
            reason=receipt["justification"]["reason"],
            grader_id=receipt["grader"]["grader_id"],
            grader_role=receipt["grader"]["grader_role"],
            delegation_id=receipt["principal"]["delegation_id"],
            principal_id=receipt["principal"]["principal_id"],
            valid_until=receipt.get("validity", {}).get("not_after", ""),
            evidence_refs=list(receipt["justification"].get("evidence_refs") or []),
            chain_event_hash=receipt.get("chain_event_hash", ""),
            receipt_version=receipt.get("receipt_version", "1.0"),
        )
    except (KeyError, ReceiptRefused):
        return False
    signature = (receipt.get("signature") or {}).get("value", "")
    return signer.verify(core.signing_input(), signature)


# --------------------------------------------------------------------------
# the flow
# --------------------------------------------------------------------------


@dataclass
class Outcome:
    decision: Decision
    reason: str
    wire_value: str
    receipt: dict | None = None
    paused: bool = False

    def as_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "wire_value": self.wire_value,
            "reason": self.reason,
            "paused": self.paused,
            "receipt": self.receipt,
        }


def evaluate(
    *,
    mode: str | ComplianceMode,
    policy_allows: bool,
    halt_cause: str = HaltCause.POLICY_VIOLATION.value,
    policy_id: str = "",
    request_id: str = "",
) -> Outcome:
    """The sidecar's decision, before any exemption is considered.

    ``STRICT`` fails closed on a violation. ``VOC`` pauses and asks. Neither mode
    can proceed past a revocation or an undetermined authority, because those are
    not policy violations and no exemption reaches them.
    """
    try:
        compliance = ComplianceMode(mode)
    except ValueError:
        raise ReceiptRefused(
            f"compliance_mode must be one of {[m.value for m in ComplianceMode]}, "
            f"got {mode!r}"
        ) from None

    if halt_cause in EXEMPTION_DOES_NOT_COVER:
        return Outcome(
            decision=Decision.PAUSE if compliance is ComplianceMode.VOC else Decision.DENY,
            wire_value="pause" if compliance is ComplianceMode.VOC else "deny",
            reason=(
                f"{halt_cause} cannot be exempted, so the action halts regardless of "
                "compliance mode"
            ),
            paused=compliance is ComplianceMode.VOC,
        )

    if policy_allows:
        return Outcome(
            decision=Decision.ALLOW,
            wire_value="allow",
            reason="policy allowed the action",
        )

    if compliance is ComplianceMode.STRICT:
        return Outcome(
            decision=Decision.DENY,
            wire_value="deny",
            reason=(
                "policy denied the action and compliance mode is STRICT, so it fails "
                "closed with no exception path"
            ),
        )

    return Outcome(
        decision=Decision.PAUSE,
        wire_value="pause",
        reason=(
            "policy denied the action and compliance mode is VOC, so the sidecar "
            "pauses and requests an exemption"
        ),
        paused=True,
    )


def resume_on_exemption(
    *,
    outcome: Outcome,
    receipt: dict,
    signer: HmacSigner,
) -> Outcome:
    """Apply a signed receipt to a paused outcome.

    The signature is checked; the justification is not read. That asymmetry is
    the design, not an omission.
    """
    if not outcome.paused:
        return Outcome(
            decision=Decision.DENY,
            wire_value=outcome.wire_value,
            reason="there is no paused action to resume",
        )
    if receipt.get("resume_basis") != "exemption":
        return Outcome(
            decision=Decision.DENY,
            wire_value="deny",
            reason="the receipt is not an exemption receipt",
        )
    if not verify_receipt(receipt, signer):
        return Outcome(
            decision=Decision.DENY,
            wire_value="deny",
            reason="the receipt signature did not verify, so the pause stands",
        )
    return Outcome(
        decision=Decision.RESUME,
        wire_value="resume",
        reason=(
            "resumed on exemption: the receipt verifies, the reason is recorded and "
            "was not evaluated by the protocol"
        ),
        receipt=receipt,
    )
