"""A Merkle revocation registry.

NTI-1's paper describes a registry whose root hash updates when a human or policy
layer issues a pause, with capability tokens bound to that root and verified
against the *latest* root at the boundary: "even if the token was issued
mid-chain, it is rejected at the boundary."

That is an accumulator, not an audit chain, and the distinction matters because
the two are routinely conflated. The audit chain is append-only and grows; the
registry's root is a single 32 byte commitment to the current set of live
capabilities, and it changes by replacement rather than by appending. This module
implements the second structure and keeps its own append-only history of roots,
so a reader can see when a root changed without confusing that history for the
audit trail.

Why a Merkle tree rather than a list of revoked identifiers: a verifier needs to
answer "is this capability live?" without downloading the whole set, and needs a
root small enough to pin in a token or a receipt. The inclusion and exclusion
proofs give both.

The one design decision worth stating plainly is that exclusion proofs are
computed against the *current* set, so a proof is only as fresh as the root it is
verified against. That is the whole point, and it is why the proof carries the
root it was built for: a stale proof verified against a fresh root fails, which
is the mid-chain rejection NTI asks for.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

__all__ = [
    "MerkleRevocationRegistry",
    "MembershipProof",
    "NonMembershipProof",
    "ProofRejected",
    "leaf_hash",
    "node_hash",
]


class ProofRejected(ValueError):
    """A proof did not establish what it claimed, or was stale."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(capability_id: str) -> bytes:
    """Domain separated so a leaf can never be confused with an interior node.

    Without the 0x00 and 0x01 prefixes, a second preimage attack can present an
    interior node as a leaf and forge a proof. This is the standard fix and it
    costs nothing.
    """
    return _sha256(b"\x00" + capability_id.encode("utf-8"))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


@dataclass
class MembershipProof:
    """Proof that a capability is in the live set at a given root."""

    capability_id: str
    index: int
    siblings: list[str]
    root: str

    def as_dict(self) -> dict:
        return {
            "type": "membership",
            "capability_id": self.capability_id,
            "index": self.index,
            "siblings": list(self.siblings),
            "root": self.root,
        }


@dataclass
class NonMembershipProof:
    """Proof that a capability is absent, and came before the next live leaf.

    A sorted Merkle tree gives non-membership from two neighbouring inclusions:
    the leaf immediately before where the capability would sort, and the leaf
    immediately after. Either or both may be absent at the edges of the set, which
    is why the two are optional.
    """

    capability_id: str
    predecessor: str = ""
    predecessor_index: int = -1
    predecessor_siblings: list[str] = field(default_factory=list)
    successor: str = ""
    successor_index: int = -1
    successor_siblings: list[str] = field(default_factory=list)
    root: str = ""

    def as_dict(self) -> dict:
        return {
            "type": "non_membership",
            "capability_id": self.capability_id,
            "predecessor": self.predecessor,
            "predecessor_index": self.predecessor_index,
            "predecessor_siblings": list(self.predecessor_siblings),
            "successor": self.successor,
            "successor_index": self.successor_index,
            "successor_siblings": list(self.successor_siblings),
            "root": self.root,
        }


class MerkleRevocationRegistry:
    """The live set of capabilities, committed to by a single root hash."""

    def __init__(self) -> None:
        self._leaves: list[str] = []
        self._root: bytes = _sha256(b"")
        self._history: list[dict] = []

    # -- state -------------------------------------------------------------

    @property
    def root(self) -> str:
        return self._root.hex()

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def capabilities(self) -> list[str]:
        return list(self._leaves)

    @property
    def history(self) -> list[dict]:
        """Every root this registry has held, oldest first.

        Kept separate from the audit chain on purpose: this records what the
        registry looked like, not what an agent did.
        """
        return list(self._history)

    def _record(self, reason: str, capability_id: str = "") -> None:
        self._history.append(
            {"root": self.root, "size": self.size, "reason": reason, "capability_id": capability_id}
        )

    # -- tree --------------------------------------------------------------

    def _layer(self) -> list[bytes]:
        return sorted(leaf_hash(c) for c in self._leaves)

    def _root_of(self, leaves: list[bytes]) -> bytes:
        if not leaves:
            return _sha256(b"")
        layer = list(leaves)
        while len(layer) > 1:
            if len(layer) % 2:
                # Duplicate the last node rather than promoting it, so every
                # internal node has two children and the shape is unambiguous.
                layer.append(layer[-1])
            layer = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        return layer[0]

    def _recompute(self) -> None:
        self._root = self._root_of(self._layer())

    def _siblings(self, index: int) -> list[str]:
        """The sibling at each level, in the same shape ``_root_of`` builds.

        The odd-node rule has to match the one used to compute the root exactly,
        or the walk produces a different value and every proof fails. Both
        functions therefore duplicate a lone node before pairing.
        """
        layer = self._layer()
        siblings: list[str] = []
        position = index
        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])
            partner = position ^ 1
            siblings.append(layer[partner].hex())
            layer = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
            position //= 2
        return siblings

    @staticmethod
    def _walk(leaf: bytes, index: int, siblings: list[str]) -> bytes:
        node = leaf
        position = index
        for sibling_hex in siblings:
            sibling = bytes.fromhex(sibling_hex)
            node = node_hash(node, sibling) if position % 2 == 0 else node_hash(sibling, node)
            position //= 2
        return node

    # -- mutation ----------------------------------------------------------

    def register(self, capability_id: str) -> str:
        """Add a live capability. Returns the new root."""
        if not capability_id.strip():
            raise ProofRejected("a capability id must not be empty")
        if capability_id in self._leaves:
            raise ProofRejected(f"{capability_id!r} is already registered")
        self._leaves.append(capability_id)
        self._recompute()
        self._record("register", capability_id)
        return self.root

    def revoke(self, capability_id: str) -> str:
        """Remove a capability. The root changes; the audit of the change is separate."""
        if capability_id not in self._leaves:
            raise ProofRejected(f"{capability_id!r} is not registered")
        self._leaves.remove(capability_id)
        self._recompute()
        self._record("revoke", capability_id)
        return self.root

    # -- proofs ------------------------------------------------------------

    def _ordered_leaves(self) -> list[tuple[bytes, str]]:
        """Leaves paired with their capability, sorted by hash.

        The tree is ordered by leaf hash, so an index taken from a list sorted by
        capability name would point at a different leaf and every proof would
        fail. Both the proof and the tree must use this one order.
        """
        return sorted((leaf_hash(c), c) for c in self._leaves)

    def prove_membership(self, capability_id: str) -> MembershipProof:
        if capability_id not in self._leaves:
            raise ProofRejected(f"{capability_id!r} is not in the live set")
        ordered = [cap for _, cap in self._ordered_leaves()]
        index = ordered.index(capability_id)
        return MembershipProof(
            capability_id=capability_id,
            index=index,
            siblings=self._siblings(index),
            root=self.root,
        )

    def prove_absence(self, capability_id: str) -> NonMembershipProof:
        """Non-membership by the two neighbouring leaves in hash order.

        The tree sorts by leaf hash, so the neighbours that bracket a missing
        capability are found by comparing hashes, not names. Comparing names here
        would produce a proof that looks right and verifies against nothing.
        """
        ordered = self._ordered_leaves()
        target = leaf_hash(capability_id)
        if any(cap == capability_id for _, cap in ordered):
            raise ProofRejected(f"{capability_id!r} is live, so absence cannot be proved")

        proof = NonMembershipProof(capability_id=capability_id, root=self.root)
        for index, (digest, cap) in enumerate(ordered):
            if digest < target:
                proof.predecessor = cap
                proof.predecessor_index = index
                proof.predecessor_siblings = self._siblings(index)
            elif digest > target and not proof.successor:
                proof.successor = cap
                proof.successor_index = index
                proof.successor_siblings = self._siblings(index)
                break
        return proof

    # -- verification ------------------------------------------------------

    def verify_membership(self, proof: MembershipProof, *, expect_root: str | None = None) -> bool:
        """Check a proof against the current root, or an explicitly pinned one.

        Passing ``expect_root`` is how a verifier states which registry state it
        is willing to accept. A proof built for an older root fails against a
        newer one, which is the mid-chain rejection NTI requires.
        """
        reference = expect_root if expect_root is not None else self.root
        if proof.root != reference:
            raise ProofRejected(
                f"the proof was built for root {proof.root[:12]} but {reference[:12]} is "
                "the root in force, so it is stale"
            )
        recomputed = self._walk(leaf_hash(proof.capability_id), proof.index, proof.siblings)
        return recomputed.hex() == reference

    def verify_absence(self, proof: NonMembershipProof, *, expect_root: str | None = None) -> bool:
        reference = expect_root if expect_root is not None else self.root
        if proof.root != reference:
            raise ProofRejected(
                f"the proof was built for root {proof.root[:12]} but {reference[:12]} is "
                "the root in force"
            )
        if not proof.predecessor and not proof.successor:
            # Absence from an empty set is trivially true, but only if the root
            # really is the empty root.
            return reference == _sha256(b"").hex()

        if proof.predecessor:
            node = self._walk(
                leaf_hash(proof.predecessor),
                proof.predecessor_index,
                proof.predecessor_siblings,
            )
            if node.hex() != reference:
                raise ProofRejected("the predecessor does not sit under the stated root")
            if not leaf_hash(proof.predecessor) < leaf_hash(proof.capability_id):
                raise ProofRejected("the predecessor does not sort before the capability")

        if proof.successor:
            node = self._walk(
                leaf_hash(proof.successor),
                proof.successor_index,
                proof.successor_siblings,
            )
            if node.hex() != reference:
                raise ProofRejected("the successor does not sit under the stated root")
            if not leaf_hash(proof.capability_id) < leaf_hash(proof.successor):
                raise ProofRejected("the successor does not sort after the capability")

        return True

    def is_live(self, capability_id: str, *, expect_root: str | None = None) -> bool:
        """The question the sidecar asks at the boundary."""
        reference = expect_root if expect_root is not None else self.root
        if reference != self.root:
            # A pinned root that is not the current one is a stale authority.
            return False
        return capability_id in self._leaves
