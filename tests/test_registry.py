"""Tests for the Merkle revocation registry.

The behaviour that matters is the mid-chain rejection NTI describes: a token
issued against an old root is refused at the boundary. Everything else here
supports that one claim.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.registry import (  # noqa: E402
    MerkleRevocationRegistry,
    NonMembershipProof,
    ProofRejected,
    leaf_hash,
    node_hash,
)


def registry_with(*caps: str) -> MerkleRevocationRegistry:
    reg = MerkleRevocationRegistry()
    for cap in caps:
        reg.register(cap)
    return reg


def test_an_empty_registry_has_a_defined_root():
    reg = MerkleRevocationRegistry()
    assert reg.root
    assert reg.size == 0


def test_membership_round_trips():
    reg = registry_with("cap-a", "cap-b", "cap-c")
    proof = reg.prove_membership("cap-b")
    assert reg.verify_membership(proof) is True


def test_a_proof_for_the_wrong_capability_fails():
    reg = registry_with("cap-a", "cap-b", "cap-c")
    proof = reg.prove_membership("cap-b")
    proof.capability_id = "cap-z"
    assert reg.verify_membership(proof) is False


def test_a_tampered_sibling_fails():
    reg = registry_with("cap-a", "cap-b", "cap-c", "cap-d")
    proof = reg.prove_membership("cap-c")
    proof.siblings[0] = "00" * 32
    assert reg.verify_membership(proof) is False


def test_absence_round_trips():
    reg = registry_with("cap-a", "cap-c")
    proof = reg.prove_absence("cap-b")
    assert reg.verify_absence(proof) is True


def test_absence_before_the_first_leaf():
    """One neighbour is enough, and which side it is depends on hash order.

    The tree sorts by leaf hash, so a capability named before every live leaf can
    still hash after them. The proof only needs the correct single neighbour, so
    this asserts the bracketing property rather than a name ordering that the
    structure does not guarantee.
    """
    reg = registry_with("cap-m", "cap-n")
    proof = reg.prove_absence("cap-a")
    neighbours = [c for c in (proof.predecessor, proof.successor) if c]
    assert len(neighbours) >= 1
    for cap in neighbours:
        if cap == proof.predecessor:
            assert leaf_hash(cap) < leaf_hash("cap-a")
        else:
            assert leaf_hash("cap-a") < leaf_hash(cap)
    assert reg.verify_absence(proof) is True


def test_absence_after_the_last_leaf():
    reg = registry_with("cap-a", "cap-b")
    proof = reg.prove_absence("cap-z")
    neighbours = [c for c in (proof.predecessor, proof.successor) if c]
    assert len(neighbours) >= 1
    assert reg.verify_absence(proof) is True


def test_absence_from_an_empty_set():
    reg = MerkleRevocationRegistry()
    proof = reg.prove_absence("cap-a")
    assert reg.verify_absence(proof) is True


def test_absence_cannot_be_proved_for_a_live_capability():
    reg = registry_with("cap-a")
    with pytest.raises(ProofRejected):
        reg.prove_absence("cap-a")


def test_a_stale_proof_is_rejected_after_a_revocation():
    """The claim from the AIW paper: mid-chain issuance is rejected at the boundary."""
    reg = registry_with("cap-a", "cap-b", "cap-c")
    proof = reg.prove_membership("cap-b")
    root_before = reg.root
    assert reg.verify_membership(proof) is True

    reg.revoke("cap-b")

    # The proof is now stale, and verifying it against the current root fails.
    with pytest.raises(ProofRejected) as excinfo:
        reg.verify_membership(proof)
    assert "stale" in str(excinfo.value)

    # Pinning the old root still validates the old proof, which is what an
    # auditor with a historical receipt needs.
    assert reg.verify_membership(proof, expect_root=root_before) is True


def test_the_root_changes_on_every_mutation():
    reg = registry_with("cap-a")
    first = reg.root
    reg.register("cap-b")
    second = reg.root
    reg.revoke("cap-a")
    third = reg.root
    assert len({first, second, third}) == 3


def test_the_sidecar_question_uses_the_latest_root():
    reg = registry_with("cap-a", "cap-b")
    assert reg.is_live("cap-b") is True
    reg.revoke("cap-b")
    assert reg.is_live("cap-b") is False


def test_a_pinned_old_root_is_treated_as_stale_authority():
    reg = registry_with("cap-a")
    old = reg.root
    reg.register("cap-b")
    # Asking with the old root must not answer yes off current state.
    assert reg.is_live("cap-a", expect_root=old) is False


def test_history_is_separate_from_the_audit_chain():
    reg = registry_with("cap-a")
    reg.register("cap-b")
    reg.revoke("cap-a")
    reasons = [entry["reason"] for entry in reg.history]
    assert reasons == ["register", "register", "revoke"]
    assert reg.history[-1]["capability_id"] == "cap-a"


def test_duplicate_registration_is_refused():
    reg = registry_with("cap-a")
    with pytest.raises(ProofRejected):
        reg.register("cap-a")


def test_revoking_an_unknown_capability_is_refused():
    reg = registry_with("cap-a")
    with pytest.raises(ProofRejected):
        reg.revoke("cap-z")


def test_leaves_and_nodes_are_domain_separated():
    """Without the prefixes an interior node can be presented as a leaf."""
    leaf = leaf_hash("cap-a")
    node = node_hash(leaf, leaf)
    assert leaf != node
    assert leaf != leaf_hash("cap-a")[1:] + b"\x00"


def test_all_leaves_verify_under_one_root():
    caps = [f"cap-{i}" for i in range(11)]  # odd count exercises the duplicate rule
    reg = registry_with(*caps)
    for cap in caps:
        assert reg.verify_membership(reg.prove_membership(cap)) is True
    assert len({reg.prove_membership(c).root for c in caps}) == 1


# ---- non-membership soundness: neighbours must be adjacent ---------------


def test_forged_absence_with_non_adjacent_neighbours_is_rejected():
    """A live capability must not be passable as absent.

    Two live leaves can still bracket a third live leaf by hash order. A
    non-membership proof that names those two non-adjacent leaves as the
    neighbours of a present capability sits entirely under the real root and
    sorts correctly, so it passes every bracketing check. It must still be
    rejected, because a sorted Merkle tree only proves absence when the two
    inclusions are adjacent with nothing between them. Accepting it would let a
    live capability be reported as revoked.
    """
    caps = [f"cap-{i}" for i in range(12)]
    reg = registry_with(*caps)
    ordered = [cap for _, cap in reg._ordered_leaves()]  # sorted by leaf hash

    # Pick an interior, genuinely live capability as the forgery target, and two
    # live leaves that bracket it by hash but are not its immediate neighbours.
    target = ordered[5]
    predecessor, pred_index = ordered[2], 2
    successor, succ_index = ordered[8], 8
    assert reg.is_live(target)
    assert leaf_hash(predecessor) < leaf_hash(target) < leaf_hash(successor)

    forged = NonMembershipProof(
        capability_id=target,
        predecessor=predecessor,
        predecessor_index=pred_index,
        predecessor_siblings=reg._siblings(pred_index),
        successor=successor,
        successor_index=succ_index,
        successor_siblings=reg._siblings(succ_index),
        root=reg.root,
    )
    with pytest.raises(ProofRejected) as excinfo:
        reg.verify_absence(forged)
    assert "adjacent" in str(excinfo.value)


def test_forged_absence_before_first_with_wrong_successor_is_rejected():
    """A one-sided proof must name the actual boundary leaf.

    Claiming nothing sorts before the target, while pointing at a successor that
    is not the first leaf, leaves room for a live leaf to sort ahead of the
    target. The live leaf at index 0 would then be reported absent.
    """
    caps = [f"cap-{i}" for i in range(12)]
    reg = registry_with(*caps)
    ordered = [cap for _, cap in reg._ordered_leaves()]

    target = ordered[0]  # the genuinely live first leaf
    successor, succ_index = ordered[1], 1  # not index 0
    assert reg.is_live(target)

    forged = NonMembershipProof(
        capability_id=target,
        successor=successor,
        successor_index=succ_index,
        successor_siblings=reg._siblings(succ_index),
        root=reg.root,
    )
    with pytest.raises(ProofRejected):
        reg.verify_absence(forged)


def test_forged_absence_after_last_with_wrong_predecessor_is_rejected():
    """The mirror case: a predecessor that is not the last leaf."""
    caps = [f"cap-{i}" for i in range(12)]
    reg = registry_with(*caps)
    ordered = [cap for _, cap in reg._ordered_leaves()]

    target = ordered[-1]  # the genuinely live last leaf
    predecessor, pred_index = ordered[-3], len(ordered) - 3  # not the last index
    assert reg.is_live(target)

    forged = NonMembershipProof(
        capability_id=target,
        predecessor=predecessor,
        predecessor_index=pred_index,
        predecessor_siblings=reg._siblings(pred_index),
        root=reg.root,
    )
    with pytest.raises(ProofRejected):
        reg.verify_absence(forged)


def test_honest_absence_proofs_still_verify_after_the_adjacency_rule():
    """The fix must not break genuine non-membership proofs of any shape."""
    reg = registry_with(*[f"cap-{i}" for i in range(13)])
    for name in ("absent-x", "absent-y", "zzz-last", "000-first", "cap-middle"):
        if name in reg.capabilities:
            continue
        proof = reg.prove_absence(name)
        assert reg.verify_absence(proof) is True
