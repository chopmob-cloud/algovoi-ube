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
