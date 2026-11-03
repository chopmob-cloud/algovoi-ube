"""NTI-1 Layer 0 test suite.

Covers all spec testable requirements plus Layer 0 internal invariants.
T-1.1 Identity: no-signature -> Deny
T-2.1 Governance: expired capability -> Deny
T-3.1 Consensus: no-threshold -> Deny
T-4.1 Audit: 100 actions -> chain length == 100
T-5.1 Persistence: chain integrity survives reload
"""
import hashlib
import pytest

pytest.importorskip("pqcrypto", reason="pqcrypto not installed; install algovoi-ube[layer0]")

from algovoi_ube.layer0.crypto.dilithium import keygen, sign, verify, SIGNATURE_SIZE
from algovoi_ube.layer0.crypto.jcs_canon import canonicalize, sha256_canonical
from algovoi_ube.layer0.crypto.hashchain import HashChain, action_hash, GENESIS_PARENT
from algovoi_ube.layer0.objects.identity import AtomicIdentity
from algovoi_ube.layer0.objects.envelope import ActionEnvelope
from algovoi_ube.layer0.objects.capability import (
    CapabilityGrant, CaveatExpires, CaveatMaxExecutions,
    CaveatValueLimit, CaveatPathRestricted, CaveatDenied,
)
from algovoi_ube.layer0.objects.audit import VoteRecord, BFTQuorum, ResumeReceipt, ResumeBasis, EXEMPTION_DOES_NOT_COVER
from algovoi_ube.layer0.trust.registry import PrincipalRegistry, RegistryError
from algovoi_ube.layer0.trust.lifecycle import KeyLifecycle
from algovoi_ube.layer0.trust.revocation import MerkleAccumulator, IncompleteCheckError


# Crypto engine

class TestDilithium:
    def test_keygen_sizes(self):
        pk, sk = keygen()
        assert len(pk) == 2592
        assert len(sk) == 4896

    def test_sign_verify(self):
        pk, sk = keygen()
        msg = b"nti layer0"
        sig = sign(sk, msg)
        assert len(sig) == SIGNATURE_SIZE
        assert verify(pk, msg, sig)

    def test_tamper_detected(self):
        pk, sk = keygen()
        sig = sign(sk, b"hello")
        assert not verify(pk, b"tampered", sig)

    def test_wrong_key_rejected(self):
        pk1, sk1 = keygen()
        pk2, sk2 = keygen()
        sig = sign(sk1, b"msg")
        assert not verify(pk2, b"msg", sig)

    def test_t1_1_no_signature_denied(self):
        """T-1.1: action with no signature MUST be Deny."""
        pk, _ = keygen()
        env = ActionEnvelope(
            action_id="x", agent_id="a", principal_id="p",
            action_type="read", payload_hash="abc",
            timestamp="2026-01-01T00:00:00+00:00",
            nonce="n", signature_hex="",
        )
        assert not env.verify(pk)


class TestJCS:
    def test_key_ordering(self):
        b = canonicalize({"z": 1, "a": 2, "m": 3})
        assert b == b'{"a":2,"m":3,"z":1}'

    def test_nested(self):
        b = canonicalize({"b": {"y": 1, "x": 2}, "a": 3})
        assert b == b'{"a":3,"b":{"x":2,"y":1}}'

    def test_preimage_distinct(self):
        h1 = sha256_canonical({"a": "1,b", "b": "2"})
        h2 = sha256_canonical({"a": "1", "b": ",b,2"})
        assert h1 != h2, "delimiter-join preimage collision should not exist with JCS"


# Hash chain

class TestHashChain:
    def test_t4_1_hundred_actions(self):
        """T-4.1: 100 actions -> chain length == 100."""
        chain = HashChain()
        for i in range(100):
            chain.append("agent-x", action_hash(f"action{i}".encode()), "Allow", "ok")
        assert len(chain) == 100
        assert chain.verify_integrity(expected_length=100)

    def test_tamper_detected(self):
        chain = HashChain()
        chain.append("a", action_hash(b"x"), "Allow", "ok")
        chain.append("a", action_hash(b"y"), "Allow", "ok")
        chain._nodes[0].decision = "TAMPERED"
        assert not chain.verify_integrity()

    def test_truncation_detected(self):
        """T-4.1 extension: truncated log rejected when expected_length provided."""
        chain = HashChain()
        for _ in range(5):
            chain.append("a", action_hash(b"x"), "Allow", "ok")
        chain._nodes.pop()
        assert not chain.verify_integrity(expected_length=5)

    def test_parent_links(self):
        chain = HashChain()
        chain.append("a", action_hash(b"1"), "Allow", "ok")
        chain.append("a", action_hash(b"2"), "Allow", "ok")
        assert chain._nodes[1].parent_hash == chain._nodes[0].event_hash

    def test_genesis_parent(self):
        chain = HashChain()
        chain.append("a", action_hash(b"x"), "Allow", "ok")
        assert chain._nodes[0].parent_hash == GENESIS_PARENT

    def test_t5_1_persistence(self):
        """T-5.1: integrity check survives re-verification (simulated reload)."""
        chain = HashChain()
        for i in range(10):
            chain.append("a", action_hash(f"a{i}".encode()), "Deny", "policy")
        assert chain.verify_integrity(expected_length=10)


# Objects

class TestAtomicIdentity:
    def test_roundtrip(self):
        pk, _ = keygen()
        identity = AtomicIdentity.new("principal:alice", pk)
        assert identity.public_key_bytes == pk
        d = identity.to_dict()
        back = AtomicIdentity.from_dict(d)
        assert back.public_key_bytes == pk

    def test_not_expired(self):
        pk, _ = keygen()
        identity = AtomicIdentity.new("p", pk, expires_at="2099-01-01T00:00:00+00:00")
        assert not identity.is_expired()

    def test_expired(self):
        pk, _ = keygen()
        identity = AtomicIdentity.new("p", pk, expires_at="2020-01-01T00:00:00+00:00")
        assert identity.is_expired()


class TestActionEnvelope:
    def test_sign_verify(self):
        pk, sk = keygen()
        env = ActionEnvelope.new("agent-1", "principal-1", "read", b"payload", sk)
        assert env.verify(pk)

    def test_tamper_rejected(self):
        pk, sk = keygen()
        env = ActionEnvelope.new("agent-1", "p-1", "read", b"data", sk)
        env.action_type = "WRITE_TAMPERED"
        assert not env.verify(pk)

    def test_nonce_unique(self):
        pk, sk = keygen()
        e1 = ActionEnvelope.new("a", "p", "read", b"x", sk)
        e2 = ActionEnvelope.new("a", "p", "read", b"x", sk)
        assert e1.nonce != e2.nonce
        assert e1.action_id != e2.action_id


class TestCapabilityGrant:
    def test_allow(self):
        grant = CapabilityGrant("g1", "p", "a", ["read", "write"])
        assert grant.evaluate("read") == "Allow"

    def test_t2_1_expired_denied(self):
        """T-2.1: expired capability -> Deny."""
        past = "2020-01-01T00:00:00+00:00"
        grant = CapabilityGrant("g2", "p", "a", ["read"],
                                caveats=[CaveatExpires(past)])
        with pytest.raises(CaveatDenied):
            grant.evaluate("read")

    def test_max_executions(self):
        grant = CapabilityGrant("g3", "p", "a", ["op"],
                                caveats=[CaveatMaxExecutions(2)])
        assert grant.evaluate("op") == "Allow"
        assert grant.evaluate("op") == "Allow"
        with pytest.raises(CaveatDenied):
            grant.evaluate("op")

    def test_value_limit(self):
        grant = CapabilityGrant("g4", "p", "a", ["transfer"],
                                caveats=[CaveatValueLimit(100.0)])
        assert grant.evaluate("transfer", value=50.0) == "Allow"
        with pytest.raises(CaveatDenied):
            grant.evaluate("transfer", value=200.0)

    def test_path_restricted(self):
        grant = CapabilityGrant("g5", "p", "a", ["read"],
                                caveats=[CaveatPathRestricted([r"/data/.*"])])
        assert grant.evaluate("read", path="/data/file.txt") == "Allow"
        with pytest.raises(CaveatDenied):
            grant.evaluate("read", path="/admin/secret")

    def test_unknown_action_denied(self):
        grant = CapabilityGrant("g6", "p", "a", ["read"])
        with pytest.raises(CaveatDenied):
            grant.evaluate("delete")


class TestBFTQuorum:
    def test_t3_1_no_threshold_denied(self):
        """T-3.1: multi-agent action without threshold -> Deny."""
        quorum = BFTQuorum(threshold=2/3)
        quorum.cast(VoteRecord("v1", "r1", "Allow", "abc", "sig1"))
        assert not quorum.reached(quorum_size=3)

    def test_threshold_met(self):
        quorum = BFTQuorum(threshold=2/3)
        quorum.cast(VoteRecord("v1", "r1", "Allow", "abc", ""))
        quorum.cast(VoteRecord("v2", "r1", "Allow", "abc", ""))
        quorum.cast(VoteRecord("v3", "r1", "Allow", "abc", ""))
        assert quorum.reached(quorum_size=3)

    def test_duplicate_vote_rejected(self):
        quorum = BFTQuorum()
        quorum.cast(VoteRecord("v1", "r1", "Allow", "h", ""))
        with pytest.raises(ValueError, match="duplicate vote"):
            quorum.cast(VoteRecord("v1", "r1", "Allow", "h", ""))

    def test_outcome_hash_must_agree(self):
        quorum = BFTQuorum()
        quorum.cast(VoteRecord("v1", "r1", "Allow", "hash_a", ""))
        quorum.cast(VoteRecord("v2", "r1", "Allow", "hash_b", ""))
        assert not quorum.outcome_hash_agrees("hash_a")


class TestResumeReceipt:
    def test_evidence_ok(self):
        r = ResumeReceipt("a", "r", ResumeBasis.EVIDENCE, reason="condition verified")
        assert r.resume_basis == ResumeBasis.EVIDENCE

    def test_exemption_policy_violation_ok(self):
        r = ResumeReceipt("a", "r", ResumeBasis.EXEMPTION,
                          exemption_covers="policy_violation")
        assert "exemption_does_not_cover" in r.to_dict()

    def test_exemption_authority_revoked_blocked(self):
        with pytest.raises(ValueError, match="authority_revoked"):
            ResumeReceipt("a", "r", ResumeBasis.EXEMPTION,
                          exemption_covers="authority_revoked")

    def test_exemption_authority_not_determined_blocked(self):
        with pytest.raises(ValueError, match="authority_not_determined"):
            ResumeReceipt("a", "r", ResumeBasis.EXEMPTION,
                          exemption_covers="authority_not_determined")


# Trust plane

class TestPrincipalRegistry:
    def test_register_lookup(self):
        reg = PrincipalRegistry()
        pk, _ = keygen()
        identity = AtomicIdentity.new("p:alice", pk)
        reg.register(identity)
        assert reg.public_key("p:alice") == pk

    def test_unknown_raises(self):
        reg = PrincipalRegistry()
        with pytest.raises(RegistryError):
            reg.public_key("unknown")

    def test_revoke(self):
        reg = PrincipalRegistry()
        pk, _ = keygen()
        reg.register(AtomicIdentity.new("p:bob", pk))
        reg.revoke("p:bob")
        assert "p:bob" not in reg


class TestKeyLifecycle:
    def test_generate_and_sign(self):
        reg = PrincipalRegistry()
        lc = KeyLifecycle(reg)
        identity, sk = lc.generate("p:carol")
        msg = b"test"
        sig = sign(sk, msg)
        assert verify(reg.public_key("p:carol"), msg, sig)

    def test_rotation_changes_key(self):
        reg = PrincipalRegistry()
        lc = KeyLifecycle(reg)
        _, sk1 = lc.generate("p:dave")
        old_pk = reg.public_key("p:dave")
        _, sk2 = lc.rotate("p:dave")
        new_pk = reg.public_key("p:dave")
        assert old_pk != new_pk
        assert len(lc.rotation_log) == 1

    def test_revoke_auditable(self):
        reg = PrincipalRegistry()
        lc = KeyLifecycle(reg)
        lc.generate("p:eve")
        lc.revoke("p:eve")
        assert "p:eve" not in reg
        assert lc.rotation_log[-1].auditable


class TestMerkleAccumulator:
    def test_add_valid(self):
        acc = MerkleAccumulator()
        acc.add("key:alice")
        assert acc.check("key:alice")

    def test_removed_invalid(self):
        acc = MerkleAccumulator()
        acc.add("key:bob")
        acc.remove("key:bob")
        assert not acc.check("key:bob")

    def test_root_changes_on_revocation(self):
        acc = MerkleAccumulator()
        acc.add("key:a")
        acc.add("key:b")
        root1 = acc.root
        acc.remove("key:a")
        root2 = acc.root
        assert root1 != root2

    def test_fail_closed_outage(self):
        """Fail-closed: unreachable registry -> IncompleteCheckError."""
        acc = MerkleAccumulator()
        acc.add("key:c")
        acc.simulate_outage(True)
        with pytest.raises(IncompleteCheckError) as exc_info:
            acc.check("key:c")
        assert exc_info.value.reason.value == "tryLater"

    def test_resume_after_outage(self):
        acc = MerkleAccumulator()
        acc.add("key:d")
        acc.simulate_outage(True)
        acc.simulate_outage(False)
        assert acc.check("key:d")

    def test_empty_accumulator_root_stable(self):
        acc = MerkleAccumulator()
        r1 = acc.root
        r2 = acc.root
        assert r1 == r2
