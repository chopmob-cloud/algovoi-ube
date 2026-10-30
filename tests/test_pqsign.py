"""Tests for the isolated ML-DSA signing core.

These are skipped when the Rust binary is absent, but skipped is not passed: the
skip reason says how to build it, and the clean-room stages assert the core is
present so a missing binary cannot masquerade as a green run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.pqsign import (  # noqa: E402
    SIGNATURE_BYTES,
    VERIFYING_KEY_BYTES,
    Dilithium5Signer,
    SignerUnavailable,
    find_core,
    self_check,
)

BUILD_HINT = (
    "the ML-DSA core is not built. Run `cargo build --release` in "
    "rust/nti-signer, or set NTI_SIGNER_BIN."
)


def core_available() -> bool:
    try:
        find_core()
        return True
    except SignerUnavailable:
        return False


pytestmark = pytest.mark.skipif(not core_available(), reason=BUILD_HINT)


def test_the_core_signs_and_verifies():
    result = self_check()
    assert result["valid_payload_verifies"] is True
    assert result["tampered_payload_rejected"] is True
    assert result["empty_payload_refused"] is True


def test_the_parameter_set_is_the_one_nti_names():
    """ML-DSA-87 is category 5, the standardised form of Dilithium5."""
    with Dilithium5Signer() as signer:
        assert signer.algorithm == "ML-DSA-87"
        assert len(signer.verify_key) // 2 == VERIFYING_KEY_BYTES


def test_signatures_are_the_documented_length():
    with Dilithium5Signer() as signer:
        signature = signer.sign(b"a real payload")
        assert len(signature) // 2 == SIGNATURE_BYTES


def test_a_tampered_payload_is_rejected():
    with Dilithium5Signer() as signer:
        signature = signer.sign(b"original")
        assert signer.verify(b"original", signature) is True
        assert signer.verify(b"original ", signature) is False
        assert signer.verify(b"originaL", signature) is False


def test_an_empty_payload_is_refused():
    """A signature over nothing is the defect found in the published example."""
    with Dilithium5Signer() as signer:
        with pytest.raises(SignerUnavailable):
            signer.sign(b"")


def test_the_signing_key_never_crosses_the_boundary():
    """The public key is published; nothing exposes the private key."""
    with Dilithium5Signer() as signer:
        assert len(signer.verify_key) // 2 == VERIFYING_KEY_BYTES
        # No attribute on the handle holds key material.
        for name in ("signing_key", "private_key", "seed", "secret"):
            assert not hasattr(signer, name), name


def test_a_seeded_core_is_reproducible():
    """The seed path exists for vectors, and produces the same key twice."""
    seed = "00" * 32
    with Dilithium5Signer(seed_hex=seed) as first:
        key_one = first.verify_key
        sig_one = first.sign(b"vector payload")
    with Dilithium5Signer(seed_hex=seed) as second:
        key_two = second.verify_key
        sig_two = second.sign(b"vector payload")
    assert key_one == key_two
    assert sig_one == sig_two, "ML-DSA-87 signing must be deterministic for a fixed seed"


def test_different_keys_do_not_verify_each_others_signatures():
    with Dilithium5Signer() as first, Dilithium5Signer() as second:
        signature = first.sign(b"payload")
        assert first.verify(b"payload", signature) is True
        assert second.verify(b"payload", signature) is False


def test_a_missing_core_raises_rather_than_falling_back():
    """There is no weaker signer to fall back to, and there must not be."""
    with pytest.raises(SignerUnavailable):
        find_core("C:/definitely/not/a/binary")


def test_the_fingerprint_pins_the_key():
    with Dilithium5Signer() as signer:
        fingerprint = signer.fingerprint()
        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)
