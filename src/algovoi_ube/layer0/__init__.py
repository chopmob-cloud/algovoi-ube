"""NTI-1 Layer 0 -- cryptographic substrate.

Optional extra: install with ``pip install algovoi-ube[layer0]``.
Requires pqcrypto>=0.4,<2 and jcs>=0.2 (both Apache-2.0).
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 AlgoVoi
from __future__ import annotations

try:
    from .crypto.dilithium import keygen, sign, verify, ALGORITHM, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE
    from .crypto.jcs_canon import canonicalize, sha256_canonical
    from .crypto.hashchain import HashChain, ChainNode, GENESIS_PARENT, action_hash
    from .objects.identity import AtomicIdentity
    from .objects.envelope import ActionEnvelope
    from .objects.capability import CapabilityGrant, CaveatDenied, CaveatExpires, CaveatMaxExecutions, CaveatValueLimit, CaveatPathRestricted
    from .objects.audit import BFTQuorum, VoteRecord, ResumeReceipt, ResumeBasis
    from .trust.registry import PrincipalRegistry, RegistryError
    from .trust.lifecycle import KeyLifecycle
    from .trust.revocation import MerkleAccumulator, MerkleRevocationRegistry, IncompleteCheckError
except ImportError as _err:
    raise ImportError(
        "algovoi_ube.layer0 requires pqcrypto and jcs. "
        'Install them with: pip install "algovoi-ube[layer0]"'
    ) from _err

__all__ = [
    "keygen", "sign", "verify", "ALGORITHM", "PUBLIC_KEY_SIZE", "SECRET_KEY_SIZE", "SIGNATURE_SIZE",
    "canonicalize", "sha256_canonical",
    "HashChain", "ChainNode", "GENESIS_PARENT", "action_hash",
    "AtomicIdentity",
    "ActionEnvelope",
    "CapabilityGrant", "CaveatDenied", "CaveatExpires", "CaveatMaxExecutions", "CaveatValueLimit", "CaveatPathRestricted",
    "BFTQuorum", "VoteRecord", "ResumeReceipt", "ResumeBasis",
    "PrincipalRegistry", "RegistryError",
    "KeyLifecycle",
    "MerkleAccumulator", "MerkleRevocationRegistry", "IncompleteCheckError",
]
