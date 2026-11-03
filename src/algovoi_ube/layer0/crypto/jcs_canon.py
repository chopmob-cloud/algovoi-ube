"""RFC 8785 (JCS) canonicalization.

Every field NTI-1 hashes MUST pass through canonicalize() before sha256()
-- never via string concatenation (prevents preimage collisions; NTI-1 sec 3.4).
"""
import hashlib
import jcs as _jcs


def canonicalize(obj: dict) -> bytes:
    return _jcs.canonicalize(obj)


def sha256_canonical(obj: dict) -> str:
    raw = canonicalize(obj)
    return hashlib.sha256(raw).hexdigest()
