"""Dilithium5 wrapper. ML-DSA-87 (NIST FIPS 204) == CRYSTALS-Dilithium5.

Compatible with pqcrypto 0.4.x (generate_keypair / bool verify) and
pqcrypto 1.x (keygen / exception verify).
"""
from __future__ import annotations

from pqcrypto.sign import ml_dsa_87 as _d5

ALGORITHM = "CRYSTALS-Dilithium5"
PUBLIC_KEY_SIZE: int = _d5.PUBLIC_KEY_SIZE    # 2592
SECRET_KEY_SIZE: int = _d5.SECRET_KEY_SIZE    # 4896
SIGNATURE_SIZE: int = _d5.SIGNATURE_SIZE      # 4627

# pqcrypto 1.x renamed generate_keypair -> keygen
if hasattr(_d5, "keygen"):
    _keygen = _d5.keygen
else:
    _keygen = _d5.generate_keypair

# pqcrypto 1.x raises InvalidSignatureError; 0.4.x returns bool
try:
    from pqcrypto import InvalidSignatureError  # type: ignore[attr-defined]
except ImportError:
    class InvalidSignatureError(Exception):  # type: ignore[no-redef]
        pass

_verify_raises = not hasattr(_d5, "generate_keypair")


def keygen() -> tuple[bytes, bytes]:
    pk, sk = _keygen()
    return bytes(pk), bytes(sk)


def sign(sk: bytes, msg: bytes) -> bytes:
    return bytes(_d5.sign(sk, msg))


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    if _verify_raises:
        try:
            _d5.verify(pk, msg, sig)
            return True
        except Exception:
            return False
    else:
        result = _d5.verify(pk, msg, sig)
        return bool(result)
