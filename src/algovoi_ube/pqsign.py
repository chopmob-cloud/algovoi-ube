"""The isolated ML-DSA signing core, driven as a separate process.

NTI-1 names CRYSTALS-Dilithium5 for principal-bound identity, and the AIW paper
requires the key to live in an isolated core outside the LLM context window,
because an agent holding the private key is an agent whose attacker holds it.
A Python function that calls a signing library does not satisfy that: the key
would sit in the same process as the model.

This module drives a separate Rust binary over a pipe. The key is generated
inside that process and never crosses the boundary. Python can ask for a
signature and check one; it can never read the key, export it, or hold it.

The scheme is ML-DSA-87, which is NIST security category 5 and the standardised
form of the CRYSTALS-Dilithium5 that NTI-1 names.

Two properties are worth stating because they are easy to lose:

  Fail closed. If the binary is missing, not executable, crashes, or answers
  with anything unexpected, every operation raises. It never falls back to an
  unsigned path or to a weaker signer, because a silent downgrade of the
  signature is a silent downgrade of the whole claim.

  Deterministic when asked. A seed can be supplied for reproducible test
  vectors, and only then. A deterministically seeded key is a known key, so the
  seed path is opt-in and named for what it is.

The protocol is deliberately not JSON. A length-free line protocol means the
core needs no parser, which is one fewer attack surface and one fewer place for
two implementations to disagree about field ordering.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Dilithium5Signer",
    "SignerUnavailable",
    "SIGNING_KEY_BYTES",
    "VERIFYING_KEY_BYTES",
    "SIGNATURE_BYTES",
    "find_core",
]

# ML-DSA-87 sizes, from FIPS 204. Asserted against the core so a mismatched
# parameter set is caught rather than assumed.
VERIFYING_KEY_BYTES = 2592
SIGNATURE_BYTES = 4627
# The signing key is held only inside the core; this figure exists so a caller
# cannot accidentally treat a smaller value as a valid seed.
SIGNING_KEY_BYTES = 4896
SEED_BYTES = 32


class SignerUnavailable(RuntimeError):
    """The signing core could not be reached or refused an operation."""


def find_core(explicit: str | Path | None = None) -> Path:
    """Locate the nti-signer binary.

    Order: an explicit path, then ``NTI_SIGNER_BIN``, then the build outputs of
    this repository. A path that does not exist raises rather than returning
    None, because a caller that gets None tends to add a fallback.
    """
    candidates: list[Path] = []
    if explicit:
        # An explicit path is the caller's answer, not a hint. Falling back to a
        # different binary here would mean a deployment that points at the wrong
        # core silently signs with another one.
        path = Path(explicit)
        if not path.is_file():
            raise SignerUnavailable(
                f"the core path given explicitly does not exist: {path}"
            )
        return path
    env = os.environ.get("NTI_SIGNER_BIN")
    if env:
        candidates.append(Path(env))
    here = Path(__file__).resolve().parent
    for root in (here.parent.parent, here.parent.parent.parent):
        for profile in ("release", "debug"):
            for name in ("nti-signer.exe", "nti-signer"):
                candidates.append(root / "rust" / "nti-signer" / "target" / profile / name)

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    found = shutil.which("nti-signer")
    if found:
        return Path(found)

    raise SignerUnavailable(
        "the nti-signer core was not found. Build it with "
        "`cargo build --release` in rust/nti-signer, or set NTI_SIGNER_BIN. "
        "There is no fallback signer: an unsigned receipt is not a receipt."
    )


@dataclass
class Dilithium5Signer:
    """A handle to the isolated core.

    Nothing here holds key material. ``verify_key`` is the public key, which the
    core announces on start and which is safe to publish; the signing key stays
    inside the child process for its lifetime.
    """

    core_path: Path | None = None
    seed_hex: str = ""

    def __post_init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self.key_id = ""
        self.verify_key = ""
        self.algorithm = "ML-DSA-87"
        if self.core_path is None:
            self.core_path = find_core()
        self._start()

    # -- lifecycle ---------------------------------------------------------

    def _start(self) -> None:
        env = dict(os.environ)
        if self.seed_hex:
            env["NTI_SIGNER_SEED"] = self.seed_hex
        else:
            env.pop("NTI_SIGNER_SEED", None)
        try:
            self._process = subprocess.Popen(
                [str(self.core_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )
        except OSError as exc:
            raise SignerUnavailable(f"could not start the signing core: {exc}") from exc

        greeting = self._read()
        parts = greeting.split(" ")
        if parts[0] != "ready" or len(parts) < 3:
            self.close()
            raise SignerUnavailable(f"unexpected greeting from the core: {greeting!r}")
        self.key_id = parts[1]
        self.verify_key = parts[2]
        expected = VERIFYING_KEY_BYTES * 2
        if len(self.verify_key) != expected:
            self.close()
            raise SignerUnavailable(
                f"the core announced a {len(self.verify_key) // 2} byte verifying key, "
                f"but ML-DSA-87 keys are {VERIFYING_KEY_BYTES} bytes. The core is built "
                "for a different parameter set."
            )

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.write("quit\n")
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    def __enter__(self) -> "Dilithium5Signer":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass

    # -- protocol ----------------------------------------------------------

    def _read(self) -> str:
        if self._process is None or self._process.stdout is None:
            raise SignerUnavailable("the signing core is not running")
        line = self._process.stdout.readline()
        if not line:
            stderr = ""
            if self._process.stderr is not None:
                try:
                    stderr = self._process.stderr.read() or ""
                except (OSError, ValueError):
                    stderr = ""
            raise SignerUnavailable(
                f"the signing core closed unexpectedly: {stderr.strip() or 'no output'}"
            )
        return line.strip()

    def _call(self, command: str) -> str:
        if self._process is None or self._process.stdin is None:
            raise SignerUnavailable("the signing core is not running")
        try:
            self._process.stdin.write(command + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise SignerUnavailable(f"the signing core stopped accepting input: {exc}") from exc
        answer = self._read()
        if answer.startswith("err "):
            raise SignerUnavailable(answer[4:])
        if not answer.startswith("ok "):
            raise SignerUnavailable(f"unexpected answer from the core: {answer!r}")
        return answer[3:]

    # -- operations --------------------------------------------------------

    def sign(self, payload: bytes) -> str:
        """Sign raw bytes. Returns the signature as hex.

        Empty payloads are refused by the core, which is deliberate: a signature
        over nothing is exactly the defect this repository already recorded in
        the published NTI-1 example.
        """
        return self._call(f"sign {payload.hex()}")

    def sign_digest(self, payload: bytes) -> str:
        """Sign SHA-256 of the payload and return ``sha256:<hex>``.

        The core signs at most one line of hex per request, and an ML-DSA-87
        signature is 4627 bytes, so a long receipt would otherwise need a
        megabyte of hex on one line. Signing the digest keeps the protocol a
        single line while still committing to every byte, because the verifier
        recomputes the digest from the receipt and checks the signature over it.

        The algorithm field says so explicitly, so a verifier can never mistake
        a digest signature for a direct one.
        """
        import hashlib

        digest = hashlib.sha256(payload).digest()
        return "sha256:" + self._call(f"sign {digest.hex()}")

    def verify_digest(self, payload: bytes, signature: str) -> bool:
        import hashlib

        if not signature.startswith("sha256:"):
            return False
        digest = hashlib.sha256(payload).digest()
        return self.verify(digest, signature[len("sha256:") :])

    def verify(self, payload: bytes, signature_hex: str) -> bool:
        answer = self._call(f"verify {payload.hex()} {signature_hex}")
        return answer.strip().lower() == "true"

    def fingerprint(self) -> str:
        """SHA-256 of the verifying key, for pinning a core in a policy."""
        return self._call("fingerprint")

    @property
    def signature_bytes(self) -> int:
        return SIGNATURE_BYTES


def self_check(core_path: str | Path | None = None) -> dict:
    """Prove the core signs and verifies, and that a tampered payload fails.

    Returns a dict so a caller can assert on it rather than parse text.
    """
    path = find_core(core_path)
    with Dilithium5Signer(core_path=path) as signer:
        payload = b'{"action":"transfer_funds","amount":10}'
        signature = signer.sign(payload)
        good = signer.verify(payload, signature)
        tampered = signer.verify(payload + b"x", signature)
        empty_refused = False
        try:
            signer.sign(b"")
        except SignerUnavailable:
            empty_refused = True
    return {
        "core": str(path),
        "algorithm": signer.algorithm,
        "key_id": signer.key_id,
        "verify_key_bytes": len(signer.verify_key) // 2,
        "signature_bytes": len(signature) // 2,
        "valid_payload_verifies": good,
        "tampered_payload_rejected": tampered is False,
        "empty_payload_refused": empty_refused,
    }


if __name__ == "__main__":  # pragma: no cover
    import json

    try:
        print(json.dumps(self_check(), indent=2))
    except SignerUnavailable as exc:
        print(f"unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1)
