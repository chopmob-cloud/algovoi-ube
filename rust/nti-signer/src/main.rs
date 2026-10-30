//! Isolated ML-DSA signing core for NTI-1.
//!
//! NTI-1 requires that agent identity be bound to a principal via
//! CRYSTALS-Dilithium5, and the AIW paper requires that the signing key live in
//! an isolated core outside the LLM context window, because an agent holding the
//! private key is an agent whose attacker holds it. This binary is that core.
//!
//! It is a separate process on purpose. The key is generated here, used here, and
//! never serialised to stdout, a socket, or an environment variable. The protocol
//! is a small line-based one so the core needs no JSON parser, which is one fewer
//! attack surface and one fewer opportunity for two implementations to disagree
//! about field ordering.
//!
//! Protocol, one request per line on stdin, one response per line on stdout:
//!
//!   keygen                       -> ok <key_id> <verify_key_hex>
//!   verifykey                    -> ok <verify_key_hex>
//!   sign <hex payload>           -> ok <signature_hex>
//!   verify <hex payload> <hex sig> -> ok true | ok false
//!   fingerprint                  -> ok <sha256 of verify key, hex>
//!   quit                         -> ok bye
//!
//! Any failure answers `err <reason>` and the core stays usable, except for a
//! protocol violation, which exits. The core refuses to sign an empty payload,
//! because a signature over nothing is the audit-record failure the harness
//! already found in the published NTI-1 example.

use std::io::{self, BufRead, Write};

use ml_dsa::{
    signature::{Keypair, Signer, Verifier},
    Generate, MlDsa87, Seed, Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

/// NTI-1 names Dilithium5. In FIPS 204 terms that is ML-DSA-87, NIST security
/// category 5. Using the parameter set the standard names is the whole point.
type Dsa = MlDsa87;

struct Core {
    signing_key: SigningKey<Dsa>,
    verify_key: VerifyingKey<Dsa>,
    key_id: String,
}

impl Core {
    fn new() -> Self {
        // Generated in memory. Deliberately not persisted here: a key at rest is
        // a separate concern from a key in use, and this core's job is the latter.
        let signing_key = SigningKey::<Dsa>::generate();
        let verify_key = signing_key.verifying_key();
        let mut hasher = Sha256::new();
        hasher.update(verify_key.encode().as_slice());
        let digest = hasher.finalize();
        let key_id = hex::encode(&digest[..8]);
        Core {
            signing_key,
            verify_key,
            key_id,
        }
    }

    fn from_seed(seed_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(seed_hex).map_err(|e| format!("bad seed hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        let seed = Seed::try_from(bytes.as_slice())
            .map_err(|_| "seed length rejected by the crate".to_string())?;
        let signing_key = SigningKey::<Dsa>::from_seed(&seed);
        let verify_key = signing_key.verifying_key();
        let mut hasher = Sha256::new();
        hasher.update(verify_key.encode().as_slice());
        let key_id = hex::encode(digest_prefix(&hasher.finalize()));
        Ok(Core {
            signing_key,
            verify_key,
            key_id,
        })
    }

    fn verify_key_hex(&self) -> String {
        hex::encode(self.verify_key.encode().as_slice())
    }

    fn sign(&self, payload: &[u8]) -> Result<String, String> {
        if payload.is_empty() {
            return Err("refusing to sign an empty payload".to_string());
        }
        let signature: Signature<Dsa> = self.signing_key.sign(payload);
        Ok(hex::encode(signature.encode().as_slice()))
    }

    fn verify(&self, payload: &[u8], signature_hex: &str) -> Result<bool, String> {
        let raw = hex::decode(signature_hex).map_err(|e| format!("bad signature hex: {e}"))?;
        let signature = Signature::<Dsa>::try_from(raw.as_slice())
            .map_err(|_| "signature is not a well formed ML-DSA-87 value".to_string())?;
        Ok(self.verify_key.verify(payload, &signature).is_ok())
    }
}

fn digest_prefix(digest: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Optional deterministic seed for reproducible test vectors. Never used in
    // normal operation: a deterministic key is a known key.
    let seed = std::env::var("NTI_SIGNER_SEED").ok();
    let core = match seed.as_deref() {
        Some(value) if !value.is_empty() => match Core::from_seed(value) {
            Ok(core) => core,
            Err(reason) => {
                let _ = writeln!(stdout, "err {reason}");
                let _ = stdout.flush();
                std::process::exit(2);
            }
        },
        _ => Core::new(),
    };

    // Announce readiness and the public key only. The signing key is never
    // printed, and there is no command that exports it.
    let _ = writeln!(stdout, "ready {} {}", core.key_id, core.verify_key_hex());
    let _ = stdout.flush();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let command = parts.next().unwrap_or("");

        let response = match command {
            "keygen" => format!("ok {} {}", core.key_id, core.verify_key_hex()),
            "verifykey" => format!("ok {}", core.verify_key_hex()),
            "fingerprint" => {
                let mut hasher = Sha256::new();
                hasher.update(core.verify_key.encode().as_slice());
                format!("ok {}", hex::encode(hasher.finalize()))
            }
            "sign" => match parts.next() {
                Some(payload_hex) => match hex::decode(payload_hex) {
                    Ok(payload) => match core.sign(&payload) {
                        Ok(signature) => format!("ok {signature}"),
                        Err(reason) => format!("err {reason}"),
                    },
                    Err(e) => format!("err bad payload hex: {e}"),
                },
                None => "err sign needs a hex payload".to_string(),
            },
            "verify" => match (parts.next(), parts.next()) {
                (Some(payload_hex), Some(signature_hex)) => {
                    match hex::decode(payload_hex) {
                        Err(e) => format!("err bad payload hex: {e}"),
                        Ok(payload) => match core.verify(&payload, signature_hex) {
                            Ok(valid) => format!("ok {valid}"),
                            Err(reason) => format!("err {reason}"),
                        },
                    }
                }
                _ => "err verify needs a hex payload and a hex signature".to_string(),
            },
            "quit" => {
                let _ = writeln!(stdout, "ok bye");
                let _ = stdout.flush();
                break;
            }
            other => format!("err unknown command {other}"),
        };

        if writeln!(stdout, "{response}").is_err() {
            break;
        }
        if stdout.flush().is_err() {
            break;
        }
    }
}
