use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gitx_core::{GitxError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length (in hex characters) of a public-key fingerprint (128-bit BLAKE3 prefix).
pub const FINGERPRINT_HEX_LEN: usize = 32;

/// Compute the deterministic BLAKE3 fingerprint of an X25519 + Ed25519 public key pair.
pub fn compute_fingerprint(x25519_public: &[u8; 32], ed25519_public: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"gitx:pubkey:v1\0");
    hasher.update(x25519_public);
    hasher.update(ed25519_public);
    let digest = hasher.finalize();
    hex::encode(&digest.as_bytes()[..FINGERPRINT_HEX_LEN / 2])
}

/// Serializable public key bundle for a GitX user, CI runner, or machine identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub x25519_public: [u8; 32],
    pub ed25519_public: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl PublicKeyBundle {
    /// BLAKE3 hex prefix uniquely identifying this public key pair.
    pub fn fingerprint(&self) -> String {
        compute_fingerprint(&self.x25519_public, &self.ed25519_public)
    }

    pub fn x25519_public_key(&self) -> PublicKey {
        PublicKey::from(self.x25519_public)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|e| GitxError::Crypto(format!("invalid Ed25519 public key: {e}")))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = self.verifying_key()?;
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig)
            .map_err(|e| GitxError::Crypto(format!("signature verification failed: {e}")))
    }
}

/// Serializable secret key bundle for persisting a user's keypair (zeroized on drop).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBundle {
    pub x25519_secret: [u8; 32],
    pub ed25519_secret: [u8; 32],
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl fmt::Debug for SecretKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKeyBundle")
            .field("x25519_secret", &"[REDACTED]")
            .field("ed25519_secret", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

/// In-memory cryptographic identity combining an X25519 key-agreement pair
/// and an Ed25519 signing pair. Private key bytes are automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserKeyPair {
    x25519_secret: [u8; 32],
    #[zeroize(skip)]
    x25519_public: [u8; 32],
    ed25519_secret: [u8; 32],
    #[zeroize(skip)]
    ed25519_public: [u8; 32],
    #[zeroize(skip)]
    label: Option<String>,
}

impl UserKeyPair {
    /// Generate a fresh random X25519 + Ed25519 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_inner(None)
    }

    /// Generate a fresh random keypair tagged with a human-readable label.
    pub fn generate_with_label(label: impl Into<String>) -> Self {
        Self::generate_inner(Some(label.into()))
    }

    fn generate_inner(label: Option<String>) -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = PublicKey::from(&x_secret);
        let ed_signing = SigningKey::generate(&mut OsRng);
        let ed_verifying = ed_signing.verifying_key();

        Self {
            x25519_secret: x_secret.to_bytes(),
            x25519_public: x_public.to_bytes(),
            ed25519_secret: ed_signing.to_bytes(),
            ed25519_public: ed_verifying.to_bytes(),
            label,
        }
    }

    /// Reconstruct a `UserKeyPair` from a serialized `SecretKeyBundle`.
    pub fn from_secret_bundle(bundle: &SecretKeyBundle) -> Result<Self> {
        let x_secret = StaticSecret::from(bundle.x25519_secret);
        let x_public = PublicKey::from(&x_secret);
        let ed_signing = SigningKey::from_bytes(&bundle.ed25519_secret);
        let ed_verifying = ed_signing.verifying_key();

        Ok(Self {
            x25519_secret: x_secret.to_bytes(),
            x25519_public: x_public.to_bytes(),
            ed25519_secret: ed_signing.to_bytes(),
            ed25519_public: ed_verifying.to_bytes(),
            label: bundle.label.clone(),
        })
    }

    /// Export private key bytes into a serializable `SecretKeyBundle`.
    pub fn to_secret_bundle(&self) -> SecretKeyBundle {
        SecretKeyBundle {
            x25519_secret: self.x25519_secret,
            ed25519_secret: self.ed25519_secret,
            label: self.label.clone(),
        }
    }

    /// Export the public half of this identity.
    pub fn public_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            x25519_public: self.x25519_public,
            ed25519_public: self.ed25519_public,
            label: self.label.clone(),
        }
    }

    /// BLAKE3 hex prefix of this keypair's public keys.
    pub fn fingerprint(&self) -> String {
        compute_fingerprint(&self.x25519_public, &self.ed25519_public)
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    pub fn x25519_public(&self) -> PublicKey {
        PublicKey::from(self.x25519_public)
    }

    /// Perform X25519 Diffie-Hellman with a peer public key, returning a zeroizing shared secret.
    pub fn x25519_diffie_hellman(&self, peer_public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        let secret = StaticSecret::from(self.x25519_secret);
        let shared = secret.diffie_hellman(peer_public);
        if !shared.was_contributory() {
            return Err(GitxError::Crypto(
                "non-contributory X25519 shared secret".to_string(),
            ));
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.ed25519_public)
            .expect("UserKeyPair always holds a valid Ed25519 verifying key")
    }

    /// Sign arbitrary bytes with the Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing = SigningKey::from_bytes(&self.ed25519_secret);
        signing.sign(message).to_bytes()
    }

    /// Verify a signature produced by this keypair.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key()
            .verify(message, &sig)
            .map_err(|e| GitxError::Crypto(format!("signature verification failed: {e}")))
    }
}

impl fmt::Debug for UserKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKeyPair")
            .field("fingerprint", &self.fingerprint())
            .field("label", &self.label)
            .field("x25519_secret", &"[REDACTED]")
            .field("ed25519_secret", &"[REDACTED]")
            .finish()
    }
}
