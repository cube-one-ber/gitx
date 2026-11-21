use crate::keys::{PublicKeyBundle, UserKeyPair};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Utc};
use gitx_core::{DomainId, GitxError, ObjectHash, Result};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

/// A Data Encryption Key (DEK) wrapped for a single recipient using
/// ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDek {
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Envelope-encrypted secret stored inside a `secret:*` visibility domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEnvelope {
    pub domain: DomainId,
    pub key_epoch: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: BTreeMap<String, WrappedDek>,
}

impl SecretEnvelope {
    /// Content-addressed BLAKE3 hash of this envelope.
    pub fn hash(&self) -> ObjectHash {
        let bytes = bincode::serialize(self).expect("SecretEnvelope serialization cannot fail");
        ObjectHash::of_typed("gitx:envelope:v1", &bytes)
    }

    /// List recipient fingerprints authorized to unwrap this envelope.
    pub fn recipients(&self) -> Vec<&str> {
        self.wrapped_keys.keys().map(String::as_str).collect()
    }

    /// Returns `true` if `fingerprint` has a wrapped DEK entry in this envelope.
    pub fn has_recipient(&self, fingerprint: &str) -> bool {
        self.wrapped_keys.contains_key(fingerprint)
    }
}

fn build_payload_aad(domain: &DomainId, path: &str, key_epoch: u64) -> Vec<u8> {
    let domain_bytes = domain.as_str().as_bytes();
    let path_bytes = path.as_bytes();
    let mut aad = Vec::with_capacity(23 + 4 + domain_bytes.len() + 4 + path_bytes.len() + 8);
    aad.extend_from_slice(b"gitx:secret-payload:v1\0");
    aad.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(domain_bytes);
    aad.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(path_bytes);
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

fn build_wrap_aad(
    domain: &DomainId,
    path: &str,
    key_epoch: u64,
    recipient_fingerprint: &str,
) -> Vec<u8> {
    let domain_bytes = domain.as_str().as_bytes();
    let path_bytes = path.as_bytes();
    let fp_bytes = recipient_fingerprint.as_bytes();
    let mut aad =
        Vec::with_capacity(20 + 4 + domain_bytes.len() + 4 + path_bytes.len() + 4 + fp_bytes.len() + 8);
    aad.extend_from_slice(b"gitx:secret-wrap:v1\0");
    aad.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(domain_bytes);
    aad.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(path_bytes);
    aad.extend_from_slice(&(fp_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(fp_bytes);
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

fn derive_kek(
    shared_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    domain: &DomainId,
    key_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_public);
    salt[32..].copy_from_slice(recipient_public);

    let domain_bytes = domain.as_str().as_bytes();
    let mut info = Vec::with_capacity(18 + 4 + domain_bytes.len() + 8);
    info.extend_from_slice(b"gitx:dek-kek:v1\0");
    info.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
    info.extend_from_slice(domain_bytes);
    info.extend_from_slice(&key_epoch.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(&info, kek.as_mut())
        .map_err(|e| GitxError::Crypto(format!("HKDF expansion failed: {e}")))?;
    Ok(kek)
}

/// Encrypt a secret payload for a set of recipients using envelope encryption.
///
/// Generates a fresh random 32-byte DEK, encrypts `plaintext` with ChaCha20-Poly1305
/// using AAD bound to `(domain, path, key_epoch)`, and wraps the DEK individually for
/// each recipient via ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.
pub fn encrypt_secret(
    domain: &DomainId,
    path: &str,
    key_epoch: u64,
    plaintext: &[u8],
    recipients: &[PublicKeyBundle],
) -> Result<SecretEnvelope> {
    if recipients.is_empty() {
        return Err(GitxError::Crypto(
            "cannot encrypt secret with zero recipients".to_string(),
        ));
    }

    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(dek.as_mut());

    let mut payload_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut payload_nonce);

    let payload_aad = build_payload_aad(domain, path, key_epoch);
    let payload_cipher = ChaCha20Poly1305::new(Key::from_slice(dek.as_ref()));
    let ciphertext = payload_cipher
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext,
                aad: &payload_aad,
            },
        )
        .map_err(|e| GitxError::Crypto(format!("payload encryption failed: {e}")))?;

    let mut wrapped_keys = BTreeMap::new();
    for recipient in recipients {
        let recipient_fp = recipient.fingerprint();
        let recipient_pub = recipient.x25519_public_key();

        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&recipient_pub);
        if !shared.was_contributory() {
            return Err(GitxError::Crypto(format!(
                "non-contributory X25519 key for recipient '{recipient_fp}'"
            )));
        }
        let shared_bytes = Zeroizing::new(shared.to_bytes());

        let kek = derive_kek(
            &shared_bytes,
            ephemeral_public.as_bytes(),
            recipient_pub.as_bytes(),
            domain,
            key_epoch,
        )?;

        let mut wrap_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut wrap_nonce);

        let wrap_aad = build_wrap_aad(domain, path, key_epoch, &recipient_fp);
        let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
        let wrapped_ct = wrap_cipher
            .encrypt(
                Nonce::from_slice(&wrap_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|e| GitxError::Crypto(format!("DEK wrap failed: {e}")))?;

        wrapped_keys.insert(
            recipient_fp,
            WrappedDek {
                ephemeral_public: ephemeral_public.to_bytes(),
                nonce: wrap_nonce,
                ciphertext: wrapped_ct,
            },
        );
    }

    Ok(SecretEnvelope {
        domain: domain.clone(),
        key_epoch,
        nonce: payload_nonce,
        ciphertext,
        wrapped_keys,
    })
}

/// Decrypt a `SecretEnvelope` using an authorized recipient's `UserKeyPair`.
///
/// Verifies AAD binding against `(envelope.domain, path, envelope.key_epoch)`.
pub fn decrypt_secret(
    envelope: &SecretEnvelope,
    path: &str,
    keypair: &UserKeyPair,
) -> Result<Vec<u8>> {
    let fp = keypair.fingerprint();
    let wrapped = envelope
        .wrapped_keys
        .get(&fp)
        .ok_or_else(|| GitxError::AccessDenied {
            domain: envelope.domain.to_string(),
            reason: format!(
                "key '{fp}' is not an authorized recipient for epoch {}",
                envelope.key_epoch
            ),
        })?;

    let ephemeral_pub = PublicKey::from(wrapped.ephemeral_public);
    let shared_bytes = keypair.x25519_diffie_hellman(&ephemeral_pub)?;
    let recipient_pub = keypair.x25519_public();

    let kek = derive_kek(
        &shared_bytes,
        ephemeral_pub.as_bytes(),
        recipient_pub.as_bytes(),
        &envelope.domain,
        envelope.key_epoch,
    )?;

    let wrap_aad = build_wrap_aad(&envelope.domain, path, envelope.key_epoch, &fp);
    let wrap_cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let unwrapped = Zeroizing::new(
        wrap_cipher
            .decrypt(
                Nonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| GitxError::Crypto("DEK unwrap authentication failed".to_string()))?,
    );

    if unwrapped.len() != 32 {
        return Err(GitxError::Crypto(format!(
            "unwrapped DEK has invalid length: expected 32, got {}",
            unwrapped.len()
        )));
    }

    let payload_aad = build_payload_aad(&envelope.domain, path, envelope.key_epoch);
    let payload_cipher = ChaCha20Poly1305::new(Key::from_slice(&unwrapped));
    let plaintext = payload_cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &payload_aad,
            },
        )
        .map_err(|_| GitxError::Crypto("secret payload authentication failed".to_string()))?;

    Ok(plaintext)
}

/// Rotate an existing secret envelope to `old.key_epoch + 1` with a brand-new DEK
/// and a new recipient set, immediately excluding any revoked recipients.
pub fn rotate_secret(
    old: &SecretEnvelope,
    path: &str,
    author_key: &UserKeyPair,
    new_recipients: &[PublicKeyBundle],
) -> Result<SecretEnvelope> {
    let next_epoch = old
        .key_epoch
        .checked_add(1)
        .ok_or_else(|| GitxError::Crypto("key epoch overflow".to_string()))?;

    let plaintext = Zeroizing::new(decrypt_secret(old, path, author_key)?);
    encrypt_secret(&old.domain, path, next_epoch, &plaintext, new_recipients)
}

/// Immutable audit event tracking secret decryption and principal revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessEvent {
    Decrypted {
        fingerprint: String,
        domain: DomainId,
        path: String,
        key_epoch: u64,
        timestamp: DateTime<Utc>,
    },
    Revoked {
        fingerprint: String,
        domain: DomainId,
        timestamp: DateTime<Utc>,
    },
}

/// Summary of a specific secret version `(domain, path, key_epoch)` that a revoked
/// principal previously decrypted and which therefore must be rotated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExposedSecret {
    pub domain: DomainId,
    pub path: String,
    pub key_epoch: u64,
    pub first_accessed: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u64,
}

/// Append-only audit log of secret accesses and revocations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAuditLog {
    events: Vec<AccessEvent>,
}

impl SecretAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, event: AccessEvent) {
        self.events.push(event);
    }

    pub fn record_decrypt(
        &mut self,
        fingerprint: impl Into<String>,
        domain: DomainId,
        path: impl Into<String>,
        key_epoch: u64,
    ) {
        self.record_decrypt_at(fingerprint, domain, path, key_epoch, Utc::now());
    }

    pub fn record_decrypt_at(
        &mut self,
        fingerprint: impl Into<String>,
        domain: DomainId,
        path: impl Into<String>,
        key_epoch: u64,
        timestamp: DateTime<Utc>,
    ) {
        self.events.push(AccessEvent::Decrypted {
            fingerprint: fingerprint.into(),
            domain,
            path: path.into(),
            key_epoch,
            timestamp,
        });
    }

    pub fn record_revoke(&mut self, fingerprint: impl Into<String>, domain: DomainId) {
        self.record_revoke_at(fingerprint, domain, Utc::now());
    }

    pub fn record_revoke_at(
        &mut self,
        fingerprint: impl Into<String>,
        domain: DomainId,
        timestamp: DateTime<Utc>,
    ) {
        self.events.push(AccessEvent::Revoked {
            fingerprint: fingerprint.into(),
            domain,
            timestamp,
        });
    }

    pub fn events(&self) -> &[AccessEvent] {
        &self.events
    }

    /// Compute the deterministic list of every `(domain, path, key_epoch)` ever decrypted
    /// by `revoked_fingerprint`.
    pub fn rotation_report_for_revoked(&self, revoked_fingerprint: &str) -> Vec<ExposedSecret> {
        rotation_report_for_revoked(&self.events, revoked_fingerprint)
    }
}

type ExposureKey = (DomainId, String, u64);
type ExposureSpan = (DateTime<Utc>, DateTime<Utc>, u64);

/// Produce a deterministic rotation report listing every unique `(domain, path, key_epoch)`
/// that `revoked_fingerprint` ever decrypted in `events`.
pub fn rotation_report_for_revoked(
    events: &[AccessEvent],
    revoked_fingerprint: &str,
) -> Vec<ExposedSecret> {
    let mut exposures: BTreeMap<ExposureKey, ExposureSpan> = BTreeMap::new();

    for event in events {
        if let AccessEvent::Decrypted {
            fingerprint,
            domain,
            path,
            key_epoch,
            timestamp,
        } = event
        {
            if fingerprint != revoked_fingerprint {
                continue;
            }
            let key = (domain.clone(), path.clone(), *key_epoch);
            exposures
                .entry(key)
                .and_modify(|(first, last, count)| {
                    if *timestamp < *first {
                        *first = *timestamp;
                    }
                    if *timestamp > *last {
                        *last = *timestamp;
                    }
                    *count += 1;
                })
                .or_insert((*timestamp, *timestamp, 1));
        }
    }

    exposures
        .into_iter()
        .map(
            |((domain, path, key_epoch), (first_accessed, last_accessed, access_count))| {
                ExposedSecret {
                    domain,
                    path,
                    key_epoch,
                    first_accessed,
                    last_accessed,
                    access_count,
                }
            },
        )
        .collect()
}
