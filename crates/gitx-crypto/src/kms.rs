//! Pluggable KMS / OIDC envelope key-wrapping and identity verification providers.
//!
//! Enables enterprises to wrap secret DEKs through external KMS backends (AWS KMS, HashiCorp
//! Vault Transit, GCP KMS, or local master keys) and verify Ed25519-signed OIDC/JWT bearer
//! identity assertions alongside standard developer X25519 / SSH keys.

use crate::acl::Principal;
use crate::envelope::SecretEnvelope;
use crate::keys::{PublicKeyBundle, UserKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gitx_core::{DomainId, GitxError, Result};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Pluggable DEK wrapping backend (AWS KMS, Vault Transit, hardware HSM, or local master key).
pub trait KeyWrapProvider: Send + Sync {
    /// Stable provider identifier (e.g., `"local-kms"`, `"aws-kms"`, `"vault-transit"`).
    fn provider_id(&self) -> &str;

    /// Wrap a 32-byte Data Encryption Key under `key_ref` binding `aad` into integrity checks.
    fn wrap_dek(&self, dek: &[u8; 32], key_ref: &str, aad: &[u8]) -> Result<Vec<u8>>;

    /// Unwrap a 32-byte Data Encryption Key using `key_ref` and `aad`.
    fn unwrap_dek(&self, wrapped: &[u8], key_ref: &str, aad: &[u8]) -> Result<[u8; 32]>;
}

/// Encrypted KMS-wrapped DEK entry attachable to a [`KmsHybridEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsWrappedDek {
    pub provider_id: String,
    pub key_ref: String,
    pub ciphertext: Vec<u8>,
}

/// Hybrid secret envelope supporting BOTH developer X25519/SSH recipients and external KMS
/// key wraps over the same secret payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsHybridEnvelope {
    pub domain: DomainId,
    pub path: String,
    pub key_epoch: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub kms_wraps: Vec<KmsWrappedDek>,
    pub standard_envelope: Option<SecretEnvelope>,
}

impl KmsHybridEnvelope {
    /// Encrypt `plaintext` under a fresh random DEK wrapped by one or more KMS providers
    /// (and optionally also for X25519/SSH `recipients`).
    pub fn seal(
        domain: &DomainId,
        path: &str,
        key_epoch: u64,
        plaintext: &[u8],
        kms_targets: &[(&dyn KeyWrapProvider, &str)],
        recipients: &[PublicKeyBundle],
    ) -> Result<Self> {
        if kms_targets.is_empty() && recipients.is_empty() {
            return Err(GitxError::Crypto(
                "KmsHybridEnvelope::seal requires at least one KMS target or X25519 recipient"
                    .into(),
            ));
        }

        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *dek);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let aad = kms_aad(domain, path, key_epoch);
        let cipher = ChaCha20Poly1305::new_from_slice(&*dek)
            .map_err(|e| GitxError::Crypto(format!("invalid DEK: {e}")))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| GitxError::Crypto(format!("KMS hybrid payload encrypt failed: {e}")))?;

        let mut kms_wraps = Vec::with_capacity(kms_targets.len());
        for (provider, key_ref) in kms_targets {
            let wrapped = provider.wrap_dek(&dek, key_ref, &aad)?;
            kms_wraps.push(KmsWrappedDek {
                provider_id: provider.provider_id().to_string(),
                key_ref: (*key_ref).to_string(),
                ciphertext: wrapped,
            });
        }

        let standard_envelope = if !recipients.is_empty() {
            Some(crate::envelope::encrypt_secret(
                domain, path, key_epoch, plaintext, recipients,
            )?)
        } else {
            None
        };

        Ok(Self {
            domain: domain.clone(),
            path: path.to_string(),
            key_epoch,
            nonce: nonce_bytes,
            ciphertext,
            kms_wraps,
            standard_envelope,
        })
    }

    /// Decrypt using a [`KeyWrapProvider`] matching one of `self.kms_wraps`.
    pub fn open_with_kms(&self, provider: &dyn KeyWrapProvider) -> Result<Vec<u8>> {
        let aad = kms_aad(&self.domain, &self.path, self.key_epoch);
        let wrap = self
            .kms_wraps
            .iter()
            .find(|w| w.provider_id == provider.provider_id())
            .ok_or_else(|| GitxError::AccessDenied {
                domain: self.domain.to_string(),
                reason: format!(
                    "no KMS wrap found for provider '{}'",
                    provider.provider_id()
                ),
            })?;

        let dek = Zeroizing::new(provider.unwrap_dek(&wrap.ciphertext, &wrap.key_ref, &aad)?);
        let cipher = ChaCha20Poly1305::new_from_slice(&*dek)
            .map_err(|e| GitxError::Crypto(format!("invalid unwrapped DEK: {e}")))?;
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                GitxError::Crypto(
                    "KMS hybrid payload decryption failed (tampered ciphertext or AAD mismatch)"
                        .into(),
                )
            })
    }

    /// Decrypt using a developer's local [`UserKeyPair`] if recipient wraps were included.
    pub fn open_with_keypair(&self, keypair: &UserKeyPair) -> Result<Vec<u8>> {
        let Some(ref env) = self.standard_envelope else {
            return Err(GitxError::AccessDenied {
                domain: self.domain.to_string(),
                reason: "envelope has no local X25519 recipient wraps; decrypt via KMS".into(),
            });
        };
        crate::envelope::decrypt_secret(env, &self.path, keypair)
    }
}

fn kms_aad(domain: &DomainId, path: &str, key_epoch: u64) -> Vec<u8> {
    format!("gitx:kms-envelope:v1:{domain}:{path}:{key_epoch}").into_bytes()
}

/// Deterministic master-key KMS provider using HKDF-SHA256 per-`key_ref` subkeys +
/// ChaCha20-Poly1305 AEAD. Supports multi-key registries and rotation without external services.
pub struct LocalKmsProvider {
    provider_id: String,
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

impl LocalKmsProvider {
    pub fn new(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            keys: BTreeMap::new(),
        }
    }

    pub fn with_key(mut self, key_ref: impl Into<String>, master_key: [u8; 32]) -> Self {
        self.keys.insert(key_ref.into(), Zeroizing::new(master_key));
        self
    }

    pub fn generate_key(&mut self, key_ref: impl Into<String>) -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        self.keys.insert(key_ref.into(), Zeroizing::new(key));
        key
    }

    fn derive_wrapping_key(&self, key_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
        let master = self.keys.get(key_ref).ok_or_else(|| {
            GitxError::NotFound(format!(
                "KMS key_ref '{key_ref}' not found in provider '{}'",
                self.provider_id
            ))
        })?;
        let hk = Hkdf::<Sha256>::new(Some(b"gitx:kms-wrap:v1"), &**master);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(key_ref.as_bytes(), &mut *out)
            .map_err(|_| GitxError::Crypto("HKDF expand failed for KMS key".into()))?;
        Ok(out)
    }
}

impl KeyWrapProvider for LocalKmsProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn wrap_dek(&self, dek: &[u8; 32], key_ref: &str, aad: &[u8]) -> Result<Vec<u8>> {
        let kek = self.derive_wrapping_key(key_ref)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(&*kek)
            .map_err(|e| GitxError::Crypto(format!("invalid KMS KEK: {e}")))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: dek, aad })
            .map_err(|e| GitxError::Crypto(format!("KMS wrap failed: {e}")))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap_dek(&self, wrapped: &[u8], key_ref: &str, aad: &[u8]) -> Result<[u8; 32]> {
        if wrapped.len() < 12 + 16 {
            return Err(GitxError::Crypto("truncated KMS wrapped DEK".into()));
        }
        let kek = self.derive_wrapping_key(key_ref)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&*kek)
            .map_err(|e| GitxError::Crypto(format!("invalid KMS KEK: {e}")))?;
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&wrapped[..12]),
                    Payload {
                        msg: &wrapped[12..],
                        aad,
                    },
                )
                .map_err(|_| GitxError::AccessDenied {
                    domain: "kms".to_string(),
                    reason: format!("KMS unwrap failed for key_ref '{key_ref}'"),
                })?,
        );
        if pt.len() != 32 {
            return Err(GitxError::Crypto(format!(
                "invalid unwrapped DEK length: {}",
                pt.len()
            )));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&pt);
        Ok(dek)
    }
}

// ---------------------------------------------------------------------------
// OIDC EdDSA (Ed25519) JWT Assertion Verifier -> Principal
// ---------------------------------------------------------------------------

/// Standard OIDC / JWT identity claims mapped onto a GitX [`Principal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub teams: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
}

/// Mint a standard compact JWT (`header.payload.signature`) signed with EdDSA (`Ed25519`).
pub fn sign_oidc_jwt_eddsa(
    claims: &OidcClaims,
    signing_key: &SigningKey,
    kid: Option<&str>,
) -> Result<String> {
    let header = JwtHeader {
        alg: "EdDSA".to_string(),
        kid: kid.map(ToString::to_string),
        typ: Some("JWT".to_string()),
    };
    let h_json =
        serde_json::to_vec(&header).map_err(|e| GitxError::Serialization(e.to_string()))?;
    let p_json = serde_json::to_vec(claims).map_err(|e| GitxError::Serialization(e.to_string()))?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&h_json),
        URL_SAFE_NO_PAD.encode(&p_json)
    );
    let sig = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

/// Mint a standard compact JWT (`header.payload.signature`) signed with a GitX [`UserKeyPair`].
pub fn sign_oidc_jwt_with_keypair(
    claims: &OidcClaims,
    keypair: &UserKeyPair,
    kid: Option<&str>,
) -> Result<String> {
    let signing_key = SigningKey::from_bytes(&keypair.to_secret_bundle().ed25519_secret);
    sign_oidc_jwt_eddsa(claims, &signing_key, kid)
}

/// Verifier for EdDSA-signed OIDC JWTs (e.g., GitHub Actions, WorkOS, Okta, or internal IdPs)
/// mapping verified tokens directly into [`Principal`] objects.
#[derive(Clone)]
pub struct OidcVerifier {
    pub issuer: String,
    pub audience: String,
    pub keys: BTreeMap<String, VerifyingKey>,
}

impl OidcVerifier {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            keys: BTreeMap::new(),
        }
    }

    pub fn with_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }

    pub fn with_public_bundle(
        mut self,
        kid: impl Into<String>,
        pub_bundle: &PublicKeyBundle,
    ) -> Result<Self> {
        let vk = pub_bundle.verifying_key()?;
        self.keys.insert(kid.into(), vk);
        Ok(self)
    }

    /// Verify a compact EdDSA JWT and convert its claims into a GitX [`Principal`].
    pub fn verify_to_principal(&self, jwt: &str, now_unix: i64) -> Result<Principal> {
        let mut parts = jwt.trim().split('.');
        let (Some(h_b64), Some(p_b64), Some(s_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(GitxError::Crypto(
                "invalid OIDC JWT format: expected 3 dot-separated segments".into(),
            ));
        };

        let h_bytes = URL_SAFE_NO_PAD
            .decode(h_b64)
            .map_err(|e| GitxError::Crypto(format!("invalid JWT header base64: {e}")))?;
        let header: JwtHeader = serde_json::from_slice(&h_bytes)
            .map_err(|e| GitxError::Crypto(format!("invalid JWT header JSON: {e}")))?;
        if header.alg != "EdDSA" {
            return Err(GitxError::Crypto(format!(
                "unsupported OIDC JWT alg '{}': expected 'EdDSA'",
                header.alg
            )));
        }

        let key = match header.kid.as_deref() {
            Some(kid) => self
                .keys
                .get(kid)
                .ok_or_else(|| GitxError::Crypto(format!("unknown OIDC signing key id '{kid}'")))?,
            None if self.keys.len() == 1 => self.keys.values().next().expect("len == 1"),
            None => {
                return Err(GitxError::Crypto(
                    "OIDC JWT missing 'kid' header while multiple verifier keys are configured"
                        .into(),
                ));
            }
        };

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(s_b64)
            .map_err(|e| GitxError::Crypto(format!("invalid JWT signature base64: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| GitxError::Crypto("invalid EdDSA signature length".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let signing_input = format!("{h_b64}.{p_b64}");
        key.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| GitxError::Crypto("OIDC JWT signature verification failed".into()))?;

        let p_bytes = URL_SAFE_NO_PAD
            .decode(p_b64)
            .map_err(|e| GitxError::Crypto(format!("invalid JWT payload base64: {e}")))?;
        let claims: OidcClaims = serde_json::from_slice(&p_bytes)
            .map_err(|e| GitxError::Crypto(format!("invalid JWT claims JSON: {e}")))?;

        if claims.iss != self.issuer {
            return Err(GitxError::Crypto(format!(
                "OIDC issuer mismatch: expected '{}', got '{}'",
                self.issuer, claims.iss
            )));
        }
        if claims.aud != self.audience {
            return Err(GitxError::Crypto(format!(
                "OIDC audience mismatch: expected '{}', got '{}'",
                self.audience, claims.aud
            )));
        }
        if now_unix >= claims.exp {
            return Err(GitxError::Crypto("OIDC JWT has expired".into()));
        }
        if claims.sub.trim().is_empty() {
            return Err(GitxError::Crypto(
                "OIDC JWT subject ('sub') is empty".into(),
            ));
        }

        let mut principal = Principal::user(claims.sub);
        if !claims.teams.is_empty() {
            principal = principal.with_teams(claims.teams);
        }
        if !claims.roles.is_empty() {
            principal = principal.with_roles(claims.roles);
        }
        Ok(principal)
    }
}
