//! Cryptographically signed bearer tokens for authenticating GitX HTTP/gRPC principals.
//!
//! Supports two compact token formats:
//! - `gitx1h.<base64url(claims_json)>.<base64url(blake3_mac)>` — symmetric keyed-BLAKE3 MAC
//! - `gitx1e.<base64url(claims_json)>.<base64url(ed25519_sig)>` — asymmetric Ed25519 signature

use crate::acl::Principal;
use crate::keys::{PublicKeyBundle, UserKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gitx_core::{GitxError, Result};
use serde::{Deserialize, Serialize};

pub const HMAC_TOKEN_PREFIX: &str = "gitx1h";
pub const ED25519_TOKEN_PREFIX: &str = "gitx1e";
const HMAC_KEY_CONTEXT: &str = "gitx:token-hmac:v1";

/// Claims embedded inside a cryptographically signed GitX bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    #[serde(default)]
    pub teams: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub issued_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl TokenClaims {
    pub fn new(sub: impl Into<String>, issued_at: i64) -> Self {
        Self {
            sub: sub.into(),
            teams: Vec::new(),
            roles: Vec::new(),
            fingerprint: None,
            issued_at,
            expires_at: None,
        }
    }

    pub fn with_teams(mut self, teams: Vec<String>) -> Self {
        self.teams = teams;
        self
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    pub fn with_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.fingerprint = Some(fp.into());
        self
    }

    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn into_principal(self) -> Result<Principal> {
        let sub = self.sub.trim();
        if sub.is_empty() {
            return Err(GitxError::Crypto(
                "signed token subject ('sub') must not be empty".into(),
            ));
        }
        let mut p = Principal::user(sub);
        if !self.teams.is_empty() {
            p = p.with_teams(self.teams);
        }
        if !self.roles.is_empty() {
            p = p.with_roles(self.roles);
        }
        if let Some(fp) = self.fingerprint.filter(|s| !s.trim().is_empty()) {
            p = p.with_fingerprint(fp);
        }
        Ok(p)
    }
}

/// Sign `claims` with a symmetric secret using keyed BLAKE3 (`gitx1h.<payload>.<mac>`).
pub fn sign_token_hmac(claims: &TokenClaims, secret: &[u8]) -> Result<String> {
    if claims.sub.trim().is_empty() {
        return Err(GitxError::Crypto("token subject must not be empty".into()));
    }
    if secret.is_empty() {
        return Err(GitxError::Crypto(
            "token signing secret must not be empty".into(),
        ));
    }
    let payload_json =
        serde_json::to_vec(claims).map_err(|e| GitxError::Serialization(e.to_string()))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{HMAC_TOKEN_PREFIX}.{payload_b64}");

    let key = blake3::derive_key(HMAC_KEY_CONTEXT, secret);
    let mac = blake3::keyed_hash(&key, signing_input.as_bytes());
    let mac_b64 = URL_SAFE_NO_PAD.encode(mac.as_bytes());

    Ok(format!("{signing_input}.{mac_b64}"))
}

/// Verify a `gitx1h.*` token using constant-time MAC comparison and check expiration against `now_secs`.
pub fn verify_token_hmac(token: &str, secret: &[u8], now_secs: i64) -> Result<Principal> {
    if secret.is_empty() {
        return Err(GitxError::Crypto(
            "token verification secret must not be empty".into(),
        ));
    }
    let mut parts = token.split('.');
    let prefix = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    let mac_b64 = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    if parts.next().is_some() || prefix != HMAC_TOKEN_PREFIX {
        return Err(GitxError::Crypto("invalid gitx1h token format".into()));
    }

    let provided_mac = URL_SAFE_NO_PAD
        .decode(mac_b64)
        .map_err(|e| GitxError::Crypto(format!("invalid token MAC encoding: {e}")))?;
    if provided_mac.len() != 32 {
        return Err(GitxError::Crypto("invalid token MAC length".into()));
    }

    let signing_input = format!("{prefix}.{payload_b64}");
    let key = blake3::derive_key(HMAC_KEY_CONTEXT, secret);
    let expected_mac = blake3::keyed_hash(&key, signing_input.as_bytes());

    if !ct_eq_32(expected_mac.as_bytes(), &provided_mac) {
        return Err(GitxError::Crypto("invalid token MAC signature".into()));
    }

    decode_and_check_claims(payload_b64, now_secs)
}

/// Sign `claims` with an Ed25519 [`UserKeyPair`] (`gitx1e.<payload>.<sig>`).
pub fn sign_token_ed25519(claims: &TokenClaims, keypair: &UserKeyPair) -> Result<String> {
    if claims.sub.trim().is_empty() {
        return Err(GitxError::Crypto("token subject must not be empty".into()));
    }
    let payload_json =
        serde_json::to_vec(claims).map_err(|e| GitxError::Serialization(e.to_string()))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{ED25519_TOKEN_PREFIX}.{payload_b64}");

    let sig = keypair.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify a `gitx1e.*` Ed25519-signed token against `verifying_key` and check expiration.
pub fn verify_token_ed25519(
    token: &str,
    verifying_key: &PublicKeyBundle,
    now_secs: i64,
) -> Result<Principal> {
    let mut parts = token.split('.');
    let prefix = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("malformed signed token".into()))?;
    if parts.next().is_some() || prefix != ED25519_TOKEN_PREFIX {
        return Err(GitxError::Crypto("invalid gitx1e token format".into()));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| GitxError::Crypto(format!("invalid token signature encoding: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(GitxError::Crypto("invalid Ed25519 signature length".into()));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    let signing_input = format!("{prefix}.{payload_b64}");
    verifying_key.verify(signing_input.as_bytes(), &sig)?;

    decode_and_check_claims(payload_b64, now_secs)
}

fn decode_and_check_claims(payload_b64: &str, now_secs: i64) -> Result<Principal> {
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| GitxError::Crypto(format!("invalid token claims encoding: {e}")))?;
    let claims: TokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| GitxError::Crypto(format!("invalid token claims JSON: {e}")))?;

    if let Some(exp) = claims.expires_at
        && now_secs > exp
    {
        return Err(GitxError::Crypto("signed bearer token has expired".into()));
    }

    claims.into_principal()
}

fn ct_eq_32(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
