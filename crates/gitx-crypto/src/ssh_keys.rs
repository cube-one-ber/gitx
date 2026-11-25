//! OpenSSH Ed25519 keypair and public key import (compatible with `~/.ssh/id_ed25519` and `.pub`).
//!
//! Uses standard RFC 8032 SHA-512 scalar derivation + Curve25519 Edwards-to-Montgomery birational
//! conversion (identical to `age` `ssh-ed25519`), so encrypting a secret to a teammate's
//! `ssh-ed25519` public key decrypts cleanly with their corresponding OpenSSH private key.

use crate::keys::{PublicKeyBundle, SecretKeyBundle, UserKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use gitx_core::{GitxError, Result};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

const OPENSSH_KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
const SSH_ED25519_TYPE: &str = "ssh-ed25519";

/// Convert a 32-byte Ed25519 public key to its corresponding 32-byte X25519 Montgomery public key.
pub fn ed25519_public_to_x25519(ed25519_public: &[u8; 32]) -> Result<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed25519_public);
    let point = compressed.decompress().ok_or_else(|| {
        GitxError::Crypto("invalid Ed25519 public key: failed to decompress Edwards point".into())
    })?;
    if point.is_small_order() {
        return Err(GitxError::Crypto(
            "invalid Ed25519 public key: small-order point".into(),
        ));
    }
    Ok(point.to_montgomery().to_bytes())
}

/// Derive a [`UserKeyPair`] deterministically from a 32-byte Ed25519 private seed using the
/// RFC 8032 / `age` SHA-512 clamping derivation so its X25519 public key matches
/// [`ed25519_public_to_x25519`].
pub fn user_keypair_from_ed25519_seed(seed: [u8; 32], label: Option<String>) -> Result<UserKeyPair> {
    let mut seed_zero = Zeroizing::new(seed);
    let digest_raw: [u8; 64] = Sha512::digest(*seed_zero).into();
    let digest = Zeroizing::new(digest_raw);
    let mut x_secret_bytes = Zeroizing::new([0u8; 32]);
    x_secret_bytes.copy_from_slice(&digest[..32]);
    x_secret_bytes[0] &= 248;
    x_secret_bytes[31] &= 127;
    x_secret_bytes[31] |= 64;

    let bundle = SecretKeyBundle {
        x25519_secret: *x_secret_bytes,
        ed25519_secret: *seed_zero,
        label,
    };
    *seed_zero = [0u8; 32];
    UserKeyPair::from_secret_bundle(&bundle)
}

/// Parse an OpenSSH `ssh-ed25519` public key line (`ssh-ed25519 <base64> [comment]`) into a
/// [`PublicKeyBundle`] with both Ed25519 and derived X25519 public keys.
pub fn parse_openssh_ed25519_pub(line: &str) -> Result<PublicKeyBundle> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(GitxError::Crypto("empty OpenSSH public key line".into()));
    }

    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let key_type = parts
        .next()
        .ok_or_else(|| GitxError::Crypto("missing SSH key type".into()))?;
    if key_type != SSH_ED25519_TYPE {
        return Err(GitxError::Crypto(format!(
            "unsupported OpenSSH key type '{key_type}': expected '{SSH_ED25519_TYPE}'"
        )));
    }

    let b64 = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GitxError::Crypto("missing base64 key blob in OpenSSH public key".into()))?;
    let comment = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let blob = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| GitxError::Crypto(format!("invalid base64 in OpenSSH public key: {e}")))?;

    let mut cursor = SshReader::new(&blob);
    let wire_type = cursor.read_string_utf8()?;
    if wire_type != SSH_ED25519_TYPE {
        return Err(GitxError::Crypto(format!(
            "mismatched OpenSSH wire key type '{wire_type}': expected '{SSH_ED25519_TYPE}'"
        )));
    }
    let pk_bytes = cursor.read_bytes()?;
    if pk_bytes.len() != 32 {
        return Err(GitxError::Crypto(format!(
            "invalid Ed25519 public key length {}: expected 32",
            pk_bytes.len()
        )));
    }
    let mut ed25519_public = [0u8; 32];
    ed25519_public.copy_from_slice(pk_bytes);
    let x25519_public = ed25519_public_to_x25519(&ed25519_public)?;

    Ok(PublicKeyBundle {
        x25519_public,
        ed25519_public,
        label: comment,
    })
}

/// Format an Ed25519 public key into standard OpenSSH `.pub` line format (`ssh-ed25519 <base64> [label]`).
pub fn format_openssh_ed25519_pub(ed25519_public: &[u8; 32], label: Option<&str>) -> String {
    let mut wire = Vec::with_capacity(4 + SSH_ED25519_TYPE.len() + 4 + 32);
    write_ssh_bytes(&mut wire, SSH_ED25519_TYPE.as_bytes());
    write_ssh_bytes(&mut wire, ed25519_public);
    let b64 = BASE64_STANDARD.encode(&wire);
    match label.filter(|s| !s.trim().is_empty()) {
        Some(comment) => format!("{SSH_ED25519_TYPE} {b64} {}", comment.trim()),
        None => format!("{SSH_ED25519_TYPE} {b64}"),
    }
}

/// Parse an unencrypted OpenSSH Ed25519 private key (`-----BEGIN OPENSSH PRIVATE KEY-----`)
/// into a [`UserKeyPair`].
pub fn parse_openssh_ed25519_private(pem: &str, label_override: Option<String>) -> Result<UserKeyPair> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    if b64.is_empty() {
        return Err(GitxError::Crypto("empty OpenSSH private key PEM".into()));
    }

    let raw = Zeroizing::new(
        BASE64_STANDARD
            .decode(&b64)
            .map_err(|e| GitxError::Crypto(format!("invalid base64 in OpenSSH private key: {e}")))?,
    );
    if !raw.starts_with(OPENSSH_KEY_MAGIC) {
        return Err(GitxError::Crypto(
            "invalid OpenSSH private key: missing 'openssh-key-v1' header".into(),
        ));
    }

    let mut cursor = SshReader::new(&raw[OPENSSH_KEY_MAGIC.len()..]);
    let ciphername = cursor.read_string_utf8()?;
    let kdfname = cursor.read_string_utf8()?;
    let _kdfoptions = cursor.read_bytes()?;

    if ciphername != "none" || kdfname != "none" {
        return Err(GitxError::Crypto(format!(
            "passphrase-encrypted OpenSSH keys (cipher='{ciphername}', kdf='{kdfname}') are not yet supported; decrypt or use an unencrypted key"
        )));
    }

    let num_keys = cursor.read_u32()?;
    if num_keys != 1 {
        return Err(GitxError::Crypto(format!(
            "expected exactly 1 key in OpenSSH private key file, found {num_keys}"
        )));
    }

    let _pub_blob = cursor.read_bytes()?;
    let priv_section = cursor.read_bytes()?;

    let mut pcur = SshReader::new(priv_section);
    let check1 = pcur.read_u32()?;
    let check2 = pcur.read_u32()?;
    if check1 != check2 {
        return Err(GitxError::Crypto(
            "OpenSSH private key checkint mismatch (corrupted or encrypted key)".into(),
        ));
    }

    let key_type = pcur.read_string_utf8()?;
    if key_type != SSH_ED25519_TYPE {
        return Err(GitxError::Crypto(format!(
            "unsupported OpenSSH private key type '{key_type}': expected '{SSH_ED25519_TYPE}'"
        )));
    }

    let pub_bytes = pcur.read_bytes()?;
    let priv_bytes = pcur.read_bytes()?;
    let comment = pcur.read_string_utf8()?;

    if pub_bytes.len() != 32 || priv_bytes.len() != 64 {
        return Err(GitxError::Crypto(format!(
            "invalid Ed25519 key lengths (pub={}, priv={}; expected 32, 64)",
            pub_bytes.len(),
            priv_bytes.len()
        )));
    }
    if &priv_bytes[32..64] != pub_bytes {
        return Err(GitxError::Crypto(
            "OpenSSH Ed25519 private key public-half mismatch".into(),
        ));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&priv_bytes[..32]);

    // Sanity check that derived public key matches embedded OpenSSH public key.
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().as_bytes() != pub_bytes {
        return Err(GitxError::Crypto(
            "OpenSSH Ed25519 seed does not match embedded public key".into(),
        ));
    }

    let effective_label = label_override.or_else(|| {
        let c = comment.trim();
        if c.is_empty() {
            None
        } else {
            Some(c.to_string())
        }
    });

    let kp = user_keypair_from_ed25519_seed(seed, effective_label)?;
    // Verify X25519 public key matches Edwards-to-Montgomery conversion.
    let expected_x = ed25519_public_to_x25519(signing.verifying_key().as_bytes())?;
    let derived_x = X25519PublicKey::from(&X25519StaticSecret::from(
        kp.to_secret_bundle().x25519_secret,
    ))
    .to_bytes();
    if derived_x != expected_x {
        return Err(GitxError::Crypto(
            "internal error: derived X25519 public key mismatch".into(),
        ));
    }

    Ok(kp)
}

/// Format an Ed25519 32-byte seed into a standard unencrypted OpenSSH private key PEM string.
pub fn encode_openssh_ed25519_private(seed: &[u8; 32], comment: &str) -> String {
    let signing = SigningKey::from_bytes(seed);
    let pub_bytes = signing.verifying_key().to_bytes();

    let mut pub_blob = Vec::new();
    write_ssh_bytes(&mut pub_blob, SSH_ED25519_TYPE.as_bytes());
    write_ssh_bytes(&mut pub_blob, &pub_bytes);

    let mut priv_section = Vec::new();
    let checkint: u32 = 0x1122_3344;
    priv_section.extend_from_slice(&checkint.to_be_bytes());
    priv_section.extend_from_slice(&checkint.to_be_bytes());
    write_ssh_bytes(&mut priv_section, SSH_ED25519_TYPE.as_bytes());
    write_ssh_bytes(&mut priv_section, &pub_bytes);
    let mut priv64 = [0u8; 64];
    priv64[..32].copy_from_slice(seed);
    priv64[32..].copy_from_slice(&pub_bytes);
    write_ssh_bytes(&mut priv_section, &priv64);
    write_ssh_bytes(&mut priv_section, comment.as_bytes());

    let mut pad: u8 = 1;
    while priv_section.len() % 8 != 0 {
        priv_section.push(pad);
        pad = pad.wrapping_add(1);
    }

    let mut raw = Vec::new();
    raw.extend_from_slice(OPENSSH_KEY_MAGIC);
    write_ssh_bytes(&mut raw, b"none");
    write_ssh_bytes(&mut raw, b"none");
    write_ssh_bytes(&mut raw, b"");
    raw.extend_from_slice(&1u32.to_be_bytes());
    write_ssh_bytes(&mut raw, &pub_blob);
    write_ssh_bytes(&mut raw, &priv_section);

    let b64 = BASE64_STANDARD.encode(&raw);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}

impl PublicKeyBundle {
    /// Import a teammate's OpenSSH `ssh-ed25519` public key line (`~/.ssh/id_ed25519.pub`).
    pub fn from_openssh_ed25519_pub(line: &str) -> Result<Self> {
        parse_openssh_ed25519_pub(line)
    }

    /// Format this bundle's Ed25519 public key in standard OpenSSH `.pub` format.
    pub fn to_openssh_ed25519_pub(&self) -> String {
        format_openssh_ed25519_pub(&self.ed25519_public, self.label.as_deref())
    }
}

impl UserKeyPair {
    /// Import an unencrypted OpenSSH Ed25519 private key (`~/.ssh/id_ed25519`).
    pub fn from_openssh_ed25519(pem: &str, label: Option<String>) -> Result<Self> {
        parse_openssh_ed25519_private(pem, label)
    }

    /// Construct a [`UserKeyPair`] deterministically from a 32-byte Ed25519 seed.
    pub fn from_ed25519_seed(seed: [u8; 32], label: Option<String>) -> Result<Self> {
        user_keypair_from_ed25519_seed(seed, label)
    }

    /// Export this keypair's Ed25519 public half as an OpenSSH `.pub` line.
    pub fn to_openssh_ed25519_pub(&self) -> String {
        self.public_bundle().to_openssh_ed25519_pub()
    }
}

fn write_ssh_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

struct SshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(GitxError::Crypto(
                "unexpected EOF reading u32 in OpenSSH key".into(),
            ));
        }
        let val = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(GitxError::Crypto(
                "unexpected EOF reading byte slice in OpenSSH key".into(),
            ));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_string_utf8(&mut self) -> Result<&'a str> {
        let bytes = self.read_bytes()?;
        std::str::from_utf8(bytes)
            .map_err(|e| GitxError::Crypto(format!("invalid UTF-8 in OpenSSH key field: {e}")))
    }
}
