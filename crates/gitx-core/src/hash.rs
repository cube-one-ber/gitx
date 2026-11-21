use crate::error::{GitxError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// 32-byte BLAKE3 content-addressed object identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ObjectHash(pub [u8; 32]);

impl ObjectHash {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hash arbitrary bytes using BLAKE3.
    pub fn of_bytes(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Hash domain-separated typed payloads to prevent cross-type hash collisions.
    pub fn of_typed(domain_tag: &str, payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain_tag.as_bytes());
        hasher.update(b"\0");
        hasher.update(payload);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.to_hex()[..12].to_string()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectHash({})", self.short())
    }
}

impl FromStr for ObjectHash {
    type Err = GitxError;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| GitxError::InvalidHash(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(GitxError::InvalidHash(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}
