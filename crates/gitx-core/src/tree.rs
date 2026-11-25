use crate::domain::DomainId;
use crate::hash::ObjectHash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMode {
    Regular,
    Executable,
    Symlink,
}

/// Algebraic conflict term (Jujutsu-style): stored natively inside a tree entry so conflicts
/// never block snapshots, checkouts, or handoffs to AI agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictTerm {
    /// Positive (added / side) blob hashes.
    pub adds: Vec<Option<ObjectHash>>,
    /// Negative (base / ancestor) blob hashes.
    pub removes: Vec<Option<ObjectHash>>,
}

impl ConflictTerm {
    pub fn is_resolved(&self) -> bool {
        self.adds.len() == 1 && self.removes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Standard plaintext file pointing to a `ChunkedBlob` manifest hash.
    File {
        blob_hash: ObjectHash,
        mode: FileMode,
        size: u64,
    },
    /// Envelope-encrypted secret file (stored in a `secret:*` domain).
    EncryptedSecret {
        envelope_hash: ObjectHash,
        key_epoch: u64,
        mode: FileMode,
    },
    /// First-class unresolved conflict recorded directly inside the tree.
    Conflict { term: ConflictTerm, mode: FileMode },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    pub kind: EntryKind,
}

/// Canonical, flat-sorted tree belonging to a SINGLE Visibility Domain.
/// Because each domain has its own independent tree hash, mutating or stripping
/// private/secret domains never alters the `public` domain tree hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainTree {
    pub domain: DomainId,
    pub entries: BTreeMap<String, EntryKind>,
}

impl DomainTree {
    pub fn new(domain: DomainId) -> Self {
        Self {
            domain,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: impl Into<String>, kind: EntryKind) {
        self.entries.insert(path.into(), kind);
    }

    pub fn remove(&mut self, path: &str) -> Option<EntryKind> {
        self.entries.remove(path)
    }

    pub fn has_conflicts(&self) -> bool {
        self.entries
            .values()
            .any(|k| matches!(k, EntryKind::Conflict { .. }))
    }

    pub fn conflict_paths(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|(p, k)| matches!(k, EntryKind::Conflict { .. }).then_some(p.as_str()))
            .collect()
    }

    pub fn hash(&self) -> ObjectHash {
        let bytes = bincode::serialize(self).expect("DomainTree serialization cannot fail");
        ObjectHash::of_typed("gitx:tree:v1", &bytes)
    }
}
