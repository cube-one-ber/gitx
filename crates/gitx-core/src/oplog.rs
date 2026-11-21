use crate::changeset::ChangeId;
use crate::hash::ObjectHash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ulid::Ulid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpId(pub Ulid);

impl OpId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for OpId {
    fn default() -> Self {
        Self::new()
    }
}

/// Workspace backend mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkspaceBackendKind {
    Memory,
    CopyOnWrite,
    LazyMount,
}

/// Lock-free workspace reference pointing at its own working-copy ChangeSet (`@`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRef {
    pub name: String,
    pub root_path: Option<String>,
    pub backend: WorkspaceBackendKind,
    pub head_changeset: ObjectHash,
    pub head_change_id: ChangeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    Init,
    Snapshot { workspace: String },
    NewChange { change_id: ChangeId },
    Describe { change_id: ChangeId },
    Split { source: ChangeId, created: ChangeId },
    Squash { from: ChangeId, into: ChangeId },
    Rebase { moved: Vec<ChangeId> },
    StackSync { restacked: usize, pruned: usize },
    Land { target: String, land_seq: u64, changes: Vec<ChangeId> },
    Revert { land_seq: u64 },
    WorkspaceCreate { name: String },
    WorkspaceRemove { name: String },
    SecretUpdate { domain: String, path: String, key_epoch: u64 },
    EmbargoPublish { advisory_id: String },
    Undo { target_op: OpId },
    AgentCheckpoint { session_id: String, prompt_hash: ObjectHash },
}

/// Immutable Operation Log entry enabling `gitx undo` across every repo mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpLogEntry {
    pub id: OpId,
    pub parent: Option<OpId>,
    pub timestamp: DateTime<Utc>,
    pub kind: OpKind,
    pub summary: String,
    /// Snapshot of logical heads (bookmark/branch -> ChangeSet hash) after this operation.
    pub bookmarks: BTreeMap<String, ObjectHash>,
    /// Snapshot of active workspaces after this operation.
    pub workspaces: BTreeMap<String, WorkspaceRef>,
    /// Snapshot of ChangeId -> latest ObjectHash head after this operation.
    pub change_heads: BTreeMap<ChangeId, ObjectHash>,
}
