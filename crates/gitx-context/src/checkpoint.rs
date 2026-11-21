use chrono::{DateTime, Utc};
use gitx_core::{Actor, ObjectHash};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Sub-commit agent checkpoint capturing an intermediate workspace tree state during an AI session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: Ulid,
    pub workspace: String,
    pub session_id: String,
    pub actor: Actor,
    pub prompt_summary: String,
    pub tree_hash: ObjectHash,
    pub parent_checkpoint: Option<Ulid>,
    pub created_at: DateTime<Utc>,
}

impl Checkpoint {
    pub fn new(
        workspace: impl Into<String>,
        session_id: impl Into<String>,
        actor: Actor,
        prompt_summary: impl Into<String>,
        tree_hash: ObjectHash,
        parent_checkpoint: Option<Ulid>,
    ) -> Self {
        Self {
            id: Ulid::new(),
            workspace: workspace.into(),
            session_id: session_id.into(),
            actor,
            prompt_summary: prompt_summary.into(),
            tree_hash,
            parent_checkpoint,
            created_at: Utc::now(),
        }
    }
}
