use crate::domain::{DomainId, VisibilityPolicy};
use crate::hash::ObjectHash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use ulid::Ulid;

/// Stable logical change identifier that persists across amends, rebases, and restacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChangeId(pub Ulid);

impl ChangeId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    pub fn short(&self) -> String {
        let s = self.0.to_string().to_lowercase();
        s[s.len().saturating_sub(8)..].to_string()
    }
}

impl Default for ChangeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_string().to_lowercase())
    }
}

/// Human identity (author / reviewer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub email: String,
    pub key_fingerprint: Option<String>,
}

/// Separate committer actor: distinguishes human edits from autonomous AI agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    Human(Identity),
    Agent {
        harness: String,
        model: String,
        session_id: String,
        initiated_by: Identity,
    },
}

/// Immutable, content-addressed ChangeSet with domain-partitioned tree roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Immutable BLAKE3 revision hash covering all domains and metadata.
    pub id: ObjectHash,
    /// Stable ChangeId shared across all amended/rebased revisions of this logical change.
    pub change_id: ChangeId,
    /// Prior revision of the same ChangeId (enables Graphite-style v1..v2 interdiffs).
    pub previous_revision: Option<ObjectHash>,
    /// Parent ChangeSet IDs in the full DAG.
    pub parents: Vec<ObjectHash>,
    /// Parent public projection hashes (for stable public DAG independent of private domains).
    pub public_parents: Vec<ObjectHash>,
    /// Hash derived EXCLUSIVELY from the `public` domain tree + `public_parents` + public metadata.
    /// Invariant under mutations to private/secret domains!
    pub public_projection_hash: ObjectHash,
    /// Map of VisibilityDomain -> DomainTree hash.
    pub domain_trees: BTreeMap<DomainId, ObjectHash>,
    pub author: Identity,
    pub committer: Actor,
    pub visibility: VisibilityPolicy,
    pub has_conflicts: bool,
    pub created_at: DateTime<Utc>,
    pub description: String,
}

#[derive(Serialize)]
struct PublicProjectionPayload<'a> {
    change_id: ChangeId,
    public_parents: &'a [ObjectHash],
    public_tree: Option<ObjectHash>,
    author: &'a Identity,
    committer: &'a Actor,
    created_at: DateTime<Utc>,
    description: &'a str,
}

#[derive(Serialize)]
struct FullChangeSetPayload<'a> {
    change_id: ChangeId,
    previous_revision: Option<ObjectHash>,
    parents: &'a [ObjectHash],
    public_parents: &'a [ObjectHash],
    public_projection_hash: ObjectHash,
    domain_trees: &'a BTreeMap<DomainId, ObjectHash>,
    author: &'a Identity,
    committer: &'a Actor,
    visibility: &'a VisibilityPolicy,
    has_conflicts: bool,
    created_at: DateTime<Utc>,
    description: &'a str,
}

pub struct ChangeSetBuilder {
    change_id: ChangeId,
    previous_revision: Option<ObjectHash>,
    parents: Vec<ObjectHash>,
    public_parents: Vec<ObjectHash>,
    domain_trees: BTreeMap<DomainId, ObjectHash>,
    author: Identity,
    committer: Actor,
    visibility: VisibilityPolicy,
    has_conflicts: bool,
    created_at: DateTime<Utc>,
    description: String,
}

impl ChangeSetBuilder {
    pub fn new(author: Identity) -> Self {
        let committer = Actor::Human(author.clone());
        Self {
            change_id: ChangeId::new(),
            previous_revision: None,
            parents: Vec::new(),
            public_parents: Vec::new(),
            domain_trees: BTreeMap::new(),
            author,
            committer,
            visibility: VisibilityPolicy::public(),
            has_conflicts: false,
            created_at: Utc::now(),
            description: String::new(),
        }
    }

    pub fn change_id(mut self, id: ChangeId) -> Self {
        self.change_id = id;
        self
    }

    pub fn previous_revision(mut self, rev: Option<ObjectHash>) -> Self {
        self.previous_revision = rev;
        self
    }

    pub fn parents(mut self, parents: Vec<ObjectHash>) -> Self {
        self.parents = parents;
        self
    }

    pub fn public_parents(mut self, parents: Vec<ObjectHash>) -> Self {
        self.public_parents = parents;
        self
    }

    pub fn domain_tree(mut self, domain: DomainId, tree_hash: ObjectHash) -> Self {
        self.domain_trees.insert(domain, tree_hash);
        self
    }

    pub fn domain_trees(mut self, trees: BTreeMap<DomainId, ObjectHash>) -> Self {
        self.domain_trees = trees;
        self
    }

    pub fn committer(mut self, committer: Actor) -> Self {
        self.committer = committer;
        self
    }

    pub fn visibility(mut self, visibility: VisibilityPolicy) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn has_conflicts(mut self, has_conflicts: bool) -> Self {
        self.has_conflicts = has_conflicts;
        self
    }

    pub fn created_at(mut self, ts: DateTime<Utc>) -> Self {
        self.created_at = ts;
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn build(self) -> ChangeSet {
        let publicly_visible = self.visibility.is_publicly_visible();
        let public_tree = if publicly_visible {
            self.domain_trees.get(&DomainId::public()).copied()
        } else {
            None
        };

        let pub_payload = PublicProjectionPayload {
            change_id: self.change_id,
            public_parents: &self.public_parents,
            public_tree,
            author: &self.author,
            committer: &self.committer,
            created_at: self.created_at,
            description: if publicly_visible {
                &self.description
            } else {
                ""
            },
        };
        let pub_bytes = bincode::serialize(&pub_payload).expect("public payload serialization");
        let public_projection_hash = ObjectHash::of_typed("gitx:pubproj:v1", &pub_bytes);

        let full_payload = FullChangeSetPayload {
            change_id: self.change_id,
            previous_revision: self.previous_revision,
            parents: &self.parents,
            public_parents: &self.public_parents,
            public_projection_hash,
            domain_trees: &self.domain_trees,
            author: &self.author,
            committer: &self.committer,
            visibility: &self.visibility,
            has_conflicts: self.has_conflicts,
            created_at: self.created_at,
            description: &self.description,
        };
        let full_bytes = bincode::serialize(&full_payload).expect("full payload serialization");
        let id = ObjectHash::of_typed("gitx:changeset:v1", &full_bytes);

        ChangeSet {
            id,
            change_id: self.change_id,
            previous_revision: self.previous_revision,
            parents: self.parents,
            public_parents: self.public_parents,
            public_projection_hash,
            domain_trees: self.domain_trees,
            author: self.author,
            committer: self.committer,
            visibility: self.visibility,
            has_conflicts: self.has_conflicts,
            created_at: self.created_at,
            description: self.description,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackState {
    Draft,
    InReview,
    Approved,
    Landed,
    Abandoned,
}

/// First-class Stacked Diff unit sitting cleanly between a ChangeSet and a Merge/Land.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stack {
    pub name: String,
    pub base_target: String,
    pub changes: Vec<ChangeId>,
    pub visibility: VisibilityPolicy,
    pub state: StackState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
