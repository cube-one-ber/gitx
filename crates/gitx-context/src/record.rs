use crate::anchor::{compute_hunk_fingerprint, extract_symbol_hint};
use chrono::{DateTime, Utc};
use gitx_core::{Actor, ChangeId, DomainId, GitxError, Identity, ObjectHash, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use ulid::Ulid;

/// Unique identifier for a durable context record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContextId(pub Ulid);

impl ContextId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    pub fn short(&self) -> String {
        let s = self.0.to_string().to_lowercase();
        s[s.len().saturating_sub(8)..].to_string()
    }
}

impl Default for ContextId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Ulid> for ContextId {
    fn from(id: Ulid) -> Self {
        Self(id)
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_string().to_lowercase())
    }
}

impl FromStr for ContextId {
    type Err = GitxError;

    fn from_str(s: &str) -> Result<Self> {
        let ulid = Ulid::from_string(s)
            .map_err(|e| GitxError::Serialization(format!("invalid ContextId '{s}': {e}")))?;
        Ok(Self(ulid))
    }
}

/// Semantic category of a durable "Why" context record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextKind {
    Prompt {
        prompt: String,
        model: String,
        harness: String,
        session_id: String,
    },
    AgentTrace {
        summary: String,
        tool_calls: Vec<String>,
        session_id: String,
    },
    ReviewThread {
        reviewer: Identity,
        body: String,
        resolved: bool,
    },
    DesignDecision {
        title: String,
        rationale: String,
    },
    IssueLink {
        tracker: String,
        key: String,
        url: Option<String>,
    },
}

/// Resilient code location anchor that survives rebases, line shifts, and minor edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeAnchor {
    pub path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub symbol: Option<String>,
    pub hunk_fingerprint: ObjectHash,
    pub snippet: String,
}

impl CodeAnchor {
    /// Construct a `CodeAnchor` from a 1-based inclusive line range in `file_content`,
    /// automatically computing the hunk fingerprint, snippet, and enclosing symbol hint.
    pub fn from_file_lines(
        path: impl Into<String>,
        file_content: &str,
        line_start: u32,
        line_end: u32,
    ) -> Self {
        let all_lines: Vec<&str> = file_content.lines().collect();
        let slice: &[&str] = if line_start >= 1
            && line_end >= line_start
            && (line_start as usize) <= all_lines.len()
        {
            let start = (line_start - 1) as usize;
            let end = (line_end as usize).min(all_lines.len());
            &all_lines[start..end]
        } else {
            &[]
        };

        let hunk_fingerprint = compute_hunk_fingerprint(slice);
        let snippet = slice.join("\n");
        let symbol = extract_symbol_hint(file_content, line_start);

        Self {
            path: path.into(),
            line_start,
            line_end,
            symbol,
            hunk_fingerprint,
            snippet,
        }
    }
}

/// Durable "Why" context record bound to a logical change, revision, and Visibility Domain.
///
/// Inherits a `DomainId` so internal prompts, agent traces, and private review discussions
/// never leak into `public` projections or queries without matching domain authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRecord {
    pub id: ContextId,
    pub change_id: ChangeId,
    pub revision: ObjectHash,
    pub visibility: DomainId,
    pub author: Actor,
    pub kind: ContextKind,
    pub anchors: Vec<CodeAnchor>,
    pub created_at: DateTime<Utc>,
}

impl ContextRecord {
    /// Returns `true` if this record's visibility domain is permitted by `allowed_domains`.
    pub fn is_visible_to(&self, allowed_domains: &[DomainId]) -> bool {
        allowed_domains.contains(&self.visibility)
    }
}
