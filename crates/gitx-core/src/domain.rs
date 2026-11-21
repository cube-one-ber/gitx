use crate::error::{GitxError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Visibility Domain identifier partitioning trees, branches/stacks, secrets, and embargoes.
///
/// Examples:
/// - `public`
/// - `team:core`
/// - `secret:dev`
/// - `secret:prod`
/// - `private:user:theo`
/// - `embargo:cve-2026-0001`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DomainId(String);

impl DomainId {
    pub fn public() -> Self {
        Self("public".to_string())
    }

    pub fn secret(env: &str) -> Result<Self> {
        Self::new(format!("secret:{env}"))
    }

    pub fn team(name: &str) -> Result<Self> {
        Self::new(format!("team:{name}"))
    }

    pub fn private_user(user: &str) -> Result<Self> {
        Self::new(format!("private:user:{user}"))
    }

    pub fn embargo(advisory: &str) -> Result<Self> {
        Self::new(format!("embargo:{advisory}"))
    }

    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();
        if s.is_empty()
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
        {
            return Err(GitxError::InvalidDomain(s));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_public(&self) -> bool {
        self.0 == "public"
    }

    pub fn is_secret(&self) -> bool {
        self.0.starts_with("secret:")
    }

    pub fn is_embargo(&self) -> bool {
        self.0.starts_with("embargo:")
    }
}

impl Default for DomainId {
    fn default() -> Self {
        Self::public()
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbargoState {
    Active {
        advisory_id: String,
        disclose_at: Option<DateTime<Utc>>,
        allowed_domains: Vec<DomainId>,
    },
    Published {
        advisory_id: String,
        published_at: DateTime<Utc>,
    },
}

/// Access visibility policy attached to a ChangeSet, Stack, or Context Record.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VisibilityPolicy {
    pub primary_domain: DomainId,
    /// If true, an in-flight private stack automatically promotes its public-domain paths on land.
    pub reveal_on_land: bool,
    pub embargo: Option<EmbargoState>,
}

impl VisibilityPolicy {
    pub fn public() -> Self {
        Self::default()
    }

    pub fn private(domain: DomainId, reveal_on_land: bool) -> Self {
        Self {
            primary_domain: domain,
            reveal_on_land,
            embargo: None,
        }
    }

    pub fn embargoed(advisory_id: impl Into<String>, allowed_domains: Vec<DomainId>, disclose_at: Option<DateTime<Utc>>) -> Result<Self> {
        let advisory = advisory_id.into();
        let primary_domain = DomainId::embargo(&advisory)?;
        Ok(Self {
            primary_domain,
            reveal_on_land: false,
            embargo: Some(EmbargoState::Active {
                advisory_id: advisory,
                disclose_at,
                allowed_domains,
            }),
        })
    }
}
