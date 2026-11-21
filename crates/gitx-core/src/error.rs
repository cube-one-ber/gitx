use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitxError {
    #[error("invalid object hash: {0}")]
    InvalidHash(String),

    #[error("invalid domain identifier: {0}")]
    InvalidDomain(String),

    #[error("object not found: {0}")]
    NotFound(String),

    #[error("access denied for domain '{domain}': {reason}")]
    AccessDenied { domain: String, reason: String },

    #[error("conflict present in change {0}")]
    ConflictPresent(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("merge error: {0}")]
    Merge(String),

    #[error("workspace error: {0}")]
    Workspace(String),

    #[error("git bridge error: {0}")]
    GitBridge(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GitxError>;
