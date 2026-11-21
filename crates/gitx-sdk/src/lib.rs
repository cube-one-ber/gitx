//! Zero-disk, zero-OS in-memory Agent SDK and JSON-RPC 2.0 MCP server for GitX.
//!
//! - [`AgentRepo`] provides lock-free, copy-on-write in-memory [`gitx_vfs::MemVfs`] workspaces
//!   backed by any [`gitx_store::ObjectStore`] (`MemoryStore` for zero-disk sandboxes or
//!   `LocalStore` for durable repos), with ACL enforcement, zero-trust secret scanning, durable
//!   "Why" context provenance, transactional semantic-merge landing, and surgical checkpoint undo
//!   that preserves concurrent human edits.
//! - [`McpServer`] exposes [`AgentRepo`] over JSON-RPC 2.0 (Model Context Protocol) via
//!   line-delimited JSON or stdio streams.

pub mod agent_repo;
pub mod mcp;

pub use agent_repo::{
    AgentIdentity, AgentRepo, CommitContext, CommitOutcome, GrepMatch, LandOutcome,
    UndoCheckpointOutcome,
};
pub use mcp::{MCP_PROTOCOL_VERSION, McpServer};
