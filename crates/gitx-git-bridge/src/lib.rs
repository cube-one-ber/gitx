//! Pure-Rust lossless Git interoperability bridge for `gitx`.
//!
//! Provides:
//! - Pure-Rust Git loose object reading, writing, canonical tree building, and commit building
//!   ([`objects`]).
//! - ACL-filtered projection from a `gitx-store` repository into a `git fsck --full --strict`
//!   compliant Git repository containing only authorized visibility domains ([`project`]).
//! - Colocated import from any existing Git repository into `gitx-store` ([`import`]).
//! - Git Smart HTTP pkt-line and `git-upload-pack` helpers for serving ACL-filtered clones
//!   ([`pktline`]).
//! - ACL-filtered Git SSH transport dispatcher for `git-upload-pack` / `git-receive-pack`
//!   ([`ssh`]).

pub mod import;
pub mod objects;
pub mod pktline;
pub mod project;
pub mod ssh;

pub use import::{ImportReport, import_from_git_repo};
pub use objects::{
    GitCommitParams, GitOid, GitSignature, build_commit_payload, hash_git_object,
    read_loose_object, write_commit_object, write_loose_object, write_tree_from_files,
};
pub use pktline::{
    DELIM_PKT, FLUSH_PKT, PktLine, RECEIVE_PACK_ADVERTISEMENT_CONTENT_TYPE,
    RECEIVE_PACK_RESULT_CONTENT_TYPE, UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE,
    UPLOAD_PACK_RESULT_CONTENT_TYPE, advertise_receive_pack_refs_with_protocol,
    advertise_upload_pack_refs, advertise_upload_pack_refs_with_protocol, decode_pkt_lines,
    encode_delim_pkt, encode_flush_pkt, encode_pkt_line, handle_receive_pack_with_protocol,
    handle_upload_pack, handle_upload_pack_with_protocol,
};
pub use project::{
    ProjectionReport, export_to_git_repo, export_to_git_repo_colocated, export_to_git_repo_filtered,
};
pub use ssh::{
    GitSshService, GitSshSession, ParsedSshCommand, SshSessionReport,
    advertise_ssh_upload_pack_refs, export_receive_pack_staging,
    export_receive_pack_staging_filtered, handle_ssh_command, import_received_refs,
    import_received_refs_with_policy, list_bare_branch_refs, parse_advertised_refs,
    parse_ssh_command,
};
