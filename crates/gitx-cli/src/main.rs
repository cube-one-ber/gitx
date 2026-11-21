mod commands;
mod repo;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "gitx",
    version,
    about = "GitX — Visibility-domain VCS with native secrets, lock-free workspaces, stacked diffs, and durable AI context"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new gitx repository (optionally colocated with an existing .git repository)
    Init {
        /// Import history from an existing colocated .git repository
        #[arg(long)]
        colocate: bool,
        /// Author name for commits
        #[arg(long)]
        name: Option<String>,
        /// Author email for commits
        #[arg(long)]
        email: Option<String>,
    },

    /// Auto-snapshot working copy and show status grouped by visibility domain
    Status,

    /// Show unified diff vs parent, or revision-to-revision interdiff
    Diff {
        /// Compare previous revision vs current revision of the same ChangeId
        #[arg(long)]
        interdiff: bool,
        /// Source revision hash, ChangeId, or bookmark
        #[arg(long)]
        from: Option<String>,
        /// Target revision hash, ChangeId, or bookmark
        #[arg(long)]
        to: Option<String>,
    },

    /// Display ChangeSet history with visibility domains, agent metadata, and conflict badges
    Log {
        /// Maximum number of ChangeSets to display
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show ChangeSets from all visibility domains
        #[arg(long)]
        all_domains: bool,
    },

    /// Snapshot current `@` and start a new child ChangeSet on top
    New {
        /// Description for the new ChangeSet
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
        /// Primary visibility domain (e.g., public, team:core, private:user:alice)
        #[arg(long)]
        visibility: Option<String>,
        /// Automatically promote private change to public on land
        #[arg(long)]
        reveal_on_land: bool,
        /// Record an AI agent committer (`<harness>:<model>`)
        #[arg(long)]
        agent: Option<String>,
    },

    /// Update the description of the current `@` ChangeSet as a new immutable revision
    Describe {
        /// New description text
        #[arg(short = 'm', long = "message")]
        message: String,
    },

    /// Manage native stacked diffs
    Stack {
        #[command(subcommand)]
        action: StackAction,
    },

    /// Atomically land the current ChangeSet onto a target bookmark (default: master)
    Land {
        /// Target bookmark to land onto
        #[arg(long, default_value = "master")]
        target: String,
    },

    /// O(1) atomic revert of a previously landed sequence number
    Revert {
        /// Monotonic land_seq assigned by `gitx land`
        land_seq: u64,
    },

    /// Inspect the immutable operation log
    Op {
        #[command(subcommand)]
        action: OpAction,
    },

    /// Restore the previous OpLog snapshot (bookmarks, workspaces, and working tree)
    Undo,

    /// Manage lock-free concurrent workspaces
    Ws {
        #[command(subcommand)]
        action: WsAction,
    },

    /// Manage native envelope-encrypted secrets inside `secret:*` domains
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Manage embargoed security ChangeSets and coordinated disclosure
    Embargo {
        #[command(subcommand)]
        action: EmbargoAction,
    },

    /// Record durable "Why" context records anchored to code ranges
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },

    /// Query durable "Why" context for a file line (`<path>:<line>`)
    Why {
        /// Target file and 1-based line (`<path>:<line>`)
        target: String,
        /// Comma-separated authorized visibility domains
        #[arg(long, default_value = "public")]
        domains: String,
    },

    /// Manage sub-commit AI agent checkpoints with human-edit-preserving undo
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointAction,
    },

    /// Export an ACL-filtered Git repository containing only authorized domains
    GitExport {
        /// Target directory for the exported Git repository
        target_dir: PathBuf,
        /// Comma-separated visibility domains to export
        #[arg(long, default_value = "public")]
        domains: String,
    },

    /// Cross-machine overlay sync for local files (`.env`, `.env.local`, configs)
    Fleet {
        #[command(subcommand)]
        action: FleetAction,
    },

    /// Start the GitX HTTP/JSON and ACL-filtered Git Smart HTTP server
    Serve {
        /// Listen address (host:port)
        #[arg(long, default_value = "127.0.0.1:7878")]
        addr: String,
        /// Server data directory
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Start the JSON-RPC 2.0 Model Context Protocol (MCP) server over stdin/stdout
    Mcp {
        /// Run a pure zero-disk in-memory AgentRepo (no .gitx directory required)
        #[arg(long)]
        in_memory: bool,
    },

    /// Extract Tree-sitter AST symbols (Rust/TS/TSX/JS) with kind and line ranges
    Symbols {
        /// Path to source file to inspect
        path: PathBuf,
        /// Output extracted symbols as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage remote gitx-server configurations and run zero-clone remote RPC queries
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },

    /// Push local ChangeSet and working copy changes to a remote gitx-server (supports push-to-create)
    Push {
        /// Configured remote name (defaults to 'origin')
        remote: Option<String>,
        /// Target bookmark on the remote (defaults to repository default branch)
        #[arg(long)]
        target: Option<String>,
        /// Commit message override for the pushed ChangeSet
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
        /// Authentication token override (e.g. 'alice' or 'user=alice;teams=core,security')
        #[arg(long)]
        token: Option<String>,
    },

    /// Pull ACL-filtered ChangeSets and files from a remote gitx-server into the local repo
    Pull {
        /// Configured remote name (defaults to 'origin')
        remote: Option<String>,
        /// Target bookmark to pull from the remote (defaults to repository default branch)
        #[arg(long)]
        target: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },

    /// Interact with a remote gitx-server batched agentic merge queue
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
}

#[derive(Subcommand)]
enum StackAction {
    /// Create a named stack from open changes above master
    Create { name: String },
    /// List all stacks
    List,
    /// Restack open stack changes onto latest master (recording conflicts without failing)
    Sync,
}

#[derive(Subcommand)]
enum OpAction {
    /// Show recent entries from the immutable operation log
    Log {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum WsAction {
    /// Add a new lock-free workspace off master
    Add {
        name: String,
        /// Target directory for a Copy-on-Write or lazy overlay workspace
        #[arg(long)]
        path: Option<PathBuf>,
        /// Create an in-memory workspace instead of a disk workspace
        #[arg(long, conflicts_with = "lazy")]
        mem: bool,
        /// Create a demand-paged virtualized sparse workspace (O(1) mount, zero base files written)
        #[arg(long, conflicts_with = "mem")]
        lazy: bool,
    },
    /// List registered workspaces
    List,
    /// Remove a registered workspace
    Rm { name: String },
    /// Mount a workspace onto an OS-level virtualized mountpoint (`vfs://`)
    Mount {
        /// Name of the registered workspace to mount
        name: String,
        /// Target mountpoint directory
        mountpoint: PathBuf,
        /// Virtual mount backend (`fuse` on Linux FUSE3 or `loopback` TCP NFSv3-style server)
        #[arg(long, value_enum, default_value_t = commands::workspace::MountBackend::Fuse)]
        backend: commands::workspace::MountBackend,
    },
    /// Unmount an active OS-level virtualized workspace mountpoint
    Unmount {
        /// Mounted directory path to unmount
        mountpoint: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Encrypt and store a local file inside a `secret:*` domain tree
    Set {
        path: String,
        #[arg(long, default_value = "secret:dev")]
        domain: String,
    },
    /// Decrypt and print a secret file from a `secret:*` domain tree
    Get {
        path: String,
        #[arg(long, default_value = "secret:dev")]
        domain: String,
    },
    /// Generate a new X25519 + Ed25519 recipient keypair and print its PublicKeyBundle JSON
    Keygen { name: String },
    /// Grant a recipient's PublicKeyBundle JSON access to future secret encryptions
    Grant { name: String, pubkey_json: String },
    /// Rotate a secret's DEK to epoch+1, optionally dropping a revoked recipient fingerprint
    Rotate {
        path: String,
        #[arg(long, default_value = "secret:dev")]
        domain: String,
        #[arg(long)]
        drop: Option<String>,
    },
}

#[derive(Subcommand)]
enum EmbargoAction {
    /// Create an embargoed security ChangeSet isolated from public projections
    Create {
        advisory: String,
        /// Team or domain allowed to read the embargoed change (repeatable or comma-separated)
        #[arg(long = "allow", required = true)]
        allow: Vec<String>,
        /// Description for the embargoed ChangeSet
        #[arg(short = 'm', long = "message")]
        message: String,
    },
    /// Publish an active embargoed advisory, promoting it to public
    Publish { advisory: String },
}

#[derive(Subcommand)]
enum ContextAction {
    /// Attach a durable prompt/rationale record anchored to a code range
    Add {
        #[arg(long)]
        prompt: String,
        #[arg(long)]
        path: String,
        /// 1-based line range (`start-end` or single line)
        #[arg(long)]
        lines: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        harness: Option<String>,
        #[arg(long, default_value = "public")]
        visibility: String,
    },
}

#[derive(Subcommand)]
enum CheckpointAction {
    /// Save a sub-commit agent checkpoint of the current working tree
    Save {
        #[arg(short = 'm', long = "message")]
        message: String,
        #[arg(long)]
        session: Option<String>,
    },
    /// List checkpoints for the active workspace
    List,
    /// Undo an agent checkpoint while preserving subsequent human edits via 3-way inverse patch
    Undo { checkpoint_id: String },
}

#[derive(Subcommand)]
enum FleetAction {
    /// Export local overlay files to a portable JSON bundle (optionally end-to-end encrypted)
    Export {
        bundle_path: PathBuf,
        /// Comma-separated glob patterns to include
        #[arg(long, default_value = ".env,.env.local")]
        include: String,
        /// Encrypt the exported overlay bundle end-to-end for authorized keyring recipients
        #[arg(long)]
        encrypted: bool,
        /// Source machine identifier recorded in bundle metadata and AEAD AAD
        #[arg(long)]
        machine: Option<String>,
    },
    /// Apply a fleet overlay bundle onto the current directory
    Apply {
        bundle_path: PathBuf,
        /// Decrypt an end-to-end encrypted fleet overlay bundle using the repo's local keypair
        #[arg(long)]
        encrypted: bool,
    },
}

#[derive(Subcommand)]
enum RemoteAction {
    /// Register a new remote gitx-server repository in .gitx/remotes.toml
    Add {
        /// Local alias for the remote (e.g. origin)
        name: String,
        /// Remote URL (e.g. http://127.0.0.1:7878/owner/repo or http://127.0.0.1:7878)
        url: String,
        /// Repository owner (optional when embedded in <url>)
        #[arg(long)]
        owner: Option<String>,
        /// Repository name (optional when embedded in <url>)
        #[arg(long)]
        repo: Option<String>,
        /// Default authentication token for this remote
        #[arg(long)]
        token: Option<String>,
    },
    /// List configured remotes
    List,
    /// Show details and tracked heads for a configured remote
    Show {
        /// Remote name
        name: String,
    },
    /// Remove a configured remote
    Rm {
        /// Remote name
        name: String,
    },
    /// Zero-clone server-side grep (works with --url even without a local .gitx repo)
    Grep {
        /// Search query pattern
        pattern: String,
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Revision hash, ChangeId, or bookmark to search
        #[arg(long)]
        rev: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
        /// Case-insensitive matching
        #[arg(short = 'i', long)]
        case_insensitive: bool,
    },
    /// Zero-clone server-side unified diff between two revisions
    Diff {
        /// Source revision hash, ChangeId, or bookmark
        from: String,
        /// Target revision hash, ChangeId, or bookmark
        to: String,
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
    /// Zero-clone server-side line-by-line blame for a file path
    Blame {
        /// Repository-relative file path
        path: String,
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Revision hash, ChangeId, or bookmark
        #[arg(long)]
        rev: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
    /// Zero-clone server-side ACL-filtered commit history log
    Log {
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Revision hash, ChangeId, or bookmark to start from
        #[arg(long)]
        rev: Option<String>,
        /// Maximum number of commits to show
        #[arg(long)]
        limit: Option<usize>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
    /// Query server-side derived data engine cache statistics (/derived/stats)
    Stats {
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum QueueAction {
    /// Upload current ChangeSet lock-free and enqueue it onto the remote merge queue
    Enqueue {
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Target bookmark on the remote (defaults to repository default branch)
        #[arg(long)]
        target: Option<String>,
        /// Commit message override
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
    /// List entries in the remote merge queue
    List {
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Target bookmark on the remote (defaults to 'master')
        #[arg(long)]
        target: Option<String>,
        /// Show only pending entries
        #[arg(long)]
        pending_only: bool,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
    /// Atomically drain pending entries from the remote merge queue
    Drain {
        /// Configured remote name (defaults to 'origin')
        #[arg(long)]
        remote: Option<String>,
        /// Direct remote URL (e.g. http://127.0.0.1:7878/owner/repo)
        #[arg(long)]
        url: Option<String>,
        /// Target bookmark on the remote (defaults to repository default branch or 'master')
        #[arg(long)]
        target: Option<String>,
        /// Maximum number of pending entries to drain in one batch
        #[arg(long)]
        max_batch_size: Option<usize>,
        /// Authentication token override
        #[arg(long)]
        token: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            colocate,
            name,
            email,
        } => commands::core::cmd_init(colocate, name, email),
        Commands::Status => commands::core::cmd_status(),
        Commands::Diff {
            interdiff,
            from,
            to,
        } => commands::core::cmd_diff(interdiff, from, to),
        Commands::Log { limit, all_domains } => commands::core::cmd_log(limit, all_domains),
        Commands::New {
            message,
            visibility,
            reveal_on_land,
            agent,
        } => commands::core::cmd_new(message, visibility, reveal_on_land, agent),
        Commands::Describe { message } => commands::core::cmd_describe(message),
        Commands::Stack { action } => match action {
            StackAction::Create { name } => commands::stack::cmd_stack_create(name),
            StackAction::List => commands::stack::cmd_stack_list(),
            StackAction::Sync => commands::stack::cmd_stack_sync(),
        },
        Commands::Land { target } => commands::stack::cmd_land(target),
        Commands::Revert { land_seq } => commands::stack::cmd_revert(land_seq),
        Commands::Op { action } => match action {
            OpAction::Log { limit } => commands::stack::cmd_op_log(limit),
        },
        Commands::Undo => commands::stack::cmd_undo(),
        Commands::Ws { action } => match action {
            WsAction::Add {
                name,
                path,
                mem,
                lazy,
            } => commands::workspace::cmd_ws_add(name, path, mem, lazy),
            WsAction::List => commands::workspace::cmd_ws_list(),
            WsAction::Rm { name } => commands::workspace::cmd_ws_rm(name),
            WsAction::Mount {
                name,
                mountpoint,
                backend,
            } => commands::workspace::cmd_ws_mount(name, mountpoint, backend),
            WsAction::Unmount { mountpoint } => commands::workspace::cmd_ws_unmount(mountpoint),
        },
        Commands::Secret { action } => match action {
            SecretAction::Set { path, domain } => commands::security::cmd_secret_set(path, domain),
            SecretAction::Get { path, domain } => commands::security::cmd_secret_get(path, domain),
            SecretAction::Keygen { name } => commands::security::cmd_secret_keygen(name),
            SecretAction::Grant { name, pubkey_json } => {
                commands::security::cmd_secret_grant(name, pubkey_json)
            }
            SecretAction::Rotate { path, domain, drop } => {
                commands::security::cmd_secret_rotate(path, domain, drop)
            }
        },
        Commands::Embargo { action } => match action {
            EmbargoAction::Create {
                advisory,
                allow,
                message,
            } => commands::security::cmd_embargo_create(advisory, allow, message),
            EmbargoAction::Publish { advisory } => commands::security::cmd_embargo_publish(advisory),
        },
        Commands::Context { action } => match action {
            ContextAction::Add {
                prompt,
                path,
                lines,
                model,
                harness,
                visibility,
            } => commands::context::cmd_context_add(prompt, path, lines, model, harness, visibility),
        },
        Commands::Why { target, domains } => commands::context::cmd_why(target, domains),
        Commands::Checkpoint { action } => match action {
            CheckpointAction::Save { message, session } => {
                commands::context::cmd_checkpoint_save(message, session)
            }
            CheckpointAction::List => commands::context::cmd_checkpoint_list(),
            CheckpointAction::Undo { checkpoint_id } => {
                commands::context::cmd_checkpoint_undo(checkpoint_id)
            }
        },
        Commands::GitExport {
            target_dir,
            domains,
        } => commands::workspace::cmd_git_export(target_dir, domains),
        Commands::Fleet { action } => match action {
            FleetAction::Export {
                bundle_path,
                include,
                encrypted,
                machine,
            } => commands::workspace::cmd_fleet_export(bundle_path, include, encrypted, machine),
            FleetAction::Apply {
                bundle_path,
                encrypted,
            } => commands::workspace::cmd_fleet_apply(bundle_path, encrypted),
        },
        Commands::Serve { addr, data_dir } => commands::serve::cmd_serve(addr, data_dir),
        Commands::Mcp { in_memory } => commands::mcp::cmd_mcp(in_memory),
        Commands::Symbols { path, json } => commands::symbols::cmd_symbols(path, json),
        Commands::Remote { action } => match action {
            RemoteAction::Add {
                name,
                url,
                owner,
                repo,
                token,
            } => commands::remote::cmd_remote_add(name, url, owner, repo, token),
            RemoteAction::List => commands::remote::cmd_remote_list(),
            RemoteAction::Show { name } => commands::remote::cmd_remote_show(name),
            RemoteAction::Rm { name } => commands::remote::cmd_remote_rm(name),
            RemoteAction::Grep {
                pattern,
                remote,
                url,
                rev,
                token,
                case_insensitive,
            } => commands::remote::cmd_remote_grep(
                pattern,
                remote,
                url,
                rev,
                token,
                case_insensitive,
            ),
            RemoteAction::Diff {
                from,
                to,
                remote,
                url,
                token,
            } => commands::remote::cmd_remote_diff(from, to, remote, url, token),
            RemoteAction::Blame {
                path,
                remote,
                url,
                rev,
                token,
            } => commands::remote::cmd_remote_blame(path, remote, url, rev, token),
            RemoteAction::Log {
                remote,
                url,
                rev,
                limit,
                token,
            } => commands::remote::cmd_remote_log(remote, url, rev, limit, token),
            RemoteAction::Stats { remote, url, token } => {
                commands::remote::cmd_remote_stats(remote, url, token)
            }
        },
        Commands::Push {
            remote,
            target,
            message,
            token,
        } => commands::remote::cmd_push(remote, target, message, token),
        Commands::Pull {
            remote,
            target,
            token,
        } => commands::remote::cmd_pull(remote, target, token),
        Commands::Queue { action } => match action {
            QueueAction::Enqueue {
                remote,
                url,
                target,
                message,
                token,
            } => commands::queue::cmd_queue_enqueue(remote, url, target, message, token),
            QueueAction::List {
                remote,
                url,
                target,
                pending_only,
                token,
            } => commands::queue::cmd_queue_list(remote, url, target, pending_only, token),
            QueueAction::Drain {
                remote,
                url,
                target,
                max_batch_size,
                token,
            } => commands::queue::cmd_queue_drain(remote, url, target, max_batch_size, token),
        },
    }
}
