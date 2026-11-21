//! Always-online, ACL-enforcing HTTP/JSON and Git Smart HTTP server for GitX.

pub mod api;
pub mod auth;
pub mod derived;
pub mod error;
pub mod git_http;
pub mod queue;
pub mod state;

pub use api::{
    ActorAgentInput, BlameLine, BlameResponse, CommitRequest, CommitResponse, CreateRepoRequest,
    CreateRepoResponse, DiffFileEntry, DiffResponse, GrepMatch, GrepResponse, HealthResponse,
    LandRequest, LandResponse, ListReposResponse, LogEntry, LogResponse, PublishEmbargoRequest,
    PublishEmbargoResponse, RevertResponse, TreeFileEntry, TreeResponse, WhyResponse,
};
pub use auth::{
    AuthenticatedPrincipal, HEADER_FINGERPRINT, HEADER_ROLES, HEADER_TEAMS, HEADER_USER,
    allowed_domains_for_repo, extract_principal,
};
pub use derived::{
    CommitGraphIndex, CommitGraphNode, DerivedIndex, DerivedStats, PathHistoryIndex, TrigramIndex,
    TrigramSearchIndex,
};
pub use error::{ApiError, ApiResult};
pub use queue::{
    ConflictResolverFn, DrainRequest, DrainResponse, EnqueueRequest, EnqueueResponse, MergeQueue,
    QueueEntry, QueueListQuery, QueueListResponse, QueueStatus,
};
pub use state::{AppState, RepoHandle, RepoInfo, ServerConfig};

use axum::Router;
use axum::routing::{get, post};
use gitx_core::{GitxError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Build the complete Axum router for the GitX JSON API and ACL-filtered Git Smart HTTP server.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(api::health))
        // Repository management
        .route("/v1/repos", get(api::list_all_repos))
        .route("/v1/repos/{owner}/repos", get(api::list_owner_repos))
        .route(
            "/v1/repos/{owner}/{name}/repos",
            get(api::list_repo_scoped_repos),
        )
        .route("/v1/repos/{owner}/{name}", post(api::create_repo))
        // Zero-clone server-side operations
        .route("/v1/repos/{owner}/{name}/commit", post(api::commit))
        .route("/v1/repos/{owner}/{name}/land", post(api::land))
        .route(
            "/v1/repos/{owner}/{name}/revert/{land_seq}",
            post(api::revert_land),
        )
        .route("/v1/repos/{owner}/{name}/tree", get(api::get_tree))
        .route("/v1/repos/{owner}/{name}/diff", get(api::get_diff))
        .route("/v1/repos/{owner}/{name}/grep", get(api::grep))
        .route("/v1/repos/{owner}/{name}/blame", get(api::blame))
        .route("/v1/repos/{owner}/{name}/log", get(api::log_history))
        .route("/v1/repos/{owner}/{name}/why", get(api::why))
        .route(
            "/v1/repos/{owner}/{name}/embargo/{advisory}/publish",
            post(api::publish_embargo),
        )
        // Derived data engine observability
        .route("/v1/repos/{owner}/{name}/derived/stats", get(api::derived_stats))
        // Batched lock-free agentic merge queue
        .route(
            "/v1/repos/{owner}/{name}/queue/enqueue",
            post(queue::enqueue),
        )
        .route("/v1/repos/{owner}/{name}/queue", get(queue::list_queue))
        .route(
            "/v1/repos/{owner}/{name}/queue/drain",
            post(queue::drain_queue),
        )
        // ACL-filtered Git Smart HTTP endpoints (supports `/{owner}/{name}.git/...`)
        .route("/{owner}/{repo}/info/refs", get(git_http::info_refs))
        .route(
            "/{owner}/{repo}/git-upload-pack",
            post(git_http::upload_pack),
        )
        .with_state(state)
}

/// Serve the GitX HTTP/JSON and Git Smart HTTP server on a pre-bound `TcpListener`.
pub async fn serve(listener: TcpListener, config: ServerConfig) -> Result<()> {
    let state = Arc::new(AppState::new(config));
    let router = build_router(state);
    if let Ok(local_addr) = listener.local_addr() {
        tracing::info!("gitx-server listening on http://{local_addr}");
    }
    axum::serve(listener, router).await.map_err(GitxError::Io)
}

/// Bind `addr` and serve the GitX HTTP/JSON and Git Smart HTTP server.
pub async fn serve_addr(addr: SocketAddr, config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(GitxError::Io)?;
    serve(listener, config).await
}
