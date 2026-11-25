//! Tonic gRPC service wrapping [`AppState`] with bearer-token authentication and
//! full Visibility Domain ACL enforcement matching the HTTP API.

use crate::api::{
    self, ActorAgentInput, BlameQuery, CommitRequest, DiffQuery, GrepQuery, LandRequest, TreeQuery,
    read_blob_authorized,
};
use crate::auth::{
    AuthenticatedPrincipal, can_administer_acl, extract_principal_from_grpc_metadata,
};
use crate::error::ApiError;
use crate::queue::{self, DrainRequest, EnqueueRequest, QueueEntry, QueueStatus};
use crate::state::{AppState, RepoInfo};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use chrono::SecondsFormat;
use gitx_core::{GitxError, Result};
use gitx_proto::gitx_service_server::{GitxService, GitxServiceServer};
use gitx_proto::{
    BlameLine as ProtoBlameLine, BlameRequest, BlameResponse, CommitRequest as ProtoCommitRequest,
    CommitResponse as ProtoCommitResponse, CreateRepoRequest, CreateRepoResponse,
    DiffFileEntry as ProtoDiffFileEntry, DiffRequest, DiffResponse, DrainMergeQueueRequest,
    DrainMergeQueueResponse, EnqueueMergeRequest, EnqueueMergeResponse, GetTreeRequest,
    GetTreeResponse, GrepMatch as ProtoGrepMatch, GrepRequest, GrepResponse, HealthRequest,
    HealthResponse, LandRequest as ProtoLandRequest, LandResponse as ProtoLandResponse,
    ListReposRequest, ListReposResponse, QueueEntry as ProtoQueueEntry, ReadBlobRequest,
    ReadBlobResponse, RepoInfo as ProtoRepoInfo, RevertRequest, RevertResponse,
    TreeFileEntry as ProtoTreeFileEntry,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

/// Tonic gRPC server implementation exposing GitX zero-clone & merge-queue RPCs.
#[derive(Clone)]
pub struct GitxGrpcService {
    state: Arc<AppState>,
}

impl GitxGrpcService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> GitxServiceServer<Self> {
        GitxServiceServer::new(self)
    }
}

/// Serve the Tonic `GitxService` gRPC server on a pre-bound `TcpListener`.
pub async fn serve_grpc(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    if let Ok(local_addr) = listener.local_addr() {
        tracing::info!("gitx-server gRPC listening on grpc://{local_addr}");
    }
    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(GitxGrpcService::new(state).into_server())
        .serve_with_incoming(incoming)
        .await
        .map_err(|e| GitxError::Storage(format!("gRPC server error: {e}")))
}

/// Bind `addr` and serve the Tonic `GitxService` gRPC server.
pub async fn serve_grpc_addr(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(GitxError::Io)?;
    serve_grpc(listener, state).await
}

fn api_err_to_status(err: ApiError) -> Status {
    match err.status {
        StatusCode::BAD_REQUEST => Status::invalid_argument(err.message),
        StatusCode::UNAUTHORIZED => Status::unauthenticated(err.message),
        StatusCode::FORBIDDEN => Status::permission_denied(err.message),
        StatusCode::NOT_FOUND => Status::not_found(err.message),
        StatusCode::CONFLICT => Status::aborted(err.message),
        _ => Status::internal(err.message),
    }
}

fn repo_info_to_proto(info: RepoInfo) -> ProtoRepoInfo {
    ProtoRepoInfo {
        owner: info.owner,
        name: info.name,
        full_name: info.full_name,
        default_branch: info.default_branch,
        bookmarks: info.bookmarks.into_iter().collect(),
    }
}

fn queue_entry_to_proto(entry: QueueEntry) -> ProtoQueueEntry {
    let (status, land_seq, conflict_paths, rejection_reason) = match entry.status {
        QueueStatus::Pending => ("pending".to_string(), None, Vec::new(), None),
        QueueStatus::Landed { land_seq } => ("landed".to_string(), Some(land_seq), Vec::new(), None),
        QueueStatus::Conflicted { conflict_paths } => {
            ("conflicted".to_string(), None, conflict_paths, None)
        }
        QueueStatus::Rejected { reason } => ("rejected".to_string(), None, Vec::new(), Some(reason)),
    };

    ProtoQueueEntry {
        id: entry.id,
        changeset_id: entry.changeset_id,
        change_id: entry.change_id,
        target: entry.target,
        submitted_by: entry.submitted_by,
        enqueued_at: entry.enqueued_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
        status,
        land_seq,
        conflict_paths,
        rejection_reason,
    }
}

#[tonic::async_trait]
impl GitxService for GitxGrpcService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> std::result::Result<Response<HealthResponse>, Status> {
        let Json(resp) = api::health().await;
        Ok(Response::new(HealthResponse {
            status: resp.status,
        }))
    }

    async fn create_repo(
        &self,
        request: Request<CreateRepoRequest>,
    ) -> std::result::Result<Response<CreateRepoResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        if principal.is_anonymous {
            return Err(Status::permission_denied(
                "anonymous callers are not permitted to create or configure repositories",
            ));
        }
        let req = request.into_inner();
        let (repo, existed) = self
            .state
            .get_or_create_repo_with_status(&req.owner, &req.name)
            .map_err(|e| api_err_to_status(ApiError::from(e)))?;
        if let Some(acl_text) = req.acl {
            if existed || repo.has_default_acl() {
                let existing_policy = repo
                    .acl_snapshot()
                    .map_err(|e| api_err_to_status(ApiError::from(e)))?;
                let unchanged = repo
                    .current_acl_text()
                    .is_some_and(|cur| cur.trim() == acl_text.trim());
                if !unchanged && !can_administer_acl(&existing_policy, &principal) {
                    return Err(Status::permission_denied(format!(
                        "principal '{}' is not authorized to modify .gitxacl on '{}/{}'",
                        principal.id, req.owner, req.name
                    )));
                }
            }
            repo.update_acl_from_text(&acl_text)
                .map_err(|e| api_err_to_status(ApiError::from(e)))?;
        }
        let info = repo
            .info()
            .map_err(|e| api_err_to_status(ApiError::from(e)))?;
        Ok(Response::new(CreateRepoResponse {
            repo: Some(repo_info_to_proto(info)),
        }))
    }

    async fn list_repos(
        &self,
        request: Request<ListReposRequest>,
    ) -> std::result::Result<Response<ListReposResponse>, Status> {
        let _principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let owner_filter = req.owner.as_deref().filter(|s| !s.is_empty());
        let repos = self
            .state
            .list_repos(owner_filter)
            .map_err(|e| api_err_to_status(ApiError::from(e)))?;
        Ok(Response::new(ListReposResponse {
            repos: repos.into_iter().map(repo_info_to_proto).collect(),
        }))
    }

    async fn get_tree(
        &self,
        request: Request<GetTreeRequest>,
    ) -> std::result::Result<Response<GetTreeResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let Json(resp) = api::get_tree(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Query(TreeQuery {
                rev: req.rev,
                domain: req.domain,
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        let mut files = Vec::with_capacity(resp.files.len());
        for f in resp.files {
            let content = if let Some(text) = f.content {
                text.into_bytes()
            } else if let Some(b64) = f.content_base64 {
                BASE64_STANDARD
                    .decode(b64)
                    .map_err(|e| Status::internal(format!("failed to decode blob base64: {e}")))?
            } else {
                Vec::new()
            };
            files.push(ProtoTreeFileEntry {
                path: f.path,
                domain: f.domain,
                size: f.size,
                blob_hash: f.blob_hash,
                content,
            });
        }

        Ok(Response::new(GetTreeResponse {
            rev: resp.rev,
            domains: resp.domains,
            files,
        }))
    }

    async fn read_blob(
        &self,
        request: Request<ReadBlobRequest>,
    ) -> std::result::Result<Response<ReadBlobResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let blob = read_blob_authorized(
            &self.state,
            &principal,
            &req.owner,
            &req.name,
            req.rev.as_deref(),
            &req.path,
            req.blob_hash.as_deref(),
        )
        .map_err(api_err_to_status)?;

        Ok(Response::new(ReadBlobResponse {
            path: blob.path,
            domain: blob.domain,
            blob_hash: blob.blob_hash,
            size: blob.size,
            content: blob.content,
        }))
    }

    async fn diff(
        &self,
        request: Request<DiffRequest>,
    ) -> std::result::Result<Response<DiffResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let Json(resp) = api::get_diff(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Query(DiffQuery {
                from: req.from,
                to: req.to,
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(DiffResponse {
            from: resp.from,
            to: resp.to,
            files: resp
                .files
                .into_iter()
                .map(|f| ProtoDiffFileEntry {
                    path: f.path,
                    domain: f.domain,
                    status: f.status,
                    patch: f.patch,
                })
                .collect(),
            unified_diff: resp.unified_diff,
        }))
    }

    async fn grep(
        &self,
        request: Request<GrepRequest>,
    ) -> std::result::Result<Response<GrepResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let Json(resp) = api::grep(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Query(GrepQuery {
                q: req.query,
                rev: req.rev,
                case_insensitive: Some(req.case_insensitive),
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(GrepResponse {
            query: resp.query,
            rev: resp.rev,
            matches: resp
                .matches
                .into_iter()
                .map(|m| ProtoGrepMatch {
                    path: m.path,
                    domain: m.domain,
                    line_number: m.line_number as u64,
                    line: m.line,
                })
                .collect(),
        }))
    }

    async fn blame(
        &self,
        request: Request<BlameRequest>,
    ) -> std::result::Result<Response<BlameResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let Json(resp) = api::blame(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Query(BlameQuery {
                path: req.path,
                rev: req.rev,
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(BlameResponse {
            path: resp.path,
            rev: resp.rev,
            lines: resp
                .lines
                .into_iter()
                .map(|l| ProtoBlameLine {
                    line_number: l.line_number as u64,
                    content: l.content,
                    changeset_id: l.changeset_id,
                    change_id: l.change_id,
                    author_name: l.author_name,
                    author_email: l.author_email,
                    timestamp: l.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    message: l.message,
                })
                .collect(),
        }))
    }

    async fn commit(
        &self,
        request: Request<ProtoCommitRequest>,
    ) -> std::result::Result<Response<ProtoCommitResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();

        let mut files: BTreeMap<String, String> = BTreeMap::new();
        for f in req.files {
            files.insert(f.path, BASE64_STANDARD.encode(f.content));
        }

        let author_name = if req.author_name.trim().is_empty() {
            principal.id.clone()
        } else {
            req.author_name
        };
        let author_email = if req.author_email.trim().is_empty() {
            format!("{}@gitx.local", principal.id)
        } else {
            req.author_email
        };

        let http_req = CommitRequest {
            files,
            delete_files: req.delete_files,
            encoding: Some("base64".to_string()),
            message: req.message,
            author_name,
            author_email,
            actor_agent: req.actor_agent.map(|a| ActorAgentInput {
                harness: a.harness,
                model: a.model,
                session_id: a.session_id,
            }),
            target: req.target,
            parent: req.parent,
            update_target: req.update_target,
            visibility_domain: req.visibility_domain,
            embargo_advisory: req.embargo_advisory,
            embargo_allowed_teams: req.embargo_allowed_teams,
            context_prompt: req.context_prompt,
            secret_envelopes: BTreeMap::new(),
        };

        let Json(resp) = api::commit(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Json(http_req),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(ProtoCommitResponse {
            changeset_id: resp.changeset_id,
            change_id: resp.change_id,
            public_projection_hash: resp.public_projection_hash,
            domains_written: resp.domains_written,
            target: resp.target,
        }))
    }

    async fn land(
        &self,
        request: Request<ProtoLandRequest>,
    ) -> std::result::Result<Response<ProtoLandResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let target = if req.target.trim().is_empty() {
            "master".to_string()
        } else {
            req.target
        };

        let Json(resp) = api::land(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Json(LandRequest {
                changeset_id: req.changeset_id,
                target,
                expected_head: req.expected_head,
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(ProtoLandResponse {
            land_seq: resp.land_seq,
            target: resp.target,
            previous_head: resp.previous_head,
            new_head: resp.new_head,
            conflicts: resp.conflicts,
        }))
    }

    async fn revert(
        &self,
        request: Request<RevertRequest>,
    ) -> std::result::Result<Response<RevertResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();

        let Json(resp) = api::revert_land(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name, req.land_seq)),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(RevertResponse {
            reverted_land_seq: resp.reverted_land_seq,
            revert_land_seq: resp.revert_land_seq,
            target: resp.target,
            restored_head: resp.restored_head,
        }))
    }

    async fn enqueue_merge(
        &self,
        request: Request<EnqueueMergeRequest>,
    ) -> std::result::Result<Response<EnqueueMergeResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let target = if req.target.trim().is_empty() {
            "master".to_string()
        } else {
            req.target
        };

        let Json(resp) = queue::enqueue(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            Json(EnqueueRequest {
                changeset_id: req.changeset_id,
                target,
            }),
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(EnqueueMergeResponse {
            entry: Some(queue_entry_to_proto(resp.entry)),
            queue_depth: resp.queue_depth as u64,
        }))
    }

    async fn drain_merge_queue(
        &self,
        request: Request<DrainMergeQueueRequest>,
    ) -> std::result::Result<Response<DrainMergeQueueResponse>, Status> {
        let principal = extract_principal_from_grpc_metadata(&self.state, request.metadata())?;
        let req = request.into_inner();
        let target = if req.target.trim().is_empty() {
            "master".to_string()
        } else {
            req.target
        };

        let drain_req = DrainRequest {
            target,
            max_batch_size: req.max_batch_size.map(|n| n as usize),
        };
        let body = Bytes::from(
            serde_json::to_vec(&drain_req)
                .map_err(|e| Status::internal(format!("failed to encode drain request: {e}")))?,
        );

        let Json(resp) = queue::drain_queue(
            State(Arc::clone(&self.state)),
            AuthenticatedPrincipal(principal),
            Path((req.owner, req.name)),
            body,
        )
        .await
        .map_err(api_err_to_status)?;

        Ok(Response::new(DrainMergeQueueResponse {
            target: resp.target,
            land_seq: resp.land_seq,
            previous_head: resp.previous_head,
            new_head: resp.new_head,
            landed: resp.landed.into_iter().map(queue_entry_to_proto).collect(),
            conflicted: resp
                .conflicted
                .into_iter()
                .map(queue_entry_to_proto)
                .collect(),
            rejected: resp
                .rejected
                .into_iter()
                .map(queue_entry_to_proto)
                .collect(),
            resolved_conflicts: resp.resolved_conflicts,
        }))
    }
}
