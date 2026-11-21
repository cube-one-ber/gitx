use crate::auth::{AuthenticatedPrincipal, effective_allowed_domains};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use gitx_git_bridge::{
    UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE, UPLOAD_PACK_RESULT_CONTENT_TYPE,
    advertise_upload_pack_refs_with_protocol, export_to_git_repo,
    handle_upload_pack_with_protocol,
};
use gitx_store::ObjectStore;
use serde::Deserialize;
use std::sync::Arc;
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    #[serde(default)]
    pub service: Option<String>,
}

/// `GET /{owner}/{name}.git/info/refs?service=git-upload-pack`
///
/// Dynamically projects the repository into a temporary bare Git directory restricted
/// strictly to the caller's authorized visibility domains, then advertises refs via
/// `git-upload-pack --stateless-rpc --advertise-refs`.
pub async fn info_refs(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, raw_repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if query.service.as_deref() != Some("git-upload-pack") {
        return Err(ApiError::forbidden(
            "only service=git-upload-pack is supported on this endpoint",
        ));
    }

    let name = strip_git_suffix(&raw_repo);
    let repo = state
        .get_repo(&owner, name)?
        .ok_or_else(|| ApiError::not_found(format!("repository '{owner}/{name}' not found")))?;

    let policy = repo.acl_snapshot()?;
    let git_protocol = headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    let payload = tokio::task::spawn_blocking(move || -> ApiResult<Vec<u8>> {
        let allowed_domains = effective_allowed_domains(repo.store.as_ref(), &policy, &principal);
        let bookmarks = repo.store.list_bookmarks()?;

        let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
        export_to_git_repo(repo.store.as_ref(), tmp.path(), &allowed_domains, &bookmarks)?;

        let body = advertise_upload_pack_refs_with_protocol(tmp.path(), git_protocol.as_deref())?;
        Ok(body)
    })
    .await
    .map_err(|e| ApiError::internal(format!("git upload-pack task join error: {e}")))??;

    Ok(build_git_response(
        UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE,
        payload,
    ))
}

/// `POST /{owner}/{name}.git/git-upload-pack`
///
/// Serves a real `git-upload-pack --stateless-rpc` packfile stream built strictly from the
/// caller's ACL-filtered Git projection.
pub async fn upload_pack(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, raw_repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let name = strip_git_suffix(&raw_repo);
    let repo = state
        .get_repo(&owner, name)?
        .ok_or_else(|| ApiError::not_found(format!("repository '{owner}/{name}' not found")))?;

    let policy = repo.acl_snapshot()?;
    let git_protocol = headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let request_bytes = body.to_vec();

    let payload = tokio::task::spawn_blocking(move || -> ApiResult<Vec<u8>> {
        let allowed_domains = effective_allowed_domains(repo.store.as_ref(), &policy, &principal);
        let bookmarks = repo.store.list_bookmarks()?;

        let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
        export_to_git_repo(repo.store.as_ref(), tmp.path(), &allowed_domains, &bookmarks)?;

        let response =
            handle_upload_pack_with_protocol(tmp.path(), &request_bytes, git_protocol.as_deref())?;
        Ok(response)
    })
    .await
    .map_err(|e| ApiError::internal(format!("git upload-pack task join error: {e}")))??;

    Ok(build_git_response(
        UPLOAD_PACK_RESULT_CONTENT_TYPE,
        payload,
    ))
}

fn strip_git_suffix(raw: &str) -> &str {
    raw.strip_suffix(".git").unwrap_or(raw)
}

fn build_git_response(content_type: &'static str, payload: Vec<u8>) -> Response {
    let mut resp = (StatusCode::OK, payload).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, max-age=0, must-revalidate"),
    );
    resp
}
