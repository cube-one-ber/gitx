use crate::auth::{
    AuthenticatedPrincipal, can_administer_acl, can_write_domain_effective,
    readable_non_embargo_domains,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use gitx_core::DomainId;
use gitx_git_bridge::{
    RECEIVE_PACK_ADVERTISEMENT_CONTENT_TYPE, RECEIVE_PACK_RESULT_CONTENT_TYPE,
    UPLOAD_PACK_ADVERTISEMENT_CONTENT_TYPE, UPLOAD_PACK_RESULT_CONTENT_TYPE,
    advertise_receive_pack_refs_with_protocol, advertise_upload_pack_refs_with_protocol,
    export_receive_pack_staging_filtered, export_to_git_repo_filtered,
    handle_receive_pack_with_protocol, handle_upload_pack_with_protocol,
    import_received_refs_with_policy, list_bare_branch_refs,
};
use serde::Deserialize;
use std::sync::Arc;
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

/// `GET /{owner}/{name}.git/info/refs?service=git-upload-pack|git-receive-pack`
///
/// Dynamically projects the repository into a temporary bare Git directory restricted
/// strictly to the caller's authorized visibility domains, then advertises refs.
pub async fn info_refs(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, raw_repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let service = query.service.as_deref().unwrap_or("");
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return Err(ApiError::forbidden(
            "only service=git-upload-pack or service=git-receive-pack is supported",
        ));
    }

    let name = strip_git_suffix(&raw_repo);
    let git_protocol = headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    if service == "git-receive-pack" {
        if principal.is_anonymous {
            return Err(ApiError::forbidden(
                "anonymous callers are not permitted to git-push (git-receive-pack)",
            ));
        }
        let target_domain = match query.domain.as_deref().filter(|s| !s.is_empty()) {
            Some(raw) => DomainId::new(raw)?,
            None => DomainId::public(),
        };
        if target_domain.is_embargo() {
            return Err(ApiError::forbidden(format!(
                "git-receive-pack cannot target embargo domain '{target_domain}'"
            )));
        }
        let repo = state.get_or_create_repo(&owner, name)?;
        let policy = repo.acl_snapshot()?;
        let is_admin = principal.roles.iter().any(|r| r == "admin");
        if !can_write_domain_effective(&policy, &principal, &target_domain, &[])
            || (target_domain.is_secret()
                && !is_admin
                && !policy.can_write_domain(&principal, &target_domain))
        {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to push into domain '{}'",
                principal.id, target_domain
            )));
        }

        let payload = tokio::task::spawn_blocking(move || -> ApiResult<Vec<u8>> {
            let bookmarks = repo.store.list_bookmarks()?;
            let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
            export_receive_pack_staging_filtered(
                repo.store.as_ref(),
                tmp.path(),
                &target_domain,
                &bookmarks,
                |cs| repo.can_read_changeset_live(&policy, &principal, cs),
            )?;
            let body =
                advertise_receive_pack_refs_with_protocol(tmp.path(), git_protocol.as_deref())?;
            Ok(body)
        })
        .await
        .map_err(|e| ApiError::internal(format!("git receive-pack task join error: {e}")))??;

        return Ok(build_git_response(
            RECEIVE_PACK_ADVERTISEMENT_CONTENT_TYPE,
            payload,
        ));
    }

    let repo = state
        .get_repo(&owner, name)?
        .ok_or_else(|| ApiError::not_found(format!("repository '{owner}/{name}' not found")))?;

    let policy = repo.acl_snapshot()?;

    let payload = tokio::task::spawn_blocking(move || -> ApiResult<Vec<u8>> {
        let allowed_domains =
            readable_non_embargo_domains(repo.store.as_ref(), &policy, &principal);
        let bookmarks = repo.store.list_bookmarks()?;

        let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
        export_to_git_repo_filtered(
            repo.store.as_ref(),
            tmp.path(),
            &allowed_domains,
            &bookmarks,
            |cs| repo.can_read_changeset_live(&policy, &principal, cs),
        )?;

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

/// `POST /{owner}/{name}.git/git-receive-pack`
///
/// Serves an authenticated, ACL-enforcing `git-receive-pack --stateless-rpc` push into the
/// caller's target domain (default `public`), scanning every pushed file for leaked secrets
/// before importing commits into `gitx-store`.
pub async fn receive_pack(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, raw_repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to git-push (git-receive-pack)",
        ));
    }

    let target_domain = match query.domain.as_deref().filter(|s| !s.is_empty()) {
        Some(raw) => DomainId::new(raw)?,
        None => DomainId::public(),
    };
    if target_domain.is_embargo() {
        return Err(ApiError::forbidden(format!(
            "git-receive-pack cannot target embargo domain '{target_domain}'"
        )));
    }

    let name = strip_git_suffix(&raw_repo);
    let repo = state.get_or_create_repo(&owner, name)?;
    let policy = repo.acl_snapshot()?;
    let is_admin = principal.roles.iter().any(|r| r == "admin");
    if !can_write_domain_effective(&policy, &principal, &target_domain, &[])
        || (target_domain.is_secret()
            && !is_admin
            && !policy.can_write_domain(&principal, &target_domain))
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to push into domain '{}'",
            principal.id, target_domain
        )));
    }
    let can_admin_acl = can_administer_acl(&policy, &principal);

    let git_protocol = headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let request_bytes = body.to_vec();

    let payload = tokio::task::spawn_blocking(move || -> ApiResult<Vec<u8>> {
        let bookmarks = repo.store.list_bookmarks()?;
        let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
        export_receive_pack_staging_filtered(
            repo.store.as_ref(),
            tmp.path(),
            &target_domain,
            &bookmarks,
            |cs| repo.can_read_changeset_live(&policy, &principal, cs),
        )?;
        let refs_before = list_bare_branch_refs(tmp.path())?;

        // Reject branch deletions at the Git protocol level so single-domain HTTP pushes
        // cannot silently drop or desynchronize multi-domain GitX bookmarks.
        let cfg_status = std::process::Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["config", "receive.denyDeletes", "true"])
            .status()
            .map_err(|e| ApiError::internal(e.to_string()))?;
        if !cfg_status.success() {
            return Err(ApiError::internal(
                "failed to configure receive.denyDeletes on staging bare repository",
            ));
        }

        let response =
            handle_receive_pack_with_protocol(tmp.path(), &request_bytes, git_protocol.as_deref())?;

        // Acquire exclusive per-target write locks in deterministic sorted branch order BEFORE
        // checking pending verification / importing so concurrent pushes cannot race with in-flight
        // `publish_embargo`, `land`, or `post_land_cmd` auto-revert.
        let refs_after_pack = list_bare_branch_refs(tmp.path())?;
        let mut target_guards = Vec::new();
        for (branch, new_oid) in &refs_after_pack {
            if refs_before.get(branch) == Some(new_oid) {
                continue;
            }
            target_guards.push(repo.try_write_target(branch)?);
            let live_head = repo.store.get_bookmark(branch)?;
            if live_head != bookmarks.get(branch).copied() {
                return Err(ApiError::conflict(format!(
                    "bookmark '{branch}' changed concurrently during git push; retry"
                )));
            }
            if let Some(old_head) = live_head {
                if repo.is_head_pending_verification(old_head) {
                    return Err(ApiError::conflict(format!(
                        "bookmark '{branch}' is currently undergoing post-land verification; retry shortly"
                    )));
                }
                if let Ok(old_cs) = repo.store.get_changeset(old_head)
                    && repo.is_unlive_published_changeset(&old_cs)?
                {
                    return Err(ApiError::conflict(format!(
                        "bookmark '{branch}' points to an unverified or reverted embargo publication"
                    )));
                }
            }
        }

        // Import updated refs with full two-pass path-ACL routing, `.gitxacl` admin guard,
        // cross-secret shadow checks, and public secret scanning before mutating `gitx-store`.
        let prev_master = bookmarks.get("master").copied();
        let _imported = import_received_refs_with_policy(
            tmp.path(),
            repo.store.as_ref(),
            &target_domain,
            &bookmarks,
            &refs_before,
            &policy,
            Some(&principal),
            can_admin_acl,
        )?;
        if target_domain.is_public() && refs_before.get("master") != refs_after_pack.get("master") {
            let new_master = repo.store.get_bookmark("master")?;
            repo.reload_acl_if_master_acl_changed(prev_master, new_master)?;
        }
        drop(target_guards);
        Ok(response)
    })
    .await
    .map_err(|e| ApiError::internal(format!("git receive-pack task join error: {e}")))??;

    Ok(build_git_response(
        RECEIVE_PACK_RESULT_CONTENT_TYPE,
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
        let allowed_domains =
            readable_non_embargo_domains(repo.store.as_ref(), &policy, &principal);
        let bookmarks = repo.store.list_bookmarks()?;

        let tmp = TempDir::new().map_err(|e| ApiError::internal(e.to_string()))?;
        export_to_git_repo_filtered(
            repo.store.as_ref(),
            tmp.path(),
            &allowed_domains,
            &bookmarks,
            |cs| repo.can_read_changeset_live(&policy, &principal, cs),
        )?;

        let response =
            handle_upload_pack_with_protocol(tmp.path(), &request_bytes, git_protocol.as_deref())?;
        Ok(response)
    })
    .await
    .map_err(|e| ApiError::internal(format!("git upload-pack task join error: {e}")))??;

    Ok(build_git_response(UPLOAD_PACK_RESULT_CONTENT_TYPE, payload))
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
