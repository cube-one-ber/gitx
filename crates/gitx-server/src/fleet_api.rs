//! Live cross-machine encrypted Fleet Sync ("Dropbox for Devs") endpoints.
//!
//! Stores strictly end-to-end encrypted overlay bundles (`EncryptedFleetBundle`) scoped per
//! authenticated principal (`principal.id`). The server never sees plaintext `.env` files
//! or private workspace configs.

use crate::api::get_existing_repo;
use crate::auth::AuthenticatedPrincipal;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct FleetUploadRequest {
    /// Serialized `EncryptedFleetBundle` JSON (must be encrypted ciphertext; plaintext rejected).
    pub bundle_json: String,
    #[serde(default)]
    pub machine: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FleetQuery {
    #[serde(default)]
    pub machine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSyncRecord {
    pub owner: String,
    pub repo: String,
    pub principal_id: String,
    pub machine: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub bundle_json: String,
}

/// `POST /v1/repos/{owner}/{name}/fleet`
///
/// Uploads an end-to-end encrypted fleet overlay bundle for the authenticated user.
pub async fn upload_fleet_bundle(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<FleetUploadRequest>,
) -> ApiResult<Json<FleetSyncRecord>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers cannot upload fleet sync bundles",
        ));
    }

    // Verify bundle_json is valid JSON representing an EncryptedFleetBundle (never plaintext).
    let parsed: serde_json::Value = serde_json::from_str(&req.bundle_json)
        .map_err(|e| ApiError::bad_request(format!("invalid encrypted fleet bundle JSON: {e}")))?;
    if parsed.get("envelope").is_none() || parsed.get("files").is_some() {
        return Err(ApiError::bad_request(
            "fleet sync endpoint accepts only end-to-end EncryptedFleetBundle JSON (refusing plaintext overlay)",
        ));
    }

    let repo = state.get_or_create_repo(&owner, &name)?;
    let record = FleetSyncRecord {
        owner: owner.clone(),
        repo: name.clone(),
        principal_id: principal.id.clone(),
        machine: req.machine.clone(),
        updated_at: Utc::now(),
        bundle_json: req.bundle_json,
    };

    let target_path = fleet_record_path(&repo.root_dir, &principal.id, req.machine.as_deref());
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let payload =
        serde_json::to_vec_pretty(&record).map_err(|e| ApiError::internal(e.to_string()))?;
    fs::write(&target_path, &payload).map_err(|e| ApiError::internal(e.to_string()))?;

    // Also update the user's `latest` pointer so any machine can pull without naming a source machine.
    let latest_path = fleet_record_path(&repo.root_dir, &principal.id, None);
    if latest_path != target_path {
        fs::write(&latest_path, &payload).map_err(|e| ApiError::internal(e.to_string()))?;
    }

    Ok(Json(record))
}

/// `GET /v1/repos/{owner}/{name}/fleet`
///
/// Fetches the latest end-to-end encrypted fleet overlay bundle strictly for the authenticated user.
pub async fn download_fleet_bundle(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<FleetQuery>,
) -> ApiResult<Json<FleetSyncRecord>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers cannot download fleet sync bundles",
        ));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let path = fleet_record_path(&repo.root_dir, &principal.id, query.machine.as_deref());
    if !path.is_file() {
        return Err(ApiError::not_found(format!(
            "no fleet sync bundle found for principal '{}' on '{owner}/{name}'",
            principal.id
        )));
    }
    let bytes = fs::read(&path).map_err(|e| ApiError::internal(e.to_string()))?;
    let record: FleetSyncRecord =
        serde_json::from_slice(&bytes).map_err(|e| ApiError::internal(e.to_string()))?;
    if record.principal_id != principal.id {
        return Err(ApiError::not_found(format!(
            "no fleet sync bundle found for principal '{}' on '{owner}/{name}'",
            principal.id
        )));
    }
    Ok(Json(record))
}

fn fleet_record_path(repo_root: &std::path::Path, principal_id: &str, machine: Option<&str>) -> PathBuf {
    let user_key = gitx_core::ObjectHash::of_bytes(principal_id.as_bytes()).to_hex();
    let file_name = match machine.map(str::trim).filter(|m| !m.is_empty()) {
        Some(m) => {
            let machine_key = gitx_core::ObjectHash::of_bytes(m.as_bytes()).to_hex();
            format!("{user_key}__{machine_key}.json")
        }
        None => format!("{user_key}__latest.json"),
    };
    repo_root.join("fleet").join(file_name)
}
