use crate::backend::normalize_rel_path;
use crate::cow::{apply_workspace_permissions, detect_file_mode, write_symlink};
use chrono::{DateTime, Utc};
use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{ChangeId, DomainId, FileMode, GitxError, ObjectHash, Result, WorkspaceRef};
use gitx_crypto::{PublicKeyBundle, SecretEnvelope, UserKeyPair, decrypt_secret, encrypt_secret};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// OS-specific / build / VCS directories that are strictly excluded from Fleet Overlay bundles,
/// regardless of user-supplied `include_patterns`.
pub const FLEET_EXCLUDED_DIRS: &[&str] = &[".git", ".gitx", "target", "node_modules"];

/// Single overlay file entry carried inside a [`FleetOverlayBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayFile {
    pub path: String,
    pub mode: FileMode,
    pub content: Vec<u8>,
    pub content_hash: ObjectHash,
}

/// Active workspace metadata captured alongside overlay files for cross-machine handoff.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FleetWorkspaceMetadata {
    pub workspace_name: Option<String>,
    pub head_changeset: Option<ObjectHash>,
    pub head_change_id: Option<ChangeId>,
    pub backend: Option<WorkspaceBackendKind>,
    pub source_machine: Option<String>,
    pub extra: BTreeMap<String, String>,
}

impl FleetWorkspaceMetadata {
    pub fn from_workspace_ref(ws: &WorkspaceRef) -> Self {
        Self {
            workspace_name: Some(ws.name.clone()),
            head_changeset: Some(ws.head_changeset),
            head_change_id: Some(ws.head_change_id),
            backend: Some(ws.backend.clone()),
            source_machine: None,
            extra: BTreeMap::new(),
        }
    }
}

/// Cross-machine "Dropbox for Devs" overlay bundle capturing private/ignored local files
/// (such as `.env`, `.env.local`, editor/tool configs) and workspace metadata while strictly
/// excluding OS-specific directories (`node_modules/`, `target/`, `.git/`, `.gitx/`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetOverlayBundle {
    pub format_version: u32,
    pub created_at: DateTime<Utc>,
    pub workspace: FleetWorkspaceMetadata,
    pub files: BTreeMap<String, OverlayFile>,
}

impl FleetOverlayBundle {
    pub const CURRENT_FORMAT_VERSION: u32 = 1;

    pub fn with_workspace_ref(mut self, ws: &WorkspaceRef) -> Self {
        self.workspace.workspace_name = Some(ws.name.clone());
        self.workspace.head_changeset = Some(ws.head_changeset);
        self.workspace.head_change_id = Some(ws.head_change_id);
        self.workspace.backend = Some(ws.backend.clone());
        self
    }

    pub fn with_source_machine(mut self, machine: impl Into<String>) -> Self {
        self.workspace.source_machine = Some(machine.into());
        self
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| GitxError::Serialization(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| GitxError::Serialization(e.to_string()))
    }
}

/// Export private/ignored overlay files matching `include_patterns` from `root`, strictly
/// excluding OS-specific and VCS directories (`node_modules/`, `target/`, `.git/`, `.gitx/`).
pub fn export_overlay(root: &Path, include_patterns: &[&str]) -> Result<FleetOverlayBundle> {
    export_overlay_with_metadata(root, include_patterns, FleetWorkspaceMetadata::default())
}

/// Export overlay files with attached [`FleetWorkspaceMetadata`].
pub fn export_overlay_with_metadata(
    root: &Path,
    include_patterns: &[&str],
    workspace: FleetWorkspaceMetadata,
) -> Result<FleetOverlayBundle> {
    if !root.exists() {
        return Err(GitxError::NotFound(format!(
            "workspace root '{}' does not exist",
            root.display()
        )));
    }

    let matchers = compile_include_patterns(include_patterns)?;
    let mut files = BTreeMap::new();

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            !(entry.file_type().is_dir() && is_excluded_dir_name(&name))
        });

    for entry_res in walker {
        let entry = entry_res
            .map_err(|e| GitxError::Workspace(format!("walkdir error during overlay export: {e}")))?;
        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }

        let rel = entry.path().strip_prefix(root).map_err(|e| {
            GitxError::Workspace(format!("failed to strip root prefix during overlay export: {e}"))
        })?;
        let rel_str = normalize_rel_path(
            &rel.components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
        )?;

        if path_in_excluded_dir(&rel_str) {
            continue;
        }

        if !matches_any_pattern(&matchers, &rel_str) {
            continue;
        }

        let ft = entry.file_type();
        let (content, mode) = if ft.is_symlink() {
            let target = fs::read_link(entry.path())?;
            (
                target.to_string_lossy().into_owned().into_bytes(),
                FileMode::Symlink,
            )
        } else if ft.is_file() {
            (fs::read(entry.path())?, detect_file_mode(entry.path())?)
        } else {
            continue;
        };

        let content_hash = ObjectHash::of_typed("gitx:raw:v1", &content);
        files.insert(
            rel_str.clone(),
            OverlayFile {
                path: rel_str,
                mode,
                content,
                content_hash,
            },
        );
    }

    Ok(FleetOverlayBundle {
        format_version: FleetOverlayBundle::CURRENT_FORMAT_VERSION,
        created_at: Utc::now(),
        workspace,
        files,
    })
}

/// Apply a [`FleetOverlayBundle`] onto `root`, returning the sorted list of restored relative
/// file paths.
///
/// Validates path safety, strictly refuses excluded OS/build/VCS directories, and verifies
/// content hashes before writing files.
pub fn apply_overlay(root: &Path, bundle: &FleetOverlayBundle) -> Result<Vec<String>> {
    fs::create_dir_all(root)?;

    // Validate all entries before mutating the target directory.
    let mut validated = Vec::with_capacity(bundle.files.len());
    for (key, file) in &bundle.files {
        let norm_key = normalize_rel_path(key)?;
        let norm_path = normalize_rel_path(&file.path)?;
        if norm_key != norm_path {
            return Err(GitxError::Workspace(format!(
                "overlay bundle path mismatch: key '{norm_key}' != entry path '{norm_path}'"
            )));
        }
        if path_in_excluded_dir(&norm_path) {
            return Err(GitxError::Workspace(format!(
                "overlay bundle cannot restore excluded path '{norm_path}'"
            )));
        }
        let actual_hash = ObjectHash::of_typed("gitx:raw:v1", &file.content);
        if actual_hash != file.content_hash {
            return Err(GitxError::Workspace(format!(
                "overlay file '{norm_path}' content hash mismatch: expected {}, got {}",
                file.content_hash, actual_hash
            )));
        }
        validated.push((norm_path, file));
    }

    let mut restored = Vec::with_capacity(validated.len());
    for (rel_path, file) in validated {
        let dest = root.join(&rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::symlink_metadata(&dest).is_ok() {
            fs::remove_file(&dest)?;
        }
        if file.mode == FileMode::Symlink {
            write_symlink(&dest, &file.content)?;
        } else {
            fs::write(&dest, &file.content)?;
            apply_workspace_permissions(&dest, file.mode)?;
        }
        restored.push(rel_path);
    }

    restored.sort();
    Ok(restored)
}

/// End-to-end envelope-encrypted cross-machine Fleet Overlay bundle.
///
/// Wraps a serialized [`FleetOverlayBundle`] inside a [`SecretEnvelope`] encrypted via
/// `gitx-crypto` (ChaCha20-Poly1305 payload encryption + per-recipient X25519 ECDH /
/// HKDF-SHA256 DEK wrapping) so sensitive overlay files (`.env`, local tokens, editor configs)
/// never appear in plaintext in transit or at rest on untrusted relay/storage nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFleetBundle {
    pub envelope: SecretEnvelope,
    pub created_at: DateTime<Utc>,
    pub machine_id: String,
    pub file_count: usize,
}

impl EncryptedFleetBundle {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| GitxError::Serialization(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| GitxError::Serialization(e.to_string()))
    }
}

fn fleet_overlay_aad_path(machine_id: &str) -> String {
    format!("gitx:fleet-overlay:v1/{machine_id}")
}

/// Export private/ignored overlay files matching `include_patterns` from `root` and seal the
/// entire bundle inside an end-to-end encrypted [`EncryptedFleetBundle`] for `recipients`.
///
/// Strictly excludes OS/build/VCS directories (`node_modules/`, `target/`, `.git/`, `.gitx/`)
/// and binds `(domain, machine_id, key_epoch)` into the AEAD associated data.
pub fn export_encrypted_overlay(
    root: &Path,
    include_patterns: &[&str],
    machine_id: &str,
    domain: &DomainId,
    key_epoch: u64,
    recipients: &[PublicKeyBundle],
) -> Result<EncryptedFleetBundle> {
    let metadata = FleetWorkspaceMetadata {
        source_machine: Some(machine_id.to_string()),
        ..Default::default()
    };
    let bundle = export_overlay_with_metadata(root, include_patterns, metadata)?;
    let file_count = bundle.files.len();
    let created_at = bundle.created_at;

    let plaintext =
        serde_json::to_vec(&bundle).map_err(|e| GitxError::Serialization(e.to_string()))?;
    let aad_path = fleet_overlay_aad_path(machine_id);
    let envelope = encrypt_secret(domain, &aad_path, key_epoch, &plaintext, recipients)?;

    Ok(EncryptedFleetBundle {
        envelope,
        created_at,
        machine_id: machine_id.to_string(),
        file_count,
    })
}

/// Decrypt an [`EncryptedFleetBundle`] using an authorized machine/user `keypair` and restore
/// its overlay files onto `root`, returning the sorted list of restored relative file paths.
///
/// Fails with [`GitxError::AccessDenied`] if `keypair` is not an authorized recipient, or
/// [`GitxError::Crypto`] if the ciphertext or authenticated header metadata was tampered with.
pub fn apply_encrypted_overlay(
    root: &Path,
    bundle: &EncryptedFleetBundle,
    keypair: &UserKeyPair,
) -> Result<Vec<String>> {
    let aad_path = fleet_overlay_aad_path(&bundle.machine_id);
    let plaintext = decrypt_secret(&bundle.envelope, &aad_path, keypair)?;

    let decoded: FleetOverlayBundle =
        serde_json::from_slice(&plaintext).map_err(|e| GitxError::Serialization(e.to_string()))?;

    if decoded.files.len() != bundle.file_count {
        return Err(GitxError::Crypto(format!(
            "encrypted fleet bundle file_count mismatch: header={}, payload={}",
            bundle.file_count,
            decoded.files.len()
        )));
    }

    apply_overlay(root, &decoded)
}

struct CompiledIncludePattern {
    full: GlobMatcher,
    basename: Option<GlobMatcher>,
}

fn compile_include_patterns(patterns: &[&str]) -> Result<Vec<CompiledIncludePattern>> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for raw in patterns {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (anchored, pat) = if let Some(rest) = trimmed.strip_prefix('/') {
            (true, rest)
        } else {
            (false, trimmed)
        };
        let has_slash = pat.contains('/');
        let full_pat = if anchored || has_slash {
            pat.to_string()
        } else {
            format!("**/{pat}")
        };
        let full = GlobBuilder::new(&full_pat)
            .literal_separator(true)
            .build()
            .map_err(|e| GitxError::Workspace(format!("invalid overlay pattern '{raw}': {e}")))?
            .compile_matcher();

        let basename = if !anchored && !has_slash {
            Some(
                GlobBuilder::new(pat)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| {
                        GitxError::Workspace(format!("invalid overlay pattern '{raw}': {e}"))
                    })?
                    .compile_matcher(),
            )
        } else {
            None
        };

        compiled.push(CompiledIncludePattern { full, basename });
    }
    Ok(compiled)
}

fn matches_any_pattern(patterns: &[CompiledIncludePattern], rel_path: &str) -> bool {
    let basename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    patterns.iter().any(|p| {
        p.full.is_match(rel_path) || p.basename.as_ref().is_some_and(|bm| bm.is_match(basename))
    })
}

fn is_excluded_dir_name(name: &str) -> bool {
    FLEET_EXCLUDED_DIRS.contains(&name)
}

fn path_in_excluded_dir(rel_path: &str) -> bool {
    rel_path.split('/').any(is_excluded_dir_name)
}
