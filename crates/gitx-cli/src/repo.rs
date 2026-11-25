use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use gitx_context::ContextStore;
use gitx_core::{
    Actor, ChangeId, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode,
    Identity, ObjectHash, OpId, OpKind, OpLogEntry, VisibilityPolicy, WorkspaceRef,
};
use gitx_crypto::{
    AclPolicy, PublicKeyBundle, SecretAuditLog, SecretEnvelope, SecretFinding, SecretKeyBundle,
    UserKeyPair, decrypt_secret, encrypt_secret, scan_content,
};
use gitx_git_bridge::{export_to_git_repo, import_from_git_repo};
use gitx_merge::{materialize_conflict, merge_domain_trees};
use gitx_store::{LocalStore, ObjectStore};
use gitx_vfs::{CowWorkspace, WorkspaceBackend, WorkspaceBackendKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

pub const DEFAULT_GITXACL: &str = "\
# GitX Visibility Domain ACL Policy
# Secrets stay in secret:dev and are never exported to public Git projections.
.env -> secret:dev
.env.* -> secret:dev
*.pem -> secret:dev
*.key -> secret:dev
secrets/** -> secret:dev
";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfig {
    pub author: Identity,
    pub default_branch: String,
    pub active_workspace: String,
    #[serde(default)]
    pub colocated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePointer {
    pub gitx_dir: PathBuf,
    pub workspace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringFile {
    pub local: SecretKeyBundle,
    pub recipients: BTreeMap<String, PublicKeyBundle>,
}

pub struct InitSummary {
    pub root: PathBuf,
    pub master_hash: ObjectHash,
    pub working_changeset: ChangeSet,
    pub key_fingerprint: String,
    pub imported_commits: Option<usize>,
}

pub struct SnapshotOutcome {
    pub changeset: ChangeSet,
    pub warnings: Vec<SecretFinding>,
    #[allow(dead_code)]
    pub changed: bool,
}

pub struct Repo {
    pub root: PathBuf,
    pub gitx_dir: PathBuf,
    pub store: Arc<LocalStore>,
    pub context: ContextStore,
    pub config: RepoConfig,
}

type SecretDomainEntries = BTreeMap<String, (Vec<u8>, FileMode)>;
type PartitionedWorkspaceScan = (
    BTreeMap<DomainId, DomainTree>,
    BTreeMap<DomainId, SecretDomainEntries>,
);

impl Repo {
    pub fn init(
        root: &Path,
        colocate: bool,
        author_name: Option<String>,
        author_email: Option<String>,
    ) -> Result<InitSummary> {
        fs::create_dir_all(root)
            .with_context(|| format!("failed to create repository directory {}", root.display()))?;
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let gitx_dir = root.join(".gitx");
        if gitx_dir.exists() {
            bail!(
                "gitx repository already initialized at {}",
                gitx_dir.display()
            );
        }

        let store_dir = gitx_dir.join("store");
        let pool_dir = gitx_dir.join("pool");
        let keys_dir = gitx_dir.join("keys");
        fs::create_dir_all(&store_dir)?;
        fs::create_dir_all(&pool_dir)?;
        fs::create_dir_all(&keys_dir)?;

        let name = author_name
            .or_else(|| std::env::var("GITX_AUTHOR_NAME").ok())
            .or_else(|| std::env::var("USER").ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "GitX Developer".to_string());
        let email = author_email
            .or_else(|| std::env::var("GITX_AUTHOR_EMAIL").ok())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("{}@gitx.local", name.to_lowercase().replace(' ', ".")));

        let keypair = UserKeyPair::generate_with_label(&name);
        let key_fingerprint = keypair.fingerprint();
        let mut recipients = BTreeMap::new();
        recipients.insert("local".to_string(), keypair.public_bundle());

        let keyring = KeyringFile {
            local: keypair.to_secret_bundle(),
            recipients,
        };
        save_secret_json_file(&keys_dir.join("local.json"), &keyring)?;

        let author = Identity {
            name,
            email,
            key_fingerprint: Some(key_fingerprint.clone()),
        };

        let is_colocated = colocate && root.join(".git").exists();
        let config = RepoConfig {
            author: author.clone(),
            default_branch: "master".to_string(),
            active_workspace: "default".to_string(),
            colocated: is_colocated,
        };
        save_json_file(&gitx_dir.join("config.json"), &config)?;

        let acl_path = root.join(".gitxacl");
        if !acl_path.exists() {
            fs::write(&acl_path, DEFAULT_GITXACL)?;
        }

        let store = Arc::new(LocalStore::open(&store_dir)?);
        let context = ContextStore::open(gitx_dir.join("context.db"))?;

        let repo = Self {
            root: root.clone(),
            gitx_dir: gitx_dir.clone(),
            store,
            context,
            config,
        };

        let mut imported_commits = None;
        let master_cs = if colocate && root.join(".git").exists() {
            let report = import_from_git_repo(&root, repo.store.as_ref(), DomainId::public())?;
            imported_commits = Some(report.imported_commits);
            if let Some(imported_head) = report.head_changeset {
                repo.store.set_bookmark("master", imported_head)?;
                repo.store.get_changeset(imported_head)?
            } else {
                repo.create_initial_root_changeset(&author)?
            }
        } else {
            repo.create_initial_root_changeset(&author)?
        };

        // Create initial working-copy ChangeSet (`@`) on top of `master`.
        let working_cs = ChangeSetBuilder::new(author)
            .parents(vec![master_cs.id])
            .public_parents(vec![master_cs.public_projection_hash])
            .domain_trees(master_cs.domain_trees.clone())
            .visibility(VisibilityPolicy::public())
            .description("")
            .build();
        repo.store.put_changeset(&working_cs)?;

        let ws_ref = WorkspaceRef {
            name: "default".to_string(),
            root_path: Some(root.to_string_lossy().into_owned()),
            backend: WorkspaceBackendKind::CopyOnWrite,
            head_changeset: working_cs.id,
            head_change_id: working_cs.change_id,
        };
        repo.store.put_workspace(&ws_ref)?;

        repo.append_op(OpKind::Init, "Initialize gitx repository")?;

        Ok(InitSummary {
            root,
            master_hash: master_cs.id,
            working_changeset: working_cs,
            key_fingerprint,
            imported_commits,
        })
    }

    fn create_initial_root_changeset(&self, author: &Identity) -> Result<ChangeSet> {
        let acl = self.load_acl()?;
        let cow = self.open_cow_workspace()?;
        let (scanned, raw_secrets) = self.scan_workspace_partitioned(&cow, &acl)?;
        let keyring = self.load_keyring()?;
        let keypair = UserKeyPair::from_secret_bundle(&keyring.local)?;
        let recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();

        let mut domain_trees = BTreeMap::new();
        for (domain, tree) in scanned {
            let hash = self.store.put_tree(&tree)?;
            domain_trees.insert(domain, hash);
        }
        for (domain, entries) in raw_secrets {
            let tree =
                self.encrypt_secret_domain_entries(&domain, &entries, None, &keypair, &recipients)?;
            let hash = self.store.put_tree(&tree)?;
            domain_trees.insert(domain, hash);
        }
        if let std::collections::btree_map::Entry::Vacant(e) =
            domain_trees.entry(DomainId::public())
        {
            let empty = DomainTree::new(DomainId::public());
            let hash = self.store.put_tree(&empty)?;
            e.insert(hash);
        }

        let root_cs = ChangeSetBuilder::new(author.clone())
            .domain_trees(domain_trees)
            .visibility(VisibilityPolicy::public())
            .description("Initial commit")
            .build();
        self.store.put_changeset(&root_cs)?;
        self.store.set_bookmark("master", root_cs.id)?;
        Ok(root_cs)
    }

    pub fn open(start_dir: &Path) -> Result<Self> {
        let mut cur = fs::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
        loop {
            let candidate = cur.join(".gitx");
            if candidate.is_dir() && candidate.join("config.json").is_file() {
                let config: RepoConfig = load_json_file(&candidate.join("config.json"))?;
                let store = Arc::new(LocalStore::open(candidate.join("store"))?);
                let context = ContextStore::open(candidate.join("context.db"))?;
                return Ok(Self {
                    root: cur,
                    gitx_dir: candidate,
                    store,
                    context,
                    config,
                });
            }
            if candidate.is_dir() && candidate.join("workspace.json").is_file() {
                let pointer: WorkspacePointer = load_json_file(&candidate.join("workspace.json"))?;
                let mut config: RepoConfig = load_json_file(&pointer.gitx_dir.join("config.json"))?;
                config.active_workspace = pointer.workspace;
                let store = Arc::new(LocalStore::open(pointer.gitx_dir.join("store"))?);
                let context = ContextStore::open(pointer.gitx_dir.join("context.db"))?;
                return Ok(Self {
                    root: cur,
                    gitx_dir: pointer.gitx_dir,
                    store,
                    context,
                    config,
                });
            }
            if !cur.pop() {
                bail!(
                    "not inside a gitx repository (no .gitx directory found from {})",
                    start_dir.display()
                );
            }
        }
    }

    /// Locate a repository root and its [`RepoConfig`] without opening `LocalStore` or
    /// `ContextStore` (avoiding exclusive database locks when handing off to `AgentRepo`).
    pub fn discover_config(start_dir: &Path) -> Option<(PathBuf, RepoConfig)> {
        let mut cur = fs::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
        loop {
            let candidate = cur.join(".gitx");
            if candidate.is_dir()
                && candidate.join("config.json").is_file()
                && let Ok(config) = load_json_file::<RepoConfig>(&candidate.join("config.json"))
            {
                return Some((cur, config));
            }
            if candidate.is_dir()
                && candidate.join("workspace.json").is_file()
                && let Ok(pointer) =
                    load_json_file::<WorkspacePointer>(&candidate.join("workspace.json"))
                && let Ok(mut config) =
                    load_json_file::<RepoConfig>(&pointer.gitx_dir.join("config.json"))
            {
                config.active_workspace = pointer.workspace;
                let primary_root = pointer
                    .gitx_dir
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or(cur);
                return Some((primary_root, config));
            }
            if !cur.pop() {
                return None;
            }
        }
    }

    pub fn pool_dir(&self) -> PathBuf {
        self.gitx_dir.join("pool")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.gitx_dir.join("keys")
    }

    pub fn open_cow_workspace(&self) -> Result<CowWorkspace> {
        Ok(CowWorkspace::open(&self.root, self.pool_dir())?)
    }

    pub fn load_acl(&self) -> Result<AclPolicy> {
        let acl_path = self.root.join(".gitxacl");
        if acl_path.is_file() {
            let text = fs::read_to_string(&acl_path)?;
            return Ok(AclPolicy::parse(&text)?);
        }
        if let Some(primary_root) = self.gitx_dir.parent() {
            let primary_acl = primary_root.join(".gitxacl");
            if primary_acl.is_file() {
                let text = fs::read_to_string(&primary_acl)?;
                return Ok(AclPolicy::parse(&text)?);
            }
        }
        Ok(AclPolicy::default_secure())
    }

    pub fn load_keyring(&self) -> Result<KeyringFile> {
        load_json_file(&self.keys_dir().join("local.json"))
    }

    pub fn save_keyring(&self, keyring: &KeyringFile) -> Result<()> {
        save_secret_json_file(&self.keys_dir().join("local.json"), keyring)
    }

    pub fn load_local_keypair(&self) -> Result<UserKeyPair> {
        let keyring = self.load_keyring()?;
        Ok(UserKeyPair::from_secret_bundle(&keyring.local)?)
    }

    pub fn load_audit_log(&self) -> Result<SecretAuditLog> {
        let path = self.keys_dir().join("audit.json");
        if path.is_file() {
            load_json_file(&path)
        } else {
            Ok(SecretAuditLog::new())
        }
    }

    pub fn save_audit_log(&self, log: &SecretAuditLog) -> Result<()> {
        save_json_file(&self.keys_dir().join("audit.json"), log)
    }

    pub fn active_workspace_ref(&self) -> Result<WorkspaceRef> {
        self.store
            .get_workspace(&self.config.active_workspace)?
            .ok_or_else(|| {
                anyhow!(
                    "active workspace '{}' not found",
                    self.config.active_workspace
                )
            })
    }

    pub fn current_changeset(&self) -> Result<ChangeSet> {
        let ws = self.active_workspace_ref()?;
        Ok(self.store.get_changeset(ws.head_changeset)?)
    }

    pub fn update_active_workspace_head(&self, cs: &ChangeSet) -> Result<WorkspaceRef> {
        let mut ws = self.active_workspace_ref()?;
        ws.head_changeset = cs.id;
        ws.head_change_id = cs.change_id;
        self.store.put_workspace(&ws)?;
        Ok(ws)
    }

    pub fn put_envelope(&self, env: &SecretEnvelope) -> Result<ObjectHash> {
        let hash = env.hash();
        let bytes = serde_json::to_vec(env)?;
        self.store.put_raw_object(hash, &bytes)?;
        Ok(hash)
    }

    pub fn get_envelope(&self, hash: ObjectHash) -> Result<SecretEnvelope> {
        let bytes = self.store.get_raw_object(hash)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Snapshot the local working copy into the active workspace's `@` ChangeSet.
    ///
    /// - Partitions files using `AclPolicy::domain_for_path`.
    /// - Scans `public` files with `scan_content`, returning any secret findings as warnings.
    /// - Envelope-encrypts any files routed to `secret:*` domains (preserving existing unchanged
    ///   envelopes so clean status checks never churn revisions).
    /// - Preserves unresolved `EntryKind::Conflict` entries if the materialized conflict file on
    ///   disk has not been edited by the user.
    /// - When changes are detected, creates a new immutable revision keeping the same `ChangeId`,
    ///   setting `previous_revision`, updating the workspace ref, and recording an OpLog entry.
    pub fn snapshot_working_copy(&self) -> Result<SnapshotOutcome> {
        let current = self.current_changeset()?;
        let acl = self.load_acl()?;
        let cow = self.open_cow_workspace()?;
        let (scanned, raw_secrets) = self.scan_workspace_partitioned(&cow, &acl)?;

        let keyring = self.load_keyring()?;
        let keypair = UserKeyPair::from_secret_bundle(&keyring.local)?;
        let recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();

        let mut warnings = Vec::new();
        let mut new_domain_trees = BTreeMap::new();

        // Collect all domains present in either scanned files or existing ChangeSet.
        let mut all_domains: BTreeSet<DomainId> = BTreeSet::new();
        all_domains.extend(scanned.keys().cloned());
        all_domains.extend(raw_secrets.keys().cloned());
        all_domains.extend(current.domain_trees.keys().cloned());
        all_domains.insert(DomainId::public());

        let is_active_embargo = matches!(
            current.visibility.embargo,
            Some(gitx_core::EmbargoState::Active { .. })
        );

        for domain in all_domains {
            let existing_tree = match current.domain_trees.get(&domain) {
                Some(&h) => Some(self.store.get_tree(h)?),
                None => None,
            };

            if domain.is_secret() {
                let merged_secret_tree = match raw_secrets.get(&domain) {
                    Some(entries) => self.encrypt_secret_domain_entries(
                        &domain,
                        entries,
                        existing_tree.as_ref(),
                        &keypair,
                        &recipients,
                    )?,
                    None => {
                        // Preserve encrypted secrets that are not materialized on disk.
                        existing_tree.unwrap_or_else(|| DomainTree::new(domain.clone()))
                    }
                };
                if !merged_secret_tree.entries.is_empty() {
                    let h = self.store.put_tree(&merged_secret_tree)?;
                    new_domain_trees.insert(domain, h);
                }
                continue;
            }

            // If we are on an active embargoed ChangeSet, route working public files into the
            // embargo domain rather than leaking them into `public`.
            if is_active_embargo && domain == current.visibility.primary_domain {
                let mut embargo_tree = scanned
                    .get(&DomainId::public())
                    .cloned()
                    .unwrap_or_else(|| DomainTree::new(domain.clone()));
                embargo_tree.domain = domain.clone();
                if let Some(ref existing) = existing_tree {
                    self.preserve_unchanged_conflicts(&mut embargo_tree, existing)?;
                }
                let h = self.store.put_tree(&embargo_tree)?;
                new_domain_trees.insert(domain, h);
                continue;
            }
            if is_active_embargo && domain.is_public() {
                if let Some(&h) = current.domain_trees.get(&domain) {
                    new_domain_trees.insert(domain, h);
                }
                continue;
            }

            let mut tree = scanned
                .get(&domain)
                .cloned()
                .unwrap_or_else(|| DomainTree::new(domain.clone()));

            // Scan public files for accidentally committed secrets.
            if domain.is_public() {
                for (path, kind) in &tree.entries {
                    if let EntryKind::File { blob_hash, .. } = kind {
                        let bytes = self.store.read_blob_bytes(*blob_hash)?;
                        warnings.extend(scan_content(path, &bytes));
                    }
                }
            }

            if let Some(ref existing) = existing_tree {
                self.preserve_unchanged_conflicts(&mut tree, existing)?;
            }

            if domain.is_public() || !tree.entries.is_empty() {
                let h = self.store.put_tree(&tree)?;
                new_domain_trees.insert(domain, h);
            }
        }

        if new_domain_trees == current.domain_trees {
            return Ok(SnapshotOutcome {
                changeset: current,
                warnings,
                changed: false,
            });
        }

        let has_conflicts = self.trees_have_conflicts(&new_domain_trees)?;
        let updated = ChangeSetBuilder::new(current.author.clone())
            .change_id(current.change_id)
            .previous_revision(Some(current.id))
            .parents(current.parents.clone())
            .public_parents(current.public_parents.clone())
            .domain_trees(new_domain_trees)
            .committer(current.committer.clone())
            .visibility(current.visibility.clone())
            .has_conflicts(has_conflicts)
            .description(current.description.clone())
            .build();

        self.store.put_changeset(&updated)?;
        self.update_active_workspace_head(&updated)?;
        self.append_op(
            OpKind::Snapshot {
                workspace: self.config.active_workspace.clone(),
            },
            format!(
                "Snapshot working copy ({} -> {})",
                current.id.short(),
                updated.id.short()
            ),
        )?;

        Ok(SnapshotOutcome {
            changeset: updated,
            warnings,
            changed: true,
        })
    }

    /// Scan working-copy files and partition them across domains WITHOUT ever writing
    /// `secret:*` plaintext bytes into the content-addressed object store.
    fn scan_workspace_partitioned(
        &self,
        cow: &CowWorkspace,
        acl: &AclPolicy,
    ) -> Result<PartitionedWorkspaceScan> {
        let files = cow.scan_files()?;
        let mut plain_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
        let mut secret_entries: BTreeMap<DomainId, SecretDomainEntries> = BTreeMap::new();

        for (rel_path, data, mode) in files {
            let domain = acl.domain_for_path(&rel_path);
            if domain.is_secret() {
                secret_entries
                    .entry(domain)
                    .or_default()
                    .insert(rel_path, (data, mode));
            } else {
                let blob = self.store.put_blob_bytes(&data)?;
                let tree = plain_trees
                    .entry(domain.clone())
                    .or_insert_with(|| DomainTree::new(domain));
                tree.insert(
                    rel_path,
                    EntryKind::File {
                        blob_hash: blob.manifest_hash(),
                        mode,
                        size: blob.total_size,
                    },
                );
            }
        }

        Ok((plain_trees, secret_entries))
    }

    fn encrypt_secret_domain_entries(
        &self,
        domain: &DomainId,
        scanned: &SecretDomainEntries,
        existing: Option<&DomainTree>,
        keypair: &UserKeyPair,
        recipients: &[PublicKeyBundle],
    ) -> Result<DomainTree> {
        let mut out = DomainTree::new(domain.clone());

        // Start by preserving existing encrypted secrets not present on disk.
        if let Some(existing_tree) = existing {
            for (path, kind) in &existing_tree.entries {
                if !scanned.contains_key(path) && matches!(kind, EntryKind::EncryptedSecret { .. })
                {
                    out.insert(path.clone(), kind.clone());
                }
            }
        }

        for (path, (plaintext, mode)) in scanned {
            // Reuse existing encrypted entry if decrypted plaintext matches disk bytes.
            if let Some(existing_tree) = existing
                && let Some(
                    existing_entry @ EntryKind::EncryptedSecret {
                        envelope_hash,
                        mode: existing_mode,
                        ..
                    },
                ) = existing_tree.entries.get(path)
                && existing_mode == mode
                && let Ok(env) = self.get_envelope(*envelope_hash)
                && let Ok(dec) = decrypt_secret(&env, path, keypair)
                && dec == *plaintext
            {
                out.insert(path.clone(), existing_entry.clone());
                continue;
            }

            let next_epoch = existing
                .and_then(|t| t.entries.get(path))
                .and_then(|k| match k {
                    EntryKind::EncryptedSecret { key_epoch, .. } => Some(*key_epoch),
                    _ => None,
                })
                .unwrap_or(1);

            let env = encrypt_secret(domain, path, next_epoch, plaintext, recipients)?;
            let env_hash = self.put_envelope(&env)?;
            out.insert(
                path.clone(),
                EntryKind::EncryptedSecret {
                    envelope_hash: env_hash,
                    key_epoch: next_epoch,
                    mode: *mode,
                },
            );
        }

        Ok(out)
    }

    fn preserve_unchanged_conflicts(
        &self,
        scanned: &mut DomainTree,
        existing: &DomainTree,
    ) -> Result<()> {
        for (path, existing_kind) in &existing.entries {
            let EntryKind::Conflict { term, mode } = existing_kind else {
                continue;
            };
            let Some(EntryKind::File { blob_hash, .. }) = scanned.entries.get(path) else {
                continue;
            };
            let disk_bytes = self.store.read_blob_bytes(*blob_hash)?;
            let materialized = materialize_conflict(term, path, |h| self.store.read_blob_bytes(h))?;
            if disk_bytes == materialized {
                scanned.insert(
                    path.clone(),
                    EntryKind::Conflict {
                        term: term.clone(),
                        mode: *mode,
                    },
                );
            }
        }
        Ok(())
    }

    pub fn trees_have_conflicts(&self, trees: &BTreeMap<DomainId, ObjectHash>) -> Result<bool> {
        for &tree_hash in trees.values() {
            let tree = self.store.get_tree(tree_hash)?;
            if tree.has_conflicts() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Materialize a `ChangeSet`'s non-secret domain trees onto the local working copy,
    /// removing stale non-secret files that are no longer present in `target`.
    pub fn materialize_changeset(&self, target: &ChangeSet) -> Result<()> {
        let mut combined = DomainTree::new(DomainId::public());
        let mut secret_paths = BTreeSet::new();

        for (domain, &tree_hash) in &target.domain_trees {
            let tree = self.store.get_tree(tree_hash)?;
            for (path, kind) in tree.entries {
                if domain.is_secret() || matches!(kind, EntryKind::EncryptedSecret { .. }) {
                    secret_paths.insert(path);
                } else {
                    combined.insert(path, kind);
                }
            }
        }

        self.materialize_domain_tree(&combined, &secret_paths)
    }

    /// Materialize a single `DomainTree` onto the working copy, preserving any paths in
    /// `preserve_paths` (such as local secret files).
    pub fn materialize_domain_tree(
        &self,
        target_tree: &DomainTree,
        preserve_paths: &BTreeSet<String>,
    ) -> Result<()> {
        let mut cow = self.open_cow_workspace()?;
        let existing_files = cow.list_files()?;
        let acl = self.load_acl()?;

        for rel_path in existing_files {
            if target_tree.entries.contains_key(&rel_path) {
                continue;
            }
            if preserve_paths.contains(&rel_path) || acl.domain_for_path(&rel_path).is_secret() {
                continue;
            }
            let _ = cow.remove_file(&rel_path);
        }

        cow.materialize_tree(target_tree, self.store.as_ref())?;
        Ok(())
    }

    pub fn append_op(&self, kind: OpKind, summary: impl Into<String>) -> Result<OpLogEntry> {
        let parent = self.store.latest_op()?.map(|o| o.id);
        let bookmarks = self.store.list_bookmarks()?;
        let workspaces = self.store.list_workspaces()?;
        let change_heads = self.collect_change_heads()?;

        let entry = OpLogEntry {
            id: OpId::new(),
            parent,
            timestamp: Utc::now(),
            kind,
            summary: summary.into(),
            bookmarks,
            workspaces,
            change_heads,
        };
        self.store.append_op(&entry)?;
        self.sync_colocated_git_if_enabled();
        Ok(entry)
    }

    /// When initialized with `--colocate`, continuously keep the colocated `.git` directory
    /// synchronized with the `public` domain projection of GitX bookmarks (never exporting
    /// private domains, encrypted `.env` secrets, or active embargoes).
    pub fn sync_colocated_git_if_enabled(&self) {
        if !self.config.colocated {
            return;
        }
        let git_dir = self.root.join(".git");
        if !git_dir.is_dir() {
            return;
        }
        let Ok(bookmarks) = self.store.list_bookmarks() else {
            return;
        };
        if bookmarks.is_empty() {
            return;
        }
        let _ = export_to_git_repo(
            self.store.as_ref(),
            &git_dir,
            &[DomainId::public()],
            &bookmarks,
        );
    }

    fn collect_change_heads(&self) -> Result<BTreeMap<ChangeId, ObjectHash>> {
        let mut heads = BTreeMap::new();
        for cs in self.store.list_changesets()? {
            heads.insert(cs.change_id, cs.id);
        }
        Ok(heads)
    }

    /// Resolve a bookmark name, `@`, full/prefix revision `ObjectHash`, or `ChangeId` prefix.
    pub fn resolve_changeset(&self, spec: &str) -> Result<ChangeSet> {
        let spec = spec.trim();
        if spec == "@" {
            return self.current_changeset();
        }
        if let Some(hash) = self.store.get_bookmark(spec)? {
            return Ok(self.store.get_changeset(hash)?);
        }
        if let Ok(full_hash) = ObjectHash::from_str(spec) {
            return Ok(self.store.get_changeset(full_hash)?);
        }

        let lower = spec.to_lowercase();
        let all = self.store.list_changesets()?;
        let mut matched: Option<ChangeSet> = None;
        for cs in all {
            let hex = cs.id.to_hex();
            let cid = cs.change_id.to_string();
            let cid_short = cs.change_id.short();
            if hex.starts_with(&lower) || cid.starts_with(&lower) || cid_short == lower {
                matched = Some(cs);
            }
        }
        matched.ok_or_else(|| anyhow!("could not resolve changeset '{spec}'"))
    }

    pub fn get_domain_tree_or_empty(
        &self,
        cs: Option<&ChangeSet>,
        domain: &DomainId,
    ) -> Result<DomainTree> {
        match cs.and_then(|c| c.domain_trees.get(domain)) {
            Some(&hash) => Ok(self.store.get_tree(hash)?),
            None => Ok(DomainTree::new(domain.clone())),
        }
    }

    /// Check whether `ancestor` is reachable from `descendant` via parent links.
    pub fn is_ancestor(&self, ancestor: ObjectHash, descendant: ObjectHash) -> Result<bool> {
        if ancestor == descendant {
            return Ok(true);
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(descendant);
        visited.insert(descendant);

        while let Some(cur) = queue.pop_front() {
            let Ok(cs) = self.store.get_changeset(cur) else {
                continue;
            };
            for &p in &cs.parents {
                if p == ancestor {
                    return Ok(true);
                }
                if visited.insert(p) {
                    queue.push_back(p);
                }
            }
        }
        Ok(false)
    }

    /// Find the nearest common ancestor of two ChangeSets in the parent DAG.
    pub fn find_common_ancestor(&self, a: ObjectHash, b: ObjectHash) -> Result<Option<ObjectHash>> {
        let mut ancestors_a = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(a);
        ancestors_a.insert(a);
        while let Some(cur) = q.pop_front() {
            if let Ok(cs) = self.store.get_changeset(cur) {
                for &p in &cs.parents {
                    if ancestors_a.insert(p) {
                        q.push_back(p);
                    }
                }
            }
        }

        let mut visited_b = HashSet::new();
        let mut qb = VecDeque::new();
        qb.push_back(b);
        visited_b.insert(b);
        while let Some(cur) = qb.pop_front() {
            if ancestors_a.contains(&cur) {
                return Ok(Some(cur));
            }
            if let Ok(cs) = self.store.get_changeset(cur) {
                for &p in &cs.parents {
                    if visited_b.insert(p) {
                        qb.push_back(p);
                    }
                }
            }
        }
        Ok(None)
    }

    /// 3-way merge all domain trees across `base`, `ours`, and `theirs`.
    /// Returns `(merged_domain_trees, all_conflict_paths)`.
    pub fn merge_changeset_trees(
        &self,
        base: Option<&ChangeSet>,
        ours: &ChangeSet,
        theirs: &ChangeSet,
    ) -> Result<(BTreeMap<DomainId, ObjectHash>, Vec<String>)> {
        let mut domains = BTreeSet::new();
        if let Some(b) = base {
            domains.extend(b.domain_trees.keys().cloned());
        }
        domains.extend(ours.domain_trees.keys().cloned());
        domains.extend(theirs.domain_trees.keys().cloned());
        domains.insert(DomainId::public());

        let mut merged_trees = BTreeMap::new();
        let mut conflicts = Vec::new();

        for domain in domains {
            let base_tree = self.get_domain_tree_or_empty(base, &domain)?;
            let ours_tree = self.get_domain_tree_or_empty(Some(ours), &domain)?;
            let theirs_tree = self.get_domain_tree_or_empty(Some(theirs), &domain)?;

            let result = merge_domain_trees(
                &base_tree,
                &ours_tree,
                &theirs_tree,
                |h| self.store.read_blob_bytes(h),
                |bytes| {
                    let blob = self.store.put_blob_bytes(bytes)?;
                    Ok((blob.manifest_hash(), blob.total_size))
                },
            )?;

            conflicts.extend(result.conflict_paths);
            if domain.is_public() || !result.tree.entries.is_empty() {
                let hash = self.store.put_tree(&result.tree)?;
                merged_trees.insert(domain, hash);
            }
        }

        Ok((merged_trees, conflicts))
    }

    /// Collect the chain of `ChangeId`s from `head` back to (but not including) `stop_at`.
    pub fn collect_change_ids_since(
        &self,
        head: ObjectHash,
        stop_at: Option<ObjectHash>,
    ) -> Result<Vec<ChangeId>> {
        let mut visited = HashSet::new();
        let mut stack = vec![head];
        let mut out = Vec::new();

        while let Some(cur) = stack.pop() {
            if Some(cur) == stop_at || !visited.insert(cur) {
                continue;
            }
            let cs = self.store.get_changeset(cur)?;
            if let Some(stop) = stop_at
                && self.is_ancestor(cur, stop)?
            {
                continue;
            }
            out.push(cs.change_id);
            if let Some(&first_parent) = cs.parents.first() {
                stack.push(first_parent);
            }
        }

        out.reverse();
        Ok(out)
    }
}

pub fn save_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}

/// Write a sensitive JSON file (such as private key material) with owner-only (`0o600`)
/// permissions on Unix so keys are never created world-readable.
pub fn save_secret_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn parse_agent_spec(spec: &str, initiated_by: Identity) -> Actor {
    let (harness, model) = match spec.split_once(':') {
        Some((h, m)) if !h.is_empty() && !m.is_empty() => (h.to_string(), m.to_string()),
        _ => (spec.to_string(), "default".to_string()),
    };
    Actor::Agent {
        harness,
        model,
        session_id: ulid::Ulid::new().to_string().to_lowercase(),
        initiated_by,
    }
}
