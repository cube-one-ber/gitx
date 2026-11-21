use gitx_context::ContextStore;
use gitx_core::{DomainId, EntryKind, GitxError, Result};
use gitx_crypto::AclPolicy;
use gitx_store::{LocalStore, ObjectStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Configuration for the GitX HTTP + Git Smart HTTP server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub default_acl: Option<String>,
}

impl ServerConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            default_acl: None,
        }
    }

    pub fn with_default_acl(mut self, acl: impl Into<String>) -> Self {
        self.default_acl = Some(acl.into());
        self
    }
}

/// Summary metadata for a hosted repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub default_branch: String,
    pub bookmarks: BTreeMap<String, String>,
}

/// Handle to a single multi-domain GitX repository hosted on the server.
pub struct RepoHandle {
    pub owner: String,
    pub name: String,
    pub root_dir: PathBuf,
    pub store: Arc<LocalStore>,
    pub context: Arc<ContextStore>,
    pub acl: RwLock<AclPolicy>,
    default_acl: Option<String>,
}

impl RepoHandle {
    /// Open or initialize a repository handle at `root_dir`.
    pub fn open(
        owner: String,
        name: String,
        root_dir: PathBuf,
        default_acl: Option<String>,
    ) -> Result<Self> {
        fs::create_dir_all(&root_dir)?;
        let store = Arc::new(LocalStore::open(&root_dir)?);
        let context = Arc::new(ContextStore::open(root_dir.join("context.sqlite"))?);
        let policy = load_initial_acl(&root_dir, store.as_ref(), default_acl.as_deref())?;

        Ok(Self {
            owner,
            name,
            root_dir,
            store,
            context,
            acl: RwLock::new(policy),
            default_acl,
        })
    }

    /// Return a cloned snapshot of the current [`AclPolicy`].
    pub fn acl_snapshot(&self) -> Result<AclPolicy> {
        self.acl
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))
    }

    /// Parse and install a new `.gitxacl` policy both in memory and on disk.
    pub fn update_acl_from_text(&self, text: &str) -> Result<AclPolicy> {
        let parsed = AclPolicy::parse(text)?;
        fs::write(self.root_dir.join(".gitxacl"), text)?;
        let mut guard = self
            .acl
            .write()
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))?;
        *guard = parsed.clone();
        Ok(parsed)
    }

    /// Reload `.gitxacl` from the current `master` tree (if present), falling back to
    /// disk `.gitxacl`, `default_acl`, or `AclPolicy::default_secure()`.
    pub fn reload_acl_from_store(&self) -> Result<AclPolicy> {
        let policy = if let Some(text) = read_committed_acl(self.store.as_ref())? {
            fs::write(self.root_dir.join(".gitxacl"), &text)?;
            AclPolicy::parse(&text)?
        } else {
            load_initial_acl(
                &self.root_dir,
                self.store.as_ref(),
                self.default_acl.as_deref(),
            )?
        };
        let mut guard = self
            .acl
            .write()
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))?;
        *guard = policy.clone();
        Ok(policy)
    }

    /// Build serializable repository metadata.
    pub fn info(&self) -> Result<RepoInfo> {
        let bookmarks = self
            .store
            .list_bookmarks()?
            .into_iter()
            .map(|(k, v)| (k, v.to_hex()))
            .collect();
        Ok(RepoInfo {
            owner: self.owner.clone(),
            name: self.name.clone(),
            full_name: format!("{}/{}", self.owner, self.name),
            default_branch: "master".to_string(),
            bookmarks,
        })
    }
}

/// Shared multi-repository state for the GitX HTTP server.
pub struct AppState {
    pub config: ServerConfig,
    repos: RwLock<BTreeMap<(String, String), Arc<RepoHandle>>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            repos: RwLock::new(BTreeMap::new()),
        }
    }

    fn repos_base_dir(&self) -> PathBuf {
        self.config.data_dir.join("repos")
    }

    fn repo_dir(&self, owner: &str, name: &str) -> PathBuf {
        self.repos_base_dir().join(owner).join(name)
    }

    /// Push-to-create: returns an existing repository handle or automatically provisions
    /// `{data_dir}/repos/{owner}/{name}` on demand.
    pub fn get_or_create_repo(&self, owner: &str, name: &str) -> Result<Arc<RepoHandle>> {
        validate_repo_segment(owner, "owner")?;
        validate_repo_segment(name, "name")?;

        let key = (owner.to_string(), name.to_string());
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            if let Some(handle) = guard.get(&key) {
                return Ok(Arc::clone(handle));
            }
        }

        let mut guard = self
            .repos
            .write()
            .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
        if let Some(handle) = guard.get(&key) {
            return Ok(Arc::clone(handle));
        }

        let dir = self.repo_dir(owner, name);
        let handle = Arc::new(RepoHandle::open(
            owner.to_string(),
            name.to_string(),
            dir,
            self.config.default_acl.clone(),
        )?);
        guard.insert(key, Arc::clone(&handle));
        Ok(handle)
    }

    /// Return an existing repository handle without creating a new repo if absent.
    pub fn get_repo(&self, owner: &str, name: &str) -> Result<Option<Arc<RepoHandle>>> {
        validate_repo_segment(owner, "owner")?;
        validate_repo_segment(name, "name")?;

        let key = (owner.to_string(), name.to_string());
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            if let Some(handle) = guard.get(&key) {
                return Ok(Some(Arc::clone(handle)));
            }
        }

        let dir = self.repo_dir(owner, name);
        if !dir.join("metadata.sqlite").exists() {
            return Ok(None);
        }

        let mut guard = self
            .repos
            .write()
            .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
        if let Some(handle) = guard.get(&key) {
            return Ok(Some(Arc::clone(handle)));
        }

        let handle = Arc::new(RepoHandle::open(
            owner.to_string(),
            name.to_string(),
            dir,
            self.config.default_acl.clone(),
        )?);
        guard.insert(key, Arc::clone(&handle));
        Ok(Some(handle))
    }

    /// List hosted repositories, optionally filtered by `owner`.
    pub fn list_repos(&self, owner_filter: Option<&str>) -> Result<Vec<RepoInfo>> {
        if let Some(owner) = owner_filter {
            validate_repo_segment(owner, "owner")?;
        }

        let mut keys: Vec<(String, String)> = Vec::new();
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            for (owner, name) in guard.keys() {
                if owner_filter.is_none_or(|f| f == owner) {
                    keys.push((owner.clone(), name.clone()));
                }
            }
        }

        let base = self.repos_base_dir();
        if base.is_dir() {
            for owner_entry in fs::read_dir(&base)? {
                let owner_entry = owner_entry?;
                if !owner_entry.file_type()?.is_dir() {
                    continue;
                }
                let owner = owner_entry.file_name().to_string_lossy().to_string();
                if owner_filter.is_some_and(|f| f != owner) {
                    continue;
                }
                if validate_repo_segment(&owner, "owner").is_err() {
                    continue;
                }
                for repo_entry in fs::read_dir(owner_entry.path())? {
                    let repo_entry = repo_entry?;
                    if !repo_entry.file_type()?.is_dir() {
                        continue;
                    }
                    let name = repo_entry.file_name().to_string_lossy().to_string();
                    if validate_repo_segment(&name, "name").is_err() {
                        continue;
                    }
                    if repo_entry.path().join("metadata.sqlite").exists() {
                        let pair = (owner.clone(), name);
                        if !keys.contains(&pair) {
                            keys.push(pair);
                        }
                    }
                }
            }
        }

        keys.sort();
        keys.dedup();

        let mut out = Vec::with_capacity(keys.len());
        for (owner, name) in keys {
            if let Some(handle) = self.get_repo(&owner, &name)? {
                out.push(handle.info()?);
            }
        }
        Ok(out)
    }
}

pub fn validate_repo_segment(seg: &str, label: &str) -> Result<()> {
    if seg.is_empty()
        || seg == "."
        || seg == ".."
        || seg.len() > 128
        || !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(GitxError::InvalidDomain(format!(
            "invalid repository {label} '{seg}'"
        )));
    }
    Ok(())
}

fn load_initial_acl(
    root_dir: &Path,
    store: &dyn ObjectStore,
    default_acl: Option<&str>,
) -> Result<AclPolicy> {
    let disk_acl = root_dir.join(".gitxacl");
    if disk_acl.is_file() {
        let text = fs::read_to_string(&disk_acl)?;
        return AclPolicy::parse(&text);
    }

    if let Some(text) = read_committed_acl(store)? {
        return AclPolicy::parse(&text);
    }

    if let Some(default_text) = default_acl {
        return AclPolicy::parse(default_text);
    }

    Ok(AclPolicy::default_secure())
}

fn read_committed_acl(store: &dyn ObjectStore) -> Result<Option<String>> {
    let Some(head_hash) = store.get_bookmark("master")? else {
        return Ok(None);
    };
    let cs = store.get_changeset(head_hash)?;
    let Some(&pub_tree_hash) = cs.domain_trees.get(&DomainId::public()) else {
        return Ok(None);
    };
    let pub_tree = store.get_tree(pub_tree_hash)?;
    let Some(EntryKind::File { blob_hash, .. }) = pub_tree.entries.get(".gitxacl") else {
        return Ok(None);
    };
    let bytes = store.read_blob_bytes(*blob_hash)?;
    let text = String::from_utf8(bytes)
        .map_err(|e| GitxError::Crypto(format!(".gitxacl is not valid UTF-8: {e}")))?;
    Ok(Some(text))
}
