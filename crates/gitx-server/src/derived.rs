//! Scion-style server-side derived data engine, strictly partitioned by [`DomainId`].
//!
//! Provides three lazy, incrementally cached indices attached to each [`RepoHandle`]:
//! - [`TrigramIndex`]: per-`(tree_hash, domain)` trigram posting lists accelerating `/grep`.
//! - [`CommitGraphIndex`]: cached DAG parent/depth table for fast ancestry & `merge_base(a, b)`.
//! - [`PathHistoryIndex`]: per-`(path, domain)` touching-commit lists accelerating `/blame`.
//!
//! **Security invariant:** Every derived search and history index is keyed by [`DomainId`]
//! and validated against the underlying [`DomainTree`]'s domain. Callers may only query
//! domains authorized by their [`AclPolicy`] projection, guaranteeing private, secret, and
//! embargoed content can never leak through derived caches.

use gitx_core::{ChangeSet, DomainId, EntryKind, GitxError, ObjectHash, Result};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

/// Alias matching the architecture specification name for [`TrigramIndex`].
pub type TrigramSearchIndex = TrigramIndex;

/// Upper bound on cached trigram trees per repository to prevent unbounded memory growth.
const MAX_CACHED_TRIGRAM_TREES: usize = 1024;
/// Upper bound on cached path history entries per repository to prevent unbounded memory growth.
const MAX_CACHED_PATH_HISTORIES: usize = 4096;

// ---------------------------------------------------------------------------
// Derived Stats (HTTP + programmatic observability)
// ---------------------------------------------------------------------------

/// Aggregated cache statistics across all derived data indices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedStats {
    pub trigram_indexed_trees: usize,
    pub trigram_domains: Vec<String>,
    pub trigram_total_postings: usize,
    pub trigram_cache_hits: u64,
    pub trigram_cache_misses: u64,
    pub commit_graph_nodes: usize,
    pub commit_graph_cache_hits: u64,
    pub commit_graph_cache_misses: u64,
    pub path_history_entries: usize,
    pub path_history_cache_hits: u64,
    pub path_history_cache_misses: u64,
    #[serde(default)]
    pub symbol_indexed_trees: usize,
    #[serde(default)]
    pub symbol_total_symbols: usize,
    #[serde(default)]
    pub symbol_cache_hits: u64,
    #[serde(default)]
    pub symbol_cache_misses: u64,
}

// ---------------------------------------------------------------------------
// 1. TrigramIndex — strictly partitioned by (tree_hash, DomainId)
// ---------------------------------------------------------------------------

/// Cached trigram posting index for a single immutable `(tree_hash, domain)` pair.
#[derive(Debug)]
struct TreeTrigramEntry {
    /// Sorted list of all UTF-8 text file paths in this `(tree_hash, domain)`.
    text_paths: Vec<String>,
    /// All file entries (`path -> blob_hash`) in this `(tree_hash, domain)`.
    file_blobs: BTreeMap<String, ObjectHash>,
    /// ASCII-lowercased 3-byte trigram -> sorted, deduplicated file paths containing it.
    postings: HashMap<[u8; 3], Vec<String>>,
}

impl TreeTrigramEntry {
    fn build(store: &dyn ObjectStore, tree_hash: ObjectHash, domain: &DomainId) -> Result<Self> {
        let tree = store.get_tree(tree_hash)?;
        if &tree.domain != domain {
            return Err(GitxError::AccessDenied {
                domain: domain.to_string(),
                reason: format!(
                    "domain tree {tree_hash} belongs to '{}' rather than '{domain}'",
                    tree.domain
                ),
            });
        }

        let mut text_paths = Vec::new();
        let mut file_blobs = BTreeMap::new();
        let mut postings: HashMap<[u8; 3], Vec<String>> = HashMap::new();

        for (path, entry) in &tree.entries {
            if let EntryKind::File { blob_hash, .. } = entry {
                file_blobs.insert(path.clone(), *blob_hash);
                let bytes = store.read_blob_bytes(*blob_hash)?;
                if std::str::from_utf8(&bytes).is_ok() {
                    text_paths.push(path.clone());
                    for trigram in extract_unique_trigrams(&bytes) {
                        postings.entry(trigram).or_default().push(path.clone());
                    }
                }
            }
        }

        Ok(Self {
            text_paths,
            file_blobs,
            postings,
        })
    }

    fn candidate_files(&self, query: &str) -> Vec<(String, ObjectHash)> {
        let candidate_paths: Vec<String> = if query.len() >= 3 && query.is_ascii() {
            let trigrams = extract_unique_trigrams(query.as_bytes());
            if trigrams.is_empty() {
                self.text_paths.clone()
            } else {
                let mut lists: Vec<&[String]> = Vec::with_capacity(trigrams.len());
                for tri in trigrams {
                    let Some(list) = self.postings.get(&tri) else {
                        return Vec::new();
                    };
                    lists.push(list.as_slice());
                }
                lists.sort_by_key(|l| l.len());
                let mut current: Vec<String> = lists[0].to_vec();
                for next in &lists[1..] {
                    current = intersect_sorted(&current, next);
                    if current.is_empty() {
                        return Vec::new();
                    }
                }
                current
            }
        } else {
            self.text_paths.clone()
        };

        candidate_paths
            .into_iter()
            .filter_map(|p| self.file_blobs.get(&p).copied().map(|h| (p, h)))
            .collect()
    }
}

/// Domain-partitioned trigram search index keyed strictly by `(tree_hash, DomainId)`.
#[derive(Debug, Default)]
pub struct TrigramIndex {
    trees: HashMap<(ObjectHash, DomainId), TreeTrigramEntry>,
    domain_hits: HashMap<DomainId, AtomicU64>,
    domain_misses: HashMap<DomainId, AtomicU64>,
}

impl TrigramIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `(tree_hash, domain)` is already indexed in memory.
    pub fn contains(&self, tree_hash: ObjectHash, domain: &DomainId) -> bool {
        self.trees.contains_key(&(tree_hash, domain.clone()))
    }

    /// Query candidate `(path, blob_hash)` pairs using ONLY a shared reference (`RwLock::read`).
    /// Returns `None` if `(tree_hash, domain)` is not yet cached.
    pub fn try_query_cached(
        &self,
        tree_hash: ObjectHash,
        domain: &DomainId,
        query: &str,
    ) -> Option<Vec<(String, ObjectHash)>> {
        let entry = self.trees.get(&(tree_hash, domain.clone()))?;
        if let Some(counter) = self.domain_hits.get(domain) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Some(entry.candidate_files(query))
    }

    /// Check whether a cached `(tree_hash, domain)` contains `path`.
    pub fn cached_tree_contains_path(
        &self,
        tree_hash: ObjectHash,
        domain: &DomainId,
        path: &str,
    ) -> Option<bool> {
        let entry = self.trees.get(&(tree_hash, domain.clone()))?;
        Some(entry.file_blobs.contains_key(path))
    }

    /// Ensure `(tree_hash, domain)` is indexed (recording a cache hit or miss) and return
    /// candidate `(path, blob_hash)` pairs matching `query`'s trigrams.
    pub fn query_or_build(
        &mut self,
        store: &dyn ObjectStore,
        tree_hash: ObjectHash,
        domain: &DomainId,
        query: &str,
    ) -> Result<Vec<(String, ObjectHash)>> {
        let key = (tree_hash, domain.clone());
        if let Some(entry) = self.trees.get(&key) {
            self.domain_hits
                .entry(domain.clone())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            return Ok(entry.candidate_files(query));
        }

        let built = TreeTrigramEntry::build(store, tree_hash, domain)?;
        let candidates = built.candidate_files(query);
        if self.trees.len() >= MAX_CACHED_TRIGRAM_TREES
            && let Some(evict_key) = self.trees.keys().next().cloned()
        {
            self.trees.remove(&evict_key);
        }
        self.trees.insert(key, built);
        self.domain_hits
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0));
        self.domain_misses
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        Ok(candidates)
    }

    /// Ensure `(tree_hash, domain)` is present in the cache without counting as a search query hit.
    pub fn ensure_indexed(
        &mut self,
        store: &dyn ObjectStore,
        tree_hash: ObjectHash,
        domain: &DomainId,
    ) -> Result<()> {
        let key = (tree_hash, domain.clone());
        if self.trees.contains_key(&key) {
            return Ok(());
        }
        let built = TreeTrigramEntry::build(store, tree_hash, domain)?;
        if self.trees.len() >= MAX_CACHED_TRIGRAM_TREES
            && let Some(evict_key) = self.trees.keys().next().cloned()
        {
            self.trees.remove(&evict_key);
        }
        self.trees.insert(key, built);
        self.domain_hits
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0));
        self.domain_misses
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn stats_filtered(
        &self,
        allowed: Option<&BTreeSet<DomainId>>,
    ) -> (usize, Vec<String>, usize, u64, u64) {
        let mut tree_count = 0usize;
        let mut domains = BTreeSet::new();
        let mut total_postings = 0usize;

        for ((_, dom), entry) in &self.trees {
            if allowed.is_some_and(|set| !set.contains(dom)) {
                continue;
            }
            tree_count += 1;
            domains.insert(dom.to_string());
            total_postings += entry.postings.len();
        }

        let mut hits = 0u64;
        for (dom, c) in &self.domain_hits {
            if allowed.is_none_or(|set| set.contains(dom)) {
                hits += c.load(Ordering::Relaxed);
            }
        }

        let mut misses = 0u64;
        for (dom, c) in &self.domain_misses {
            if allowed.is_none_or(|set| set.contains(dom)) {
                misses += c.load(Ordering::Relaxed);
            }
        }

        (
            tree_count,
            domains.into_iter().collect(),
            total_postings,
            hits,
            misses,
        )
    }
}

// ---------------------------------------------------------------------------
// 2. CommitGraphIndex — cached parent/depth table for fast ancestry & merge_base
// ---------------------------------------------------------------------------

/// Cached commit-graph metadata for a single [`ChangeSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitGraphNode {
    pub id: ObjectHash,
    pub parents: Vec<ObjectHash>,
    pub depth: u32,
    pub primary_domain: DomainId,
    pub tree_hashes: BTreeMap<DomainId, ObjectHash>,
}

/// In-memory commit-graph index providing O(1) parent/depth lookups, depth-pruned
/// ancestry checks, and fast DAG `merge_base(a, b)` queries.
#[derive(Debug, Default)]
pub struct CommitGraphIndex {
    nodes: HashMap<ObjectHash, CommitGraphNode>,
    domain_hits: HashMap<DomainId, AtomicU64>,
    domain_misses: HashMap<DomainId, AtomicU64>,
}

impl CommitGraphIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get(&self, id: ObjectHash) -> Option<&CommitGraphNode> {
        self.nodes.get(&id)
    }

    pub fn depth(&self, id: ObjectHash) -> Option<u32> {
        self.nodes.get(&id).map(|n| n.depth)
    }

    pub fn parents(&self, id: ObjectHash) -> Option<&[ObjectHash]> {
        self.nodes.get(&id).map(|n| n.parents.as_slice())
    }

    pub fn tree_hash(&self, id: ObjectHash, domain: &DomainId) -> Option<ObjectHash> {
        self.nodes
            .get(&id)
            .and_then(|n| n.tree_hashes.get(domain).copied())
    }

    /// Ensure `root` and all of its reachable ancestors are loaded into the commit graph.
    pub fn ensure_commit(&mut self, store: &dyn ObjectStore, root: ObjectHash) -> Result<()> {
        if let Some(node) = self.nodes.get(&root) {
            self.domain_hits
                .entry(node.primary_domain.clone())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Iteratively discover all unindexed ancestors in post-order so parents are
        // always inserted before children and depths are exact.
        let mut loaded: HashMap<ObjectHash, ChangeSet> = HashMap::new();
        let mut stack: Vec<(ObjectHash, bool)> = vec![(root, false)];
        let mut post_order: Vec<ObjectHash> = Vec::new();
        let mut seen: HashSet<ObjectHash> = HashSet::new();

        while let Some((curr, expanded)) = stack.pop() {
            if self.nodes.contains_key(&curr) {
                continue;
            }
            if expanded {
                post_order.push(curr);
                continue;
            }
            if !seen.insert(curr) {
                continue;
            }
            let cs = match store.get_changeset(curr) {
                Ok(c) => c,
                Err(_) if curr != root => continue,
                Err(err) => return Err(err),
            };
            let parents = cs.parents.clone();
            loaded.insert(curr, cs);
            stack.push((curr, true));
            for parent in parents {
                if !self.nodes.contains_key(&parent) && !seen.contains(&parent) {
                    stack.push((parent, false));
                }
            }
        }

        for hash in post_order {
            if self.nodes.contains_key(&hash) {
                continue;
            }
            if let Some(cs) = loaded.remove(&hash) {
                let depth = cs
                    .parents
                    .iter()
                    .filter_map(|p| self.nodes.get(p).map(|n| n.depth.saturating_add(1)))
                    .max()
                    .unwrap_or(0);
                let primary_domain = cs.visibility.primary_domain;
                self.nodes.insert(
                    hash,
                    CommitGraphNode {
                        id: cs.id,
                        parents: cs.parents,
                        depth,
                        primary_domain: primary_domain.clone(),
                        tree_hashes: cs.domain_trees,
                    },
                );
                self.domain_hits
                    .entry(primary_domain.clone())
                    .or_insert_with(|| AtomicU64::new(0));
                self.domain_misses
                    .entry(primary_domain)
                    .or_insert_with(|| AtomicU64::new(0))
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Returns `true` if `ancestor` is an ancestor of (or equal to) `descendant`.
    pub fn is_ancestor(
        &mut self,
        store: &dyn ObjectStore,
        ancestor: ObjectHash,
        descendant: ObjectHash,
    ) -> Result<bool> {
        if ancestor == descendant {
            return Ok(true);
        }
        self.ensure_commit(store, ancestor)?;
        self.ensure_commit(store, descendant)?;

        let Some(anc_depth) = self.depth(ancestor) else {
            return Ok(false);
        };
        let Some(desc_depth) = self.depth(descendant) else {
            return Ok(false);
        };
        if anc_depth >= desc_depth {
            return Ok(false);
        }

        let mut visited: HashSet<ObjectHash> = HashSet::new();
        let mut queue: VecDeque<ObjectHash> = VecDeque::new();
        queue.push_back(descendant);

        while let Some(curr) = queue.pop_front() {
            if !visited.insert(curr) {
                continue;
            }
            if curr == ancestor {
                return Ok(true);
            }
            if let Some(node) = self.nodes.get(&curr) {
                if node.depth <= anc_depth {
                    continue;
                }
                for &parent in &node.parents {
                    if parent == ancestor {
                        return Ok(true);
                    }
                    if !visited.contains(&parent)
                        && self
                            .nodes
                            .get(&parent)
                            .is_some_and(|p| p.depth >= anc_depth)
                    {
                        queue.push_back(parent);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Find the closest common ancestor (merge-base / LCA) of `a` and `b` using cached graph metadata.
    pub fn merge_base(
        &mut self,
        store: &dyn ObjectStore,
        a: ObjectHash,
        b: ObjectHash,
    ) -> Result<Option<ObjectHash>> {
        if a == b {
            let _ = self.ensure_commit(store, a);
            return Ok(Some(a));
        }

        self.ensure_commit(store, a)?;
        self.ensure_commit(store, b)?;

        let mut dist_a: HashMap<ObjectHash, usize> = HashMap::new();
        let mut queue_a: VecDeque<(ObjectHash, usize)> = VecDeque::new();
        queue_a.push_back((a, 0));

        while let Some((curr, dist)) = queue_a.pop_front() {
            if dist_a.contains_key(&curr) {
                continue;
            }
            dist_a.insert(curr, dist);
            if let Some(node) = self.nodes.get(&curr) {
                for &parent in &node.parents {
                    if !dist_a.contains_key(&parent) {
                        queue_a.push_back((parent, dist + 1));
                    }
                }
            }
        }

        let mut visited_b: HashSet<ObjectHash> = HashSet::new();
        let mut queue_b: VecDeque<(ObjectHash, usize)> = VecDeque::new();
        queue_b.push_back((b, 0));
        let mut best: Option<(usize, u32, ObjectHash)> = None;

        while let Some((curr, d_b)) = queue_b.pop_front() {
            if !visited_b.insert(curr) {
                continue;
            }
            if let Some(&d_a) = dist_a.get(&curr) {
                let score = d_a + d_b;
                let depth = self.depth(curr).unwrap_or(0);
                let replace = match best {
                    None => true,
                    Some((best_score, best_depth, best_hash)) => {
                        score < best_score
                            || (score == best_score && depth > best_depth)
                            || (score == best_score && depth == best_depth && curr < best_hash)
                    }
                };
                if replace {
                    best = Some((score, depth, curr));
                }
            }
            if let Some(node) = self.nodes.get(&curr) {
                for &parent in &node.parents {
                    if !visited_b.contains(&parent) {
                        queue_b.push_back((parent, d_b + 1));
                    }
                }
            }
        }

        Ok(best.map(|(_, _, h)| h))
    }

    fn stats_filtered(&self, allowed: Option<&BTreeSet<DomainId>>) -> (usize, u64, u64) {
        let count = match allowed {
            None => self.nodes.len(),
            Some(set) => self
                .nodes
                .values()
                .filter(|n| set.contains(&n.primary_domain))
                .count(),
        };
        let mut hits = 0u64;
        for (dom, c) in &self.domain_hits {
            if allowed.is_none_or(|set| set.contains(dom)) {
                hits += c.load(Ordering::Relaxed);
            }
        }
        let mut misses = 0u64;
        for (dom, c) in &self.domain_misses {
            if allowed.is_none_or(|set| set.contains(dom)) {
                misses += c.load(Ordering::Relaxed);
            }
        }
        (count, hits, misses)
    }
}

// ---------------------------------------------------------------------------
// 3. PathHistoryIndex — cached (path, domain) -> Vec<ObjectHash> for /blame
// ---------------------------------------------------------------------------

/// Domain-partitioned path history cache mapping `(path, DomainId)` to the oldest-first
/// list of touching commit hashes up to the cached tip.
#[derive(Debug, Default)]
pub struct PathHistoryIndex {
    entries: HashMap<(String, DomainId), Vec<ObjectHash>>,
    tips: HashMap<(String, DomainId), ObjectHash>,
    domain_hits: HashMap<DomainId, AtomicU64>,
    domain_misses: HashMap<DomainId, AtomicU64>,
}

impl PathHistoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return cached touching commits for `(path, domain)` if `head` matches the cached tip.
    pub fn get_cached(
        &self,
        head: ObjectHash,
        path: &str,
        domain: &DomainId,
    ) -> Option<Vec<ObjectHash>> {
        let key = (path.to_string(), domain.clone());
        if self.tips.get(&key).copied() != Some(head) {
            return None;
        }
        let commits = self.entries.get(&key)?;
        if let Some(counter) = self.domain_hits.get(domain) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Some(commits.clone())
    }

    /// Return (or compute and cache) the ordered oldest -> newest list of commits on the
    /// first-parent chain from `head` where `path` changed within `domain`.
    pub fn history_for_path(
        &mut self,
        store: &dyn ObjectStore,
        commit_graph: &mut CommitGraphIndex,
        head: ObjectHash,
        path: &str,
        domain: &DomainId,
    ) -> Result<Vec<ObjectHash>> {
        let key = (path.to_string(), domain.clone());
        if self.tips.get(&key).copied() == Some(head)
            && let Some(commits) = self.entries.get(&key)
        {
            self.domain_hits
                .entry(domain.clone())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            return Ok(commits.clone());
        }

        commit_graph.ensure_commit(store, head)?;

        // Cache `(tree_hash -> Option<blob_hash>)` locally for this walk to avoid redundant tree reads.
        let mut tree_blob_cache: HashMap<ObjectHash, Option<ObjectHash>> = HashMap::new();
        let mut touching: Vec<ObjectHash> = Vec::new();
        let mut visited: HashSet<ObjectHash> = HashSet::new();
        let mut cursor = Some(head);

        while let Some(curr) = cursor {
            if !visited.insert(curr) {
                break;
            }
            let first_parent = commit_graph
                .parents(curr)
                .and_then(|ps| ps.first().copied());

            let curr_tree = commit_graph.tree_hash(curr, domain);
            let parent_tree = first_parent.and_then(|p| commit_graph.tree_hash(p, domain));

            // Fast skip when this commit's domain tree hash is identical to its first parent's.
            if curr_tree != parent_tree {
                let curr_blob = lookup_path_blob(store, &mut tree_blob_cache, curr_tree, path)?;
                let parent_blob = lookup_path_blob(store, &mut tree_blob_cache, parent_tree, path)?;
                if curr_blob != parent_blob {
                    touching.push(curr);
                }
            }

            cursor = first_parent;
        }

        touching.reverse();

        if self.entries.len() >= MAX_CACHED_PATH_HISTORIES
            && let Some(evict_key) = self.entries.keys().next().cloned()
        {
            self.entries.remove(&evict_key);
            self.tips.remove(&evict_key);
        }
        self.entries.insert(key.clone(), touching.clone());
        self.tips.insert(key, head);
        self.domain_hits
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0));
        self.domain_misses
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        Ok(touching)
    }

    fn stats_filtered(&self, allowed: Option<&BTreeSet<DomainId>>) -> (usize, u64, u64) {
        let count = match allowed {
            None => self.entries.len(),
            Some(set) => self
                .entries
                .keys()
                .filter(|(_, dom)| set.contains(dom))
                .count(),
        };

        let mut hits = 0u64;
        for (dom, c) in &self.domain_hits {
            if allowed.is_none_or(|set| set.contains(dom)) {
                hits += c.load(Ordering::Relaxed);
            }
        }

        let mut misses = 0u64;
        for (dom, c) in &self.domain_misses {
            if allowed.is_none_or(|set| set.contains(dom)) {
                misses += c.load(Ordering::Relaxed);
            }
        }

        (count, hits, misses)
    }
}

fn lookup_path_blob(
    store: &dyn ObjectStore,
    cache: &mut HashMap<ObjectHash, Option<ObjectHash>>,
    tree_hash: Option<ObjectHash>,
    path: &str,
) -> Result<Option<ObjectHash>> {
    let Some(hash) = tree_hash else {
        return Ok(None);
    };
    if let Some(&cached) = cache.get(&hash) {
        return Ok(cached);
    }
    let tree = store.get_tree(hash)?;
    let blob = match tree.entries.get(path) {
        Some(EntryKind::File { blob_hash, .. }) => Some(*blob_hash),
        _ => None,
    };
    cache.insert(hash, blob);
    Ok(blob)
}

// ---------------------------------------------------------------------------
// 4. SymbolIndex — strictly partitioned by (tree_hash, DomainId)
// ---------------------------------------------------------------------------

/// A symbol extracted and cached by [`SymbolIndex`] for a `(tree_hash, domain)` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedSymbol {
    pub path: String,
    pub domain: String,
    pub name: String,
    pub kind: String,
    pub line_start: u32,
    pub line_end: u32,
}

/// Domain-partitioned Tree-sitter AST symbol index keyed strictly by `(tree_hash, DomainId)`.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    trees: HashMap<(ObjectHash, DomainId), Vec<IndexedSymbol>>,
    domain_hits: HashMap<DomainId, AtomicU64>,
    domain_misses: HashMap<DomainId, AtomicU64>,
}

impl SymbolIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_query_cached(
        &self,
        tree_hash: ObjectHash,
        domain: &DomainId,
        path_filter: Option<&str>,
    ) -> Option<Vec<IndexedSymbol>> {
        let entries = self.trees.get(&(tree_hash, domain.clone()))?;
        if let Some(counter) = self.domain_hits.get(domain) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Some(filter_indexed_symbols(entries, path_filter))
    }

    pub fn query_or_build(
        &mut self,
        store: &dyn ObjectStore,
        tree_hash: ObjectHash,
        domain: &DomainId,
        path_filter: Option<&str>,
    ) -> Result<Vec<IndexedSymbol>> {
        let key = (tree_hash, domain.clone());
        if let Some(entries) = self.trees.get(&key) {
            self.domain_hits
                .entry(domain.clone())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            return Ok(filter_indexed_symbols(entries, path_filter));
        }

        let tree = store.get_tree(tree_hash)?;
        if &tree.domain != domain {
            return Err(GitxError::AccessDenied {
                domain: domain.to_string(),
                reason: format!(
                    "domain tree {tree_hash} belongs to '{}' rather than '{domain}'",
                    tree.domain
                ),
            });
        }

        let mut built = Vec::new();
        for (path, entry) in &tree.entries {
            if let EntryKind::File { blob_hash, .. } = entry {
                let bytes = store.read_blob_bytes(*blob_hash)?;
                if let Ok(source) = std::str::from_utf8(&bytes) {
                    for sym in gitx_merge::extract_ast_symbols(path, source) {
                        built.push(IndexedSymbol {
                            path: path.clone(),
                            domain: domain.to_string(),
                            name: sym.name,
                            kind: sym.kind,
                            line_start: sym.line_start,
                            line_end: sym.line_end,
                        });
                    }
                }
            }
        }

        let filtered = filter_indexed_symbols(&built, path_filter);
        if self.trees.len() >= MAX_CACHED_TRIGRAM_TREES
            && let Some(evict_key) = self.trees.keys().next().cloned()
        {
            self.trees.remove(&evict_key);
        }
        self.trees.insert(key, built);
        self.domain_hits
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0));
        self.domain_misses
            .entry(domain.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        Ok(filtered)
    }

    fn stats_filtered(&self, allowed: Option<&BTreeSet<DomainId>>) -> (usize, usize, u64, u64) {
        let mut tree_count = 0usize;
        let mut total_symbols = 0usize;
        for ((_, dom), syms) in &self.trees {
            if allowed.is_some_and(|set| !set.contains(dom)) {
                continue;
            }
            tree_count += 1;
            total_symbols += syms.len();
        }
        let mut hits = 0u64;
        for (dom, c) in &self.domain_hits {
            if allowed.is_none_or(|set| set.contains(dom)) {
                hits += c.load(Ordering::Relaxed);
            }
        }
        let mut misses = 0u64;
        for (dom, c) in &self.domain_misses {
            if allowed.is_none_or(|set| set.contains(dom)) {
                misses += c.load(Ordering::Relaxed);
            }
        }
        (tree_count, total_symbols, hits, misses)
    }
}

fn filter_indexed_symbols(
    entries: &[IndexedSymbol],
    path_filter: Option<&str>,
) -> Vec<IndexedSymbol> {
    match path_filter.map(str::trim).filter(|s| !s.is_empty()) {
        Some(target) => entries
            .iter()
            .filter(|s| s.path == target)
            .cloned()
            .collect(),
        None => entries.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Unified DerivedIndex attached to RepoHandle
// ---------------------------------------------------------------------------

/// Scion-style derived data engine attached to each hosted repository.
#[derive(Debug, Default)]
pub struct DerivedIndex {
    pub trigram: TrigramIndex,
    pub commit_graph: CommitGraphIndex,
    pub path_history: PathHistoryIndex,
    pub symbols: SymbolIndex,
}

impl DerivedIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return unfiltered statistics across all indexed domains (for internal/admin diagnostics).
    pub fn stats(&self) -> DerivedStats {
        self.build_stats(None)
    }

    /// Return ACL-filtered statistics scoped strictly to `allowed_domains`.
    pub fn stats_for_domains(&self, allowed_domains: &BTreeSet<DomainId>) -> DerivedStats {
        self.build_stats(Some(allowed_domains))
    }

    fn build_stats(&self, allowed: Option<&BTreeSet<DomainId>>) -> DerivedStats {
        let (
            trigram_indexed_trees,
            trigram_domains,
            trigram_total_postings,
            trigram_cache_hits,
            trigram_cache_misses,
        ) = self.trigram.stats_filtered(allowed);
        let (commit_graph_nodes, commit_graph_cache_hits, commit_graph_cache_misses) =
            self.commit_graph.stats_filtered(allowed);
        let (path_history_entries, path_history_cache_hits, path_history_cache_misses) =
            self.path_history.stats_filtered(allowed);
        let (symbol_indexed_trees, symbol_total_symbols, symbol_cache_hits, symbol_cache_misses) =
            self.symbols.stats_filtered(allowed);

        DerivedStats {
            trigram_indexed_trees,
            trigram_domains,
            trigram_total_postings,
            trigram_cache_hits,
            trigram_cache_misses,
            commit_graph_nodes,
            commit_graph_cache_hits,
            commit_graph_cache_misses,
            path_history_entries,
            path_history_cache_hits,
            path_history_cache_misses,
            symbol_indexed_trees,
            symbol_total_symbols,
            symbol_cache_hits,
            symbol_cache_misses,
        }
    }
}

// ---------------------------------------------------------------------------
// Trigram & Set Intersection Helpers
// ---------------------------------------------------------------------------

fn extract_unique_trigrams(bytes: &[u8]) -> Vec<[u8; 3]> {
    if bytes.len() < 3 {
        return Vec::new();
    }
    let mut set: HashSet<[u8; 3]> = HashSet::with_capacity(bytes.len().min(4096));
    for window in bytes.windows(3) {
        set.insert([
            window[0].to_ascii_lowercase(),
            window[1].to_ascii_lowercase(),
            window[2].to_ascii_lowercase(),
        ]);
    }
    set.into_iter().collect()
}

fn intersect_sorted(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(a.len().min(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i].clone());
                i += 1;
                j += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitx_core::{ChangeSetBuilder, DomainTree, FileMode, Identity, VisibilityPolicy};
    use gitx_store::MemoryStore;

    fn test_identity() -> Identity {
        Identity {
            name: "Tester".to_string(),
            email: "tester@gitx.local".to_string(),
            key_fingerprint: None,
        }
    }

    fn make_tree(store: &MemoryStore, domain: DomainId, files: &[(&str, &str)]) -> ObjectHash {
        let mut tree = DomainTree::new(domain);
        for (path, content) in files {
            let blob = store.put_blob_bytes(content.as_bytes()).unwrap();
            tree.insert(
                *path,
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode: FileMode::Regular,
                    size: blob.total_size,
                },
            );
        }
        store.put_tree(&tree).unwrap()
    }

    #[test]
    fn trigram_index_is_strictly_partitioned_by_domain() {
        let store = MemoryStore::new();
        let pub_dom = DomainId::public();
        let core_dom = DomainId::team("core").unwrap();

        let pub_tree = make_tree(
            &store,
            pub_dom.clone(),
            &[("src/lib.rs", "pub fn hello_world() {}\n")],
        );
        let core_tree = make_tree(
            &store,
            core_dom.clone(),
            &[(
                "packages/private/secret.rs",
                "pub const KEY: &str = \"CORE_SECRET_ALPHA\";\n",
            )],
        );

        let mut idx = DerivedIndex::new();

        // Warm core_dom index
        let c1 = idx
            .trigram
            .query_or_build(&store, core_tree, &core_dom, "CORE_SECRET_ALPHA")
            .unwrap();
        assert_eq!(c1.len(), 1);
        assert_eq!(c1[0].0, "packages/private/secret.rs");

        // Second query is a cache hit
        let c2 = idx
            .trigram
            .query_or_build(&store, core_tree, &core_dom, "core_secret")
            .unwrap();
        assert_eq!(c2.len(), 1);

        // Querying public tree for core secret returns ZERO candidates
        let pub_res = idx
            .trigram
            .query_or_build(&store, pub_tree, &pub_dom, "CORE_SECRET_ALPHA")
            .unwrap();
        assert!(pub_res.is_empty());

        // Attempting to index a core_dom tree under public is rejected by domain check
        let cross_err =
            idx.trigram
                .query_or_build(&store, core_tree, &pub_dom, "CORE_SECRET_ALPHA");
        assert!(cross_err.is_err());

        // ACL-filtered stats for public-only caller must not expose team:core
        let pub_only: BTreeSet<DomainId> = [pub_dom].into_iter().collect();
        let stats = idx.stats_for_domains(&pub_only);
        assert_eq!(stats.trigram_indexed_trees, 1);
        assert_eq!(stats.trigram_domains, vec!["public"]);
    }

    #[test]
    fn commit_graph_ancestry_and_merge_base() {
        let store = MemoryStore::new();
        let pub_dom = DomainId::public();
        let t0 = make_tree(&store, pub_dom.clone(), &[("a.txt", "v0\n")]);

        let c0 = ChangeSetBuilder::new(test_identity())
            .domain_trees([(pub_dom.clone(), t0)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("c0")
            .build();
        store.put_changeset(&c0).unwrap();

        let c1 = ChangeSetBuilder::new(test_identity())
            .parents(vec![c0.id])
            .domain_trees([(pub_dom.clone(), t0)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("c1")
            .build();
        store.put_changeset(&c1).unwrap();

        let c2 = ChangeSetBuilder::new(test_identity())
            .parents(vec![c0.id])
            .domain_trees([(pub_dom.clone(), t0)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("c2")
            .build();
        store.put_changeset(&c2).unwrap();

        let c3 = ChangeSetBuilder::new(test_identity())
            .parents(vec![c1.id])
            .domain_trees([(pub_dom.clone(), t0)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("c3")
            .build();
        store.put_changeset(&c3).unwrap();

        let mut graph = CommitGraphIndex::new();
        assert_eq!(graph.merge_base(&store, c3.id, c2.id).unwrap(), Some(c0.id));
        assert!(graph.is_ancestor(&store, c0.id, c3.id).unwrap());
        assert!(!graph.is_ancestor(&store, c2.id, c3.id).unwrap());
        assert_eq!(graph.depth(c0.id), Some(0));
        assert_eq!(graph.depth(c1.id), Some(1));
        assert_eq!(graph.depth(c3.id), Some(2));
    }

    #[test]
    fn path_history_skips_unrelated_commits_and_caches() {
        let store = MemoryStore::new();
        let pub_dom = DomainId::public();

        let t1 = make_tree(&store, pub_dom.clone(), &[("a.rs", "fn a() {}\n")]);
        let c1 = ChangeSetBuilder::new(test_identity())
            .domain_trees([(pub_dom.clone(), t1)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("add a.rs")
            .build();
        store.put_changeset(&c1).unwrap();

        let t2 = make_tree(
            &store,
            pub_dom.clone(),
            &[("a.rs", "fn a() {}\n"), ("b.rs", "fn b() {}\n")],
        );
        let c2 = ChangeSetBuilder::new(test_identity())
            .parents(vec![c1.id])
            .domain_trees([(pub_dom.clone(), t2)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("add b.rs")
            .build();
        store.put_changeset(&c2).unwrap();

        let t3 = make_tree(
            &store,
            pub_dom.clone(),
            &[("a.rs", "fn a() { 1 }\n"), ("b.rs", "fn b() {}\n")],
        );
        let c3 = ChangeSetBuilder::new(test_identity())
            .parents(vec![c2.id])
            .domain_trees([(pub_dom.clone(), t3)].into_iter().collect())
            .visibility(VisibilityPolicy::public())
            .description("edit a.rs")
            .build();
        store.put_changeset(&c3).unwrap();

        let mut derived = DerivedIndex::new();
        let hist1 = derived
            .path_history
            .history_for_path(&store, &mut derived.commit_graph, c3.id, "a.rs", &pub_dom)
            .unwrap();
        assert_eq!(hist1, vec![c1.id, c3.id]);

        let hist2 = derived
            .path_history
            .history_for_path(&store, &mut derived.commit_graph, c3.id, "a.rs", &pub_dom)
            .unwrap();
        assert_eq!(hist2, vec![c1.id, c3.id]);

        let stats = derived.stats();
        assert_eq!(stats.path_history_entries, 1);
        assert_eq!(stats.path_history_cache_misses, 1);
        assert_eq!(stats.path_history_cache_hits, 1);
    }
}
