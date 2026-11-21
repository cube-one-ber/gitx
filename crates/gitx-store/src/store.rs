use chrono::{DateTime, Utc};
use gitx_core::{
    ChangeId, ChangeSet, ChunkedBlob, DomainTree, GitxError, ObjectHash, OpId, OpLogEntry, Result,
    Stack, WorkspaceRef, chunk_bytes,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Atomic landing ledger record with a strictly monotonic `land_seq` to prevent
/// split-brain merges and enable O(1) reverts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandRecord {
    pub land_seq: u64,
    pub target: String,
    pub previous_head: Option<ObjectHash>,
    pub new_head: ObjectHash,
    pub landed_changes: Vec<ChangeId>,
    pub timestamp: DateTime<Utc>,
    pub reverted_by: Option<u64>,
}

/// Core storage abstraction for gitx repositories.
pub trait ObjectStore: Send + Sync {
    // ---- Raw chunks ----
    fn put_chunk(&self, hash: ObjectHash, data: &[u8]) -> Result<()>;
    fn get_chunk(&self, hash: ObjectHash) -> Result<Vec<u8>>;
    fn has_chunk(&self, hash: ObjectHash) -> Result<bool>;

    // ---- Convenience chunked blobs ----
    fn put_blob_bytes(&self, data: &[u8]) -> Result<ChunkedBlob> {
        let (blob, chunks) = chunk_bytes(data);
        for (hash, bytes) in chunks {
            self.put_chunk(hash, &bytes)?;
        }
        let manifest_hash = blob.manifest_hash();
        let manifest_bytes =
            bincode::serialize(&blob).map_err(|e| GitxError::Serialization(e.to_string()))?;
        self.put_raw_object(manifest_hash, &manifest_bytes)?;
        Ok(blob)
    }

    fn get_blob_manifest(&self, manifest_hash: ObjectHash) -> Result<ChunkedBlob> {
        let bytes = self.get_raw_object(manifest_hash)?;
        bincode::deserialize(&bytes).map_err(|e| GitxError::Serialization(e.to_string()))
    }

    fn read_blob_bytes(&self, manifest_hash: ObjectHash) -> Result<Vec<u8>> {
        let manifest = self.get_blob_manifest(manifest_hash)?;
        let mut out = Vec::with_capacity(manifest.total_size as usize);
        for chunk in &manifest.chunks {
            let bytes = self.get_chunk(chunk.hash)?;
            out.extend_from_slice(&bytes);
        }
        if out.len() as u64 != manifest.total_size {
            return Err(GitxError::Storage(format!(
                "blob {} size mismatch: expected {}, got {}",
                manifest_hash,
                manifest.total_size,
                out.len()
            )));
        }
        let actual_hash = ObjectHash::of_typed("gitx:raw:v1", &out);
        if actual_hash != manifest.content_hash {
            return Err(GitxError::Storage(format!(
                "blob {} content hash mismatch: expected {}, got {}",
                manifest_hash, manifest.content_hash, actual_hash
            )));
        }
        Ok(out)
    }

    // ---- Arbitrary opaque objects (e.g. encrypted secret envelopes) ----
    fn put_raw_object(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()>;
    fn get_raw_object(&self, hash: ObjectHash) -> Result<Vec<u8>>;

    // ---- DomainTree storage ----
    fn put_tree(&self, tree: &DomainTree) -> Result<ObjectHash> {
        let hash = tree.hash();
        let bytes =
            bincode::serialize(tree).map_err(|e| GitxError::Serialization(e.to_string()))?;
        self.put_raw_object(hash, &bytes)?;
        Ok(hash)
    }

    fn get_tree(&self, hash: ObjectHash) -> Result<DomainTree> {
        let bytes = self.get_raw_object(hash)?;
        bincode::deserialize(&bytes).map_err(|e| GitxError::Serialization(e.to_string()))
    }

    // ---- ChangeSet storage ----
    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash>;
    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet>;
    fn list_changesets(&self) -> Result<Vec<ChangeSet>>;
    /// Returns all revisions for `change_id`, ordered oldest -> newest.
    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>>;

    // ---- Stack storage ----
    fn put_stack(&self, stack: &Stack) -> Result<()>;
    fn get_stack(&self, name: &str) -> Result<Stack>;
    fn list_stacks(&self) -> Result<Vec<Stack>>;
    fn delete_stack(&self, name: &str) -> Result<()>;

    // ---- OpLog & atomic state snapshots ----
    fn append_op(&self, op: &OpLogEntry) -> Result<()>;
    fn get_op(&self, id: OpId) -> Result<OpLogEntry>;
    fn latest_op(&self) -> Result<Option<OpLogEntry>>;
    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>>;

    // ---- Atomic Landing ledger ----
    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord>;
    fn get_land(&self, land_seq: u64) -> Result<LandRecord>;
    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>>;
    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()>;

    // ---- Bookmarks & Workspaces ----
    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>>;
    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()>;
    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>>;
    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()>;
    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>>;
    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>>;
    fn remove_workspace(&self, name: &str) -> Result<()>;
}

/// Orders revisions of a single `ChangeId` from oldest to newest.
///
/// Respects `previous_revision` ancestry links first (topological order), breaking ties by
/// `(created_at, insertion_seq, id)`.
pub(crate) fn sort_revisions_oldest_first(items: Vec<(u64, ChangeSet)>) -> Vec<ChangeSet> {
    if items.len() <= 1 {
        return items.into_iter().map(|(_, cs)| cs).collect();
    }

    let mut id_to_idx: HashMap<ObjectHash, usize> = HashMap::with_capacity(items.len());
    for (idx, (_, cs)) in items.iter().enumerate() {
        id_to_idx.insert(cs.id, idx);
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); items.len()];
    let mut in_degree: Vec<usize> = vec![0; items.len()];

    for (idx, (_, cs)) in items.iter().enumerate() {
        if let Some(prev) = cs.previous_revision
            && let Some(&prev_idx) = id_to_idx.get(&prev)
            && prev_idx != idx
        {
            children[prev_idx].push(idx);
            in_degree[idx] += 1;
        }
    }

    let key_for = |idx: usize| -> (DateTime<Utc>, u64, ObjectHash, usize) {
        let (seq, cs) = &items[idx];
        (cs.created_at, *seq, cs.id, idx)
    };

    let mut ready: BTreeSet<(DateTime<Utc>, u64, ObjectHash, usize)> = BTreeSet::new();
    for (idx, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            ready.insert(key_for(idx));
        }
    }

    let mut order = Vec::with_capacity(items.len());
    let mut visited = vec![false; items.len()];

    while let Some(entry) = ready.pop_first() {
        let idx = entry.3;
        visited[idx] = true;
        order.push(idx);
        for &child_idx in &children[idx] {
            in_degree[child_idx] -= 1;
            if in_degree[child_idx] == 0 {
                ready.insert(key_for(child_idx));
            }
        }
    }

    if order.len() < items.len() {
        let mut remaining: Vec<usize> = (0..items.len()).filter(|&i| !visited[i]).collect();
        remaining.sort_by_key(|&i| key_for(i));
        order.extend(remaining);
    }

    let mut slots: Vec<Option<ChangeSet>> = items.into_iter().map(|(_, cs)| Some(cs)).collect();
    order
        .into_iter()
        .filter_map(|idx| slots[idx].take())
        .collect()
}
