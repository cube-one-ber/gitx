use crate::store::{LandRecord, ObjectStore, sort_revisions_oldest_first};
use chrono::Utc;
use gitx_core::{
    ChangeId, ChangeSet, GitxError, ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug)]
struct MemoryState {
    cas: HashMap<ObjectHash, Vec<u8>>,
    changesets: HashMap<ObjectHash, (u64, ChangeSet)>,
    next_cs_seq: u64,
    changesets_by_change_id: HashMap<ChangeId, Vec<ObjectHash>>,
    stacks: BTreeMap<String, Stack>,
    oplog: Vec<OpLogEntry>,
    oplog_index: HashMap<OpId, usize>,
    lands: BTreeMap<u64, LandRecord>,
    next_land_seq: u64,
    bookmarks: BTreeMap<String, ObjectHash>,
    workspaces: BTreeMap<String, WorkspaceRef>,
}

impl Default for MemoryState {
    fn default() -> Self {
        Self {
            cas: HashMap::new(),
            changesets: HashMap::new(),
            next_cs_seq: 1,
            changesets_by_change_id: HashMap::new(),
            stacks: BTreeMap::new(),
            oplog: Vec::new(),
            oplog_index: HashMap::new(),
            lands: BTreeMap::new(),
            next_land_seq: 1,
            bookmarks: BTreeMap::new(),
            workspaces: BTreeMap::new(),
        }
    }
}

/// Pure in-memory `RwLock`-backed `ObjectStore` for `mem://` workspaces, tests, and sandboxes.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: RwLock<MemoryState>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, MemoryState>> {
        self.state
            .read()
            .map_err(|_| GitxError::Storage("memory store read lock poisoned".to_string()))
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, MemoryState>> {
        self.state
            .write()
            .map_err(|_| GitxError::Storage("memory store write lock poisoned".to_string()))
    }
}

impl ObjectStore for MemoryStore {
    fn put_chunk(&self, hash: ObjectHash, data: &[u8]) -> Result<()> {
        let mut state = self.write_state()?;
        state.cas.entry(hash).or_insert_with(|| data.to_vec());
        Ok(())
    }

    fn get_chunk(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        let state = self.read_state()?;
        state
            .cas
            .get(&hash)
            .cloned()
            .ok_or_else(|| GitxError::NotFound(format!("chunk {hash}")))
    }

    fn has_chunk(&self, hash: ObjectHash) -> Result<bool> {
        let state = self.read_state()?;
        Ok(state.cas.contains_key(&hash))
    }

    fn put_raw_object(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()> {
        let mut state = self.write_state()?;
        state.cas.entry(hash).or_insert_with(|| bytes.to_vec());
        Ok(())
    }

    fn get_raw_object(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        let state = self.read_state()?;
        state
            .cas
            .get(&hash)
            .cloned()
            .ok_or_else(|| GitxError::NotFound(format!("object {hash}")))
    }

    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        let mut state = self.write_state()?;
        if state.changesets.contains_key(&cs.id) {
            return Ok(cs.id);
        }
        let seq = state.next_cs_seq;
        state.next_cs_seq += 1;
        state.changesets.insert(cs.id, (seq, cs.clone()));
        state
            .changesets_by_change_id
            .entry(cs.change_id)
            .or_default()
            .push(cs.id);
        Ok(cs.id)
    }

    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        let state = self.read_state()?;
        state
            .changesets
            .get(&id)
            .map(|(_, cs)| cs.clone())
            .ok_or_else(|| GitxError::NotFound(format!("changeset {id}")))
    }

    fn list_changesets(&self) -> Result<Vec<ChangeSet>> {
        let state = self.read_state()?;
        let mut items: Vec<(u64, ChangeSet)> = state.changesets.values().cloned().collect();
        items.sort_by_key(|(seq, _)| *seq);
        Ok(items.into_iter().map(|(_, cs)| cs).collect())
    }

    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>> {
        let state = self.read_state()?;
        let Some(ids) = state.changesets_by_change_id.get(&change_id) else {
            return Ok(Vec::new());
        };
        let items: Vec<(u64, ChangeSet)> = ids
            .iter()
            .filter_map(|id| state.changesets.get(id).cloned())
            .collect();
        Ok(sort_revisions_oldest_first(items))
    }

    fn put_stack(&self, stack: &Stack) -> Result<()> {
        let mut state = self.write_state()?;
        state.stacks.insert(stack.name.clone(), stack.clone());
        Ok(())
    }

    fn get_stack(&self, name: &str) -> Result<Stack> {
        let state = self.read_state()?;
        state
            .stacks
            .get(name)
            .cloned()
            .ok_or_else(|| GitxError::NotFound(format!("stack '{name}'")))
    }

    fn list_stacks(&self) -> Result<Vec<Stack>> {
        let state = self.read_state()?;
        Ok(state.stacks.values().cloned().collect())
    }

    fn delete_stack(&self, name: &str) -> Result<()> {
        let mut state = self.write_state()?;
        state.stacks.remove(name);
        Ok(())
    }

    fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        let mut state = self.write_state()?;
        if state.oplog_index.contains_key(&op.id) {
            return Err(GitxError::Storage(format!(
                "duplicate oplog entry {:?}",
                op.id
            )));
        }
        let idx = state.oplog.len();
        state.oplog.push(op.clone());
        state.oplog_index.insert(op.id, idx);
        Ok(())
    }

    fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        let state = self.read_state()?;
        let &idx = state
            .oplog_index
            .get(&id)
            .ok_or_else(|| GitxError::NotFound(format!("oplog entry {:?}", id)))?;
        Ok(state.oplog[idx].clone())
    }

    fn latest_op(&self) -> Result<Option<OpLogEntry>> {
        let state = self.read_state()?;
        Ok(state.oplog.last().cloned())
    }

    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>> {
        let state = self.read_state()?;
        Ok(state.oplog.iter().rev().take(limit).cloned().collect())
    }

    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord> {
        let mut state = self.write_state()?;
        let current_head = state.bookmarks.get(target).copied();
        if current_head != expected_previous {
            return Err(GitxError::Merge(format!(
                "CAS conflict landing onto '{target}': expected previous head {expected_previous:?}, actual {current_head:?}"
            )));
        }

        let land_seq = state.next_land_seq;
        state.next_land_seq += 1;

        let record = LandRecord {
            land_seq,
            target: target.to_string(),
            previous_head: expected_previous,
            new_head,
            landed_changes: changes,
            timestamp: Utc::now(),
            reverted_by: None,
        };

        state.lands.insert(land_seq, record.clone());
        state.bookmarks.insert(target.to_string(), new_head);
        Ok(record)
    }

    fn get_land(&self, land_seq: u64) -> Result<LandRecord> {
        let state = self.read_state()?;
        state
            .lands
            .get(&land_seq)
            .cloned()
            .ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))
    }

    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>> {
        let state = self.read_state()?;
        Ok(state
            .lands
            .values()
            .rev()
            .filter(|r| r.target == target)
            .take(limit)
            .cloned()
            .collect())
    }

    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()> {
        let mut state = self.write_state()?;
        let rec = state
            .lands
            .get_mut(&land_seq)
            .ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))?;
        if let Some(existing) = rec.reverted_by
            && existing != reverted_by
        {
            return Err(GitxError::Merge(format!(
                "land record {land_seq} already reverted by {existing}"
            )));
        }
        rec.reverted_by = Some(reverted_by);
        Ok(())
    }

    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        let state = self.read_state()?;
        Ok(state.bookmarks.get(name).copied())
    }

    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()> {
        let mut state = self.write_state()?;
        state.bookmarks.insert(name.to_string(), hash);
        Ok(())
    }

    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>> {
        let state = self.read_state()?;
        Ok(state.bookmarks.clone())
    }

    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()> {
        let mut state = self.write_state()?;
        state.workspaces.insert(ws.name.clone(), ws.clone());
        Ok(())
    }

    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        let state = self.read_state()?;
        Ok(state.workspaces.get(name).cloned())
    }

    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        let state = self.read_state()?;
        Ok(state.workspaces.clone())
    }

    fn remove_workspace(&self, name: &str) -> Result<()> {
        let mut state = self.write_state()?;
        state.workspaces.remove(name);
        Ok(())
    }
}
