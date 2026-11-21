use chrono::Utc;
use gitx_core::{
    ChangeId, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, GitxError,
    Identity, ObjectHash, OpId, OpKind, OpLogEntry, Result, WorkspaceRef,
};
use gitx_server::{
    CommitResponse, DerivedStats, DrainResponse, EnqueueResponse, QueueListResponse, QueueStatus,
    ServerConfig, TreeResponse, serve,
};
use gitx_store::{LandRecord, LocalStore, ObjectStore};
use gitx_vfs::WorkspaceBackendKind;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::{JoinHandle, JoinSet};

/// Configuration for the hermetic deterministic simulation suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimConfig {
    /// Deterministic PRNG seed for `StdRng::seed_from_u64`.
    pub seed: u64,
    /// Number of randomized operations in the OpLog & crash-recovery simulator.
    pub oplog_ops: usize,
    /// Drop and reopen `LocalStore` every N operations to simulate sudden process crashes.
    pub crash_interval: usize,
    /// Number of concurrent agent tasks in the merge-queue stress test.
    pub concurrent_agents: usize,
    /// Number of randomized adversarial fuzz probes per endpoint class.
    pub acl_fuzz_rounds: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 0x51A7_6178_2026_0001,
            oplog_ops: 200,
            crash_interval: 15,
            concurrent_agents: 32,
            acl_fuzz_rounds: 24,
        }
    }
}

/// Summary report produced by [`run_oplog_crash_recovery_sim`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpLogSimReport {
    pub seed: u64,
    pub total_ops_executed: usize,
    pub file_edits: usize,
    pub new_changesets: usize,
    pub lands: usize,
    pub reverts: usize,
    pub undos: usize,
    pub workspace_adds: usize,
    pub workspace_removes: usize,
    pub crash_recoveries: usize,
    pub final_oplog_len: usize,
    pub final_land_seq: u64,
    pub verified_blobs: usize,
}

/// Summary report produced by [`run_acl_secret_leak_fuzzer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclFuzzReport {
    pub seed: u64,
    pub canaries_planted: usize,
    pub total_http_probes: usize,
    pub cloned_git_objects_inspected: usize,
    pub cloned_files_inspected: usize,
    pub git_fsck_passed: bool,
    pub leaks_detected: usize,
}

/// Summary report produced by [`run_concurrent_merge_queue_stress`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeQueueStressReport {
    pub agent_count: usize,
    pub batch_landed: usize,
    pub conflicts: usize,
    pub rejected: usize,
    pub land_seqs: Vec<u64>,
    pub rust_functions_verified: usize,
    pub json_keys_verified: usize,
}

// ---------------------------------------------------------------------------
// Internal live-server harness for hermetic simulations
// ---------------------------------------------------------------------------

pub(crate) struct LiveTestServer {
    pub(crate) addr: SocketAddr,
    _tmp: TempDir,
    handle: JoinHandle<()>,
}

impl LiveTestServer {
    pub(crate) async fn start(default_acl: Option<&str>) -> Result<Self> {
        let tmp = TempDir::new()?;
        let mut config = ServerConfig::new(tmp.path());
        if let Some(acl) = default_acl {
            config = config.with_default_acl(acl);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = serve(listener, config).await;
        });
        Ok(Self {
            addr,
            _tmp: tmp,
            handle,
        })
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for LiveTestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn sim_err(msg: impl Into<String>) -> GitxError {
    GitxError::Storage(msg.into())
}

// ---------------------------------------------------------------------------
// 1. OpLog & Crash-Recovery Deterministic Simulator
// ---------------------------------------------------------------------------

/// Runs randomized repository operations against a durable [`LocalStore`], periodically
/// dropping and reopening the store from disk to simulate sudden crashes, verifying
/// zero corruption, exact OpLog restoration, and strictly monotonic `land_seq`.
pub fn run_oplog_crash_recovery_sim(config: &SimConfig) -> Result<OpLogSimReport> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let tmp = TempDir::new()?;
    let store_path = tmp.path().to_path_buf();
    let mut store = LocalStore::open(&store_path)?;

    let author = Identity {
        name: "SimRunner".to_string(),
        email: "sim@gitx.local".to_string(),
        key_fingerprint: Some("fp-sim-0001".to_string()),
    };

    let file_pool = [
        "src/lib.rs",
        "src/engine.rs",
        "src/storage.rs",
        "src/network.rs",
        "src/merge.rs",
        "src/cli.rs",
        "config/settings.json",
        "config/policy.toml",
        "README.md",
        "docs/architecture.md",
    ];

    // Shadow state verified after every simulated crash.
    let mut expected_oplog: Vec<OpLogEntry> = Vec::new();
    let mut expected_bookmarks: BTreeMap<String, ObjectHash> = BTreeMap::new();
    let mut expected_workspaces: BTreeMap<String, WorkspaceRef> = BTreeMap::new();
    let mut expected_change_heads: BTreeMap<ChangeId, ObjectHash> = BTreeMap::new();
    let mut expected_lands: Vec<LandRecord> = Vec::new();
    let mut cs_files: HashMap<ObjectHash, BTreeMap<String, Vec<u8>>> = HashMap::new();
    let mut last_land_seq: u64 = 0;

    // Seed initial root ChangeSet, `master` bookmark, `default` workspace, and Init OpLog entry.
    let mut init_files = BTreeMap::new();
    init_files.insert(
        "src/lib.rs".to_string(),
        b"pub fn root_init() -> u64 { 0 }\n".to_vec(),
    );
    init_files.insert(
        "README.md".to_string(),
        b"# Deterministic Simulation Repo\n".to_vec(),
    );

    let root_cs = write_changeset_from_files(
        &store,
        &author,
        ChangeId::new(),
        None,
        Vec::new(),
        &init_files,
        "Initial simulation root",
    )?;
    cs_files.insert(root_cs.id, init_files);
    expected_change_heads.insert(root_cs.change_id, root_cs.id);

    let init_land = store.record_land("master", None, root_cs.id, vec![root_cs.change_id])?;
    if init_land.land_seq <= last_land_seq {
        return Err(sim_err("initial land_seq was not positive"));
    }
    last_land_seq = init_land.land_seq;
    expected_lands.push(init_land);
    expected_bookmarks.insert("master".to_string(), root_cs.id);

    let default_ws = WorkspaceRef {
        name: "default".to_string(),
        root_path: Some("/sim/workspaces/default".to_string()),
        backend: WorkspaceBackendKind::CopyOnWrite,
        head_changeset: root_cs.id,
        head_change_id: root_cs.change_id,
    };
    store.put_workspace(&default_ws)?;
    expected_workspaces.insert(default_ws.name.clone(), default_ws);

    let init_op = OpLogEntry {
        id: OpId::new(),
        parent: None,
        timestamp: Utc::now(),
        kind: OpKind::Init,
        summary: "init simulation repository".to_string(),
        bookmarks: expected_bookmarks.clone(),
        workspaces: expected_workspaces.clone(),
        change_heads: expected_change_heads.clone(),
    };
    store.append_op(&init_op)?;
    expected_oplog.push(init_op);

    let mut report = OpLogSimReport {
        seed: config.seed,
        total_ops_executed: 0,
        file_edits: 0,
        new_changesets: 0,
        lands: 0,
        reverts: 0,
        undos: 0,
        workspace_adds: 0,
        workspace_removes: 0,
        crash_recoveries: 0,
        final_oplog_len: 0,
        final_land_seq: last_land_seq,
        verified_blobs: 0,
    };

    let mut ws_counter: u64 = 1;
    let crash_every = config.crash_interval.max(1);

    for step in 0..config.oplog_ops {
        let roll: u8 = rng.gen_range(0..100);

        // Choose operation across all 6 required categories:
        //   0..30  -> file edit (amend active workspace ChangeSet)
        //  30..50  -> new ChangeSet
        //  50..68  -> land onto master
        //  68..78  -> O(1) revert of a prior land
        //  78..88  -> OpLog undo restore
        //  88..95  -> workspace add
        //  95..100 -> workspace remove (or add if only `default` exists)
        if roll < 30 {
            // File edit in a randomly chosen active workspace
            let ws_names: Vec<String> = expected_workspaces.keys().cloned().collect();
            let ws_name = ws_names[rng.gen_range(0..ws_names.len())].clone();
            let mut ws = expected_workspaces[&ws_name].clone();

            let mut files = cs_files
                .get(&ws.head_changeset)
                .cloned()
                .unwrap_or_default();
            let path = file_pool[rng.gen_range(0..file_pool.len())].to_string();
            let val: u64 = rng.r#gen();
            let content = format!(
                "// step={step} ws={ws_name} token={val:016x}\npub fn f_{step}() -> u64 {{ {val} }}\n"
            );
            files.insert(path, content.into_bytes());

            let prev_cs = store.get_changeset(ws.head_changeset)?;
            let amended = write_changeset_from_files(
                &store,
                &author,
                ws.head_change_id,
                Some(ws.head_changeset),
                prev_cs.parents,
                &files,
                &format!("Edit step {step} in workspace {ws_name}"),
            )?;
            cs_files.insert(amended.id, files);
            expected_change_heads.insert(amended.change_id, amended.id);

            ws.head_changeset = amended.id;
            store.put_workspace(&ws)?;
            expected_workspaces.insert(ws_name.clone(), ws);

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::Snapshot {
                    workspace: ws_name.clone(),
                },
                format!("snapshot edit step {step} in {ws_name}"),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.file_edits += 1;
        } else if roll < 50 {
            // Create a brand new ChangeSet parented on current master head
            let ws_names: Vec<String> = expected_workspaces.keys().cloned().collect();
            let ws_name = ws_names[rng.gen_range(0..ws_names.len())].clone();
            let mut ws = expected_workspaces[&ws_name].clone();

            let master_head = expected_bookmarks["master"];
            let mut files = cs_files.get(&master_head).cloned().unwrap_or_default();
            let path = file_pool[rng.gen_range(0..file_pool.len())].to_string();
            let val: u64 = rng.r#gen();
            let content = format!(
                "// new-cs step={step} token={val:016x}\npub fn cs_{step}() -> u64 {{ {val} }}\n"
            );
            files.insert(path, content.into_bytes());

            let new_change_id = ChangeId::new();
            let cs = write_changeset_from_files(
                &store,
                &author,
                new_change_id,
                None,
                vec![master_head],
                &files,
                &format!("New changeset at step {step}"),
            )?;
            cs_files.insert(cs.id, files);
            expected_change_heads.insert(cs.change_id, cs.id);

            ws.head_changeset = cs.id;
            ws.head_change_id = cs.change_id;
            store.put_workspace(&ws)?;
            expected_workspaces.insert(ws_name.clone(), ws);

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::NewChange {
                    change_id: cs.change_id,
                },
                format!("new changeset {} at step {step}", cs.change_id.short()),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.new_changesets += 1;
        } else if roll < 68 {
            // Land a ChangeSet onto `master` via atomic CAS `record_land`
            let master_head = expected_bookmarks["master"];
            let candidate_ws = expected_workspaces
                .values()
                .find(|w| w.head_changeset != master_head)
                .cloned();

            let land_cs = if let Some(ws) = candidate_ws {
                store.get_changeset(ws.head_changeset)?
            } else {
                let mut files = cs_files.get(&master_head).cloned().unwrap_or_default();
                let path = file_pool[rng.gen_range(0..file_pool.len())].to_string();
                let val: u64 = rng.r#gen();
                files.insert(
                    path,
                    format!("// direct-land step={step} token={val:016x}\n").into_bytes(),
                );
                let cs = write_changeset_from_files(
                    &store,
                    &author,
                    ChangeId::new(),
                    None,
                    vec![master_head],
                    &files,
                    &format!("Direct land step {step}"),
                )?;
                cs_files.insert(cs.id, files);
                expected_change_heads.insert(cs.change_id, cs.id);
                cs
            };

            let rec = store.record_land(
                "master",
                Some(master_head),
                land_cs.id,
                vec![land_cs.change_id],
            )?;
            if rec.land_seq <= last_land_seq {
                return Err(sim_err(format!(
                    "non-monotonic land_seq: got {}, previous {}",
                    rec.land_seq, last_land_seq
                )));
            }
            last_land_seq = rec.land_seq;
            expected_lands.push(rec.clone());
            expected_bookmarks.insert("master".to_string(), land_cs.id);

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::Land {
                    target: "master".to_string(),
                    land_seq: rec.land_seq,
                    changes: rec.landed_changes,
                },
                format!("land seq {} at step {step}", rec.land_seq),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.lands += 1;
        } else if roll < 78 {
            // O(1) revert of a non-reverted land record that has a previous_head
            let revertible_idx: Vec<usize> = expected_lands
                .iter()
                .enumerate()
                .filter(|(_, l)| l.reverted_by.is_none() && l.previous_head.is_some())
                .map(|(idx, _)| idx)
                .collect();

            if let Some(&idx) = revertible_idx.last() {
                let target_land = expected_lands[idx].clone();
                let restore_head = target_land
                    .previous_head
                    .expect("filtered for Some(previous_head)");
                let current_master = expected_bookmarks["master"];

                let rev_rec = store.record_land(
                    "master",
                    Some(current_master),
                    restore_head,
                    Vec::new(),
                )?;
                if rev_rec.land_seq <= last_land_seq {
                    return Err(sim_err(format!(
                        "non-monotonic revert land_seq: got {}, previous {}",
                        rev_rec.land_seq, last_land_seq
                    )));
                }
                store.mark_reverted(target_land.land_seq, rev_rec.land_seq)?;
                last_land_seq = rev_rec.land_seq;
                expected_lands[idx].reverted_by = Some(rev_rec.land_seq);
                expected_lands.push(rev_rec.clone());
                expected_bookmarks.insert("master".to_string(), restore_head);

                append_sim_op(
                    &store,
                    &mut expected_oplog,
                    OpKind::Revert {
                        land_seq: target_land.land_seq,
                    },
                    format!(
                        "revert land_seq {} via {} at step {step}",
                        target_land.land_seq, rev_rec.land_seq
                    ),
                    &expected_bookmarks,
                    &expected_workspaces,
                    &expected_change_heads,
                )?;
                report.reverts += 1;
            } else {
                // Fallback to a land if no revertible land exists yet
                let master_head = expected_bookmarks["master"];
                let mut files = cs_files.get(&master_head).cloned().unwrap_or_default();
                let val: u64 = rng.r#gen();
                files.insert(
                    "src/lib.rs".to_string(),
                    format!("pub fn fallback_land_{step}() -> u64 {{ {val} }}\n").into_bytes(),
                );
                let cs = write_changeset_from_files(
                    &store,
                    &author,
                    ChangeId::new(),
                    None,
                    vec![master_head],
                    &files,
                    &format!("Pre-revert land step {step}"),
                )?;
                cs_files.insert(cs.id, files);
                expected_change_heads.insert(cs.change_id, cs.id);

                let rec = store.record_land("master", Some(master_head), cs.id, vec![cs.change_id])?;
                if rec.land_seq <= last_land_seq {
                    return Err(sim_err("non-monotonic fallback land_seq"));
                }
                last_land_seq = rec.land_seq;
                expected_lands.push(rec.clone());
                expected_bookmarks.insert("master".to_string(), cs.id);

                append_sim_op(
                    &store,
                    &mut expected_oplog,
                    OpKind::Land {
                        target: "master".to_string(),
                        land_seq: rec.land_seq,
                        changes: rec.landed_changes,
                    },
                    format!("land seq {} at step {step}", rec.land_seq),
                    &expected_bookmarks,
                    &expected_workspaces,
                    &expected_change_heads,
                )?;
                report.lands += 1;
            }
        } else if roll < 88 {
            // OpLog undo restore to a prior state snapshot
            let lookback = rng.gen_range(1..=expected_oplog.len().min(6));
            let target_op = expected_oplog[expected_oplog.len() - lookback].clone();

            // Restore bookmarks to target_op snapshot
            for (name, &hash) in &target_op.bookmarks {
                store.set_bookmark(name, hash)?;
            }
            expected_bookmarks = target_op.bookmarks.clone();

            // Restore workspaces to target_op snapshot (remove extras, restore missing/changed)
            let current_ws_names: Vec<String> = expected_workspaces.keys().cloned().collect();
            for name in current_ws_names {
                if !target_op.workspaces.contains_key(&name) {
                    store.remove_workspace(&name)?;
                }
            }
            for ws in target_op.workspaces.values() {
                store.put_workspace(ws)?;
            }
            expected_workspaces = target_op.workspaces.clone();
            expected_change_heads = target_op.change_heads.clone();

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::Undo {
                    target_op: target_op.id,
                },
                format!("undo restore to op {:?} at step {step}", target_op.id.0),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.undos += 1;
        } else if roll < 95 || expected_workspaces.len() <= 1 {
            // Add a new workspace pointing at current `master` head
            let master_head = expected_bookmarks["master"];
            let master_cs = store.get_changeset(master_head)?;
            let name = format!("ws-sim-{ws_counter}");
            ws_counter += 1;
            let backend = match rng.gen_range(0..3) {
                0 => WorkspaceBackendKind::Memory,
                1 => WorkspaceBackendKind::CopyOnWrite,
                _ => WorkspaceBackendKind::LazyMount,
            };
            let ws = WorkspaceRef {
                name: name.clone(),
                root_path: match backend {
                    WorkspaceBackendKind::Memory => None,
                    _ => Some(format!("/sim/workspaces/{name}")),
                },
                backend,
                head_changeset: master_cs.id,
                head_change_id: master_cs.change_id,
            };
            store.put_workspace(&ws)?;
            expected_workspaces.insert(name.clone(), ws);

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::WorkspaceCreate { name: name.clone() },
                format!("create workspace {name} at step {step}"),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.workspace_adds += 1;
        } else {
            // Remove a non-default workspace
            let removable: Vec<String> = expected_workspaces
                .keys()
                .filter(|k| k.as_str() != "default")
                .cloned()
                .collect();
            let chosen = removable[rng.gen_range(0..removable.len())].clone();
            store.remove_workspace(&chosen)?;
            expected_workspaces.remove(&chosen);

            append_sim_op(
                &store,
                &mut expected_oplog,
                OpKind::WorkspaceRemove {
                    name: chosen.clone(),
                },
                format!("remove workspace {chosen} at step {step}"),
                &expected_bookmarks,
                &expected_workspaces,
                &expected_change_heads,
            )?;
            report.workspace_removes += 1;
        }

        report.total_ops_executed += 1;

        // Periodically drop & reopen LocalStore to simulate crashes and verify full invariants.
        if (step + 1) % crash_every == 0 || step + 1 == config.oplog_ops {
            drop(store);
            store = LocalStore::open(&store_path)?;
            report.crash_recoveries += 1;

            let blobs_checked = verify_store_invariants(
                &store,
                &expected_oplog,
                &expected_bookmarks,
                &expected_workspaces,
                &expected_lands,
                &cs_files,
            )?;
            report.verified_blobs += blobs_checked;
        }
    }

    report.final_oplog_len = expected_oplog.len();
    report.final_land_seq = last_land_seq;
    Ok(report)
}

fn write_changeset_from_files(
    store: &dyn ObjectStore,
    author: &Identity,
    change_id: ChangeId,
    previous_revision: Option<ObjectHash>,
    parents: Vec<ObjectHash>,
    files: &BTreeMap<String, Vec<u8>>,
    description: &str,
) -> Result<ChangeSet> {
    let mut tree = DomainTree::new(DomainId::public());
    for (path, bytes) in files {
        let blob = store.put_blob_bytes(bytes)?;
        tree.insert(
            path.clone(),
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }
    let tree_hash = store.put_tree(&tree)?;
    let cs = ChangeSetBuilder::new(author.clone())
        .change_id(change_id)
        .previous_revision(previous_revision)
        .parents(parents)
        .domain_tree(DomainId::public(), tree_hash)
        .description(description)
        .build();
    store.put_changeset(&cs)?;
    Ok(cs)
}

fn append_sim_op(
    store: &dyn ObjectStore,
    expected_oplog: &mut Vec<OpLogEntry>,
    kind: OpKind,
    summary: String,
    bookmarks: &BTreeMap<String, ObjectHash>,
    workspaces: &BTreeMap<String, WorkspaceRef>,
    change_heads: &BTreeMap<ChangeId, ObjectHash>,
) -> Result<()> {
    let parent = expected_oplog.last().map(|op| op.id);
    let entry = OpLogEntry {
        id: OpId::new(),
        parent,
        timestamp: Utc::now(),
        kind,
        summary,
        bookmarks: bookmarks.clone(),
        workspaces: workspaces.clone(),
        change_heads: change_heads.clone(),
    };
    store.append_op(&entry)?;
    expected_oplog.push(entry);
    Ok(())
}

fn verify_store_invariants(
    store: &LocalStore,
    expected_oplog: &[OpLogEntry],
    expected_bookmarks: &BTreeMap<String, ObjectHash>,
    expected_workspaces: &BTreeMap<String, WorkspaceRef>,
    expected_lands: &[LandRecord],
    cs_files: &HashMap<ObjectHash, BTreeMap<String, Vec<u8>>>,
) -> Result<usize> {
    // 1. Exact OpLog restoration
    let persisted_ops_desc = store.list_ops(usize::MAX)?;
    if persisted_ops_desc.len() != expected_oplog.len() {
        return Err(sim_err(format!(
            "oplog length mismatch after crash: expected {}, got {}",
            expected_oplog.len(),
            persisted_ops_desc.len()
        )));
    }
    for (persisted, expected) in persisted_ops_desc.iter().zip(expected_oplog.iter().rev()) {
        if persisted != expected {
            return Err(sim_err(format!(
                "oplog entry mismatch after crash: expected {:?}, got {:?}",
                expected.id, persisted.id
            )));
        }
    }
    if store.latest_op()?.as_ref() != expected_oplog.last() {
        return Err(sim_err("latest_op mismatch after crash recovery"));
    }

    // 2. Bookmarks and Workspaces restoration
    let actual_bookmarks = store.list_bookmarks()?;
    if &actual_bookmarks != expected_bookmarks {
        return Err(sim_err(format!(
            "bookmarks mismatch after crash: expected {expected_bookmarks:?}, got {actual_bookmarks:?}"
        )));
    }

    let actual_workspaces = store.list_workspaces()?;
    if &actual_workspaces != expected_workspaces {
        return Err(sim_err(format!(
            "workspaces mismatch after crash: expected {expected_workspaces:?}, got {actual_workspaces:?}"
        )));
    }

    // 3. Land ledger strictly monotonic & intact
    let actual_lands_desc = store.list_lands("master", usize::MAX)?;
    if actual_lands_desc.len() != expected_lands.len() {
        return Err(sim_err(format!(
            "land ledger count mismatch after crash: expected {}, got {}",
            expected_lands.len(),
            actual_lands_desc.len()
        )));
    }
    let mut prev_seq = u64::MAX;
    for (actual, expected) in actual_lands_desc.iter().zip(expected_lands.iter().rev()) {
        if actual.land_seq >= prev_seq {
            return Err(sim_err(format!(
                "land_seq not strictly monotonic: {} >= {}",
                actual.land_seq, prev_seq
            )));
        }
        prev_seq = actual.land_seq;
        if actual.land_seq != expected.land_seq
            || actual.previous_head != expected.previous_head
            || actual.new_head != expected.new_head
            || actual.reverted_by != expected.reverted_by
        {
            return Err(sim_err(format!(
                "land record mismatch for seq {}",
                expected.land_seq
            )));
        }
    }

    // 4. Verify CAS blob integrity for every file in the current `master` head tree
    let mut verified_blobs = 0usize;
    let master_hash = expected_bookmarks["master"];
    let master_cs = store.get_changeset(master_hash)?;
    let pub_tree_hash = master_cs
        .domain_trees
        .get(&DomainId::public())
        .ok_or_else(|| sim_err("master changeset missing public domain tree"))?;
    let pub_tree = store.get_tree(*pub_tree_hash)?;
    let expected_map = cs_files
        .get(&master_hash)
        .ok_or_else(|| sim_err("shadow map missing master changeset files"))?;

    if pub_tree.entries.len() != expected_map.len() {
        return Err(sim_err(format!(
            "master tree entry count mismatch: expected {}, got {}",
            expected_map.len(),
            pub_tree.entries.len()
        )));
    }
    for (path, expected_bytes) in expected_map {
        let Some(EntryKind::File { blob_hash, .. }) = pub_tree.entries.get(path) else {
            return Err(sim_err(format!(
                "missing file '{path}' in master tree after crash"
            )));
        };
        let actual_bytes = store.read_blob_bytes(*blob_hash)?;
        if &actual_bytes != expected_bytes {
            return Err(sim_err(format!(
                "blob corruption detected for '{path}' after crash"
            )));
        }
        verified_blobs += 1;
    }

    Ok(verified_blobs)
}

// ---------------------------------------------------------------------------
// 2. Adversarial ACL & Secret-Leak Fuzzer
// ---------------------------------------------------------------------------

/// Populates a live `gitx-server` with random canary tokens across `secret:prod`, `team:core`,
/// `embargo:cve-2026-sim`, and private `team:core` context prompts, warms the server's derived
/// indices via authorized calls, then exhaustively attacks EVERY anonymous endpoint AND runs a
/// real `git clone http://...` + `git fsck --full --strict`, asserting ZERO canary leaks.
pub async fn run_acl_secret_leak_fuzzer(config: &SimConfig) -> Result<AclFuzzReport> {
    let mut rng = StdRng::seed_from_u64(config.seed ^ 0x0AC1_F022_DEAD_BEEF);

    let secret_canary = format!(
        "CANARY_SECRET_PROD_{:016x}{:016x}",
        rng.r#gen::<u64>(),
        rng.r#gen::<u64>()
    );
    let team_canary = format!(
        "CANARY_TEAM_CORE_{:016x}{:016x}",
        rng.r#gen::<u64>(),
        rng.r#gen::<u64>()
    );
    let embargo_canary = format!(
        "CANARY_EMBARGO_CVE_{:016x}{:016x}",
        rng.r#gen::<u64>(),
        rng.r#gen::<u64>()
    );
    let prompt_canary = format!(
        "CANARY_PRIVATE_PROMPT_{:016x}{:016x}",
        rng.r#gen::<u64>(),
        rng.r#gen::<u64>()
    );
    let secret_msg_canary = format!("CANARY_MSG_SECRET_{:016x}", rng.r#gen::<u64>());
    let team_msg_canary = format!("CANARY_MSG_TEAM_{:016x}", rng.r#gen::<u64>());
    let embargo_msg_canary = format!("CANARY_MSG_EMBARGO_{:016x}", rng.r#gen::<u64>());

    let all_canaries = vec![
        secret_canary.clone(),
        team_canary.clone(),
        embargo_canary.clone(),
        prompt_canary.clone(),
        secret_msg_canary.clone(),
        team_msg_canary.clone(),
        embargo_msg_canary.clone(),
    ];

    let acl_policy = "\
.env -> secret:prod read=role:admin write=role:admin
packages/private/** -> team:core read=team:core,role:admin write=team:core,role:admin
";

    let srv = LiveTestServer::start(Some(acl_policy)).await?;
    let client = Client::new();

    // 1. Public base commit
    let c_public_1: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/vault/commit"),
        &[("X-Gitx-User", "alice")],
        &json!({
            "files": {
                ".gitxacl": acl_policy,
                "src/lib.rs": "pub fn public_api() -> &'static str {\n    \"public-ok\"\n}\n",
                "README.md": "# Public Vault Repo\n"
            },
            "message": "Initial public release",
            "author_name": "Alice",
            "author_email": "alice@acme.dev",
            "context_prompt": "Initialize the public API surface"
        }),
    )
    .await?;

    // 2. Secret production `.env` commit (`secret:prod`)
    let c_secret: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/vault/commit"),
        &[("X-Gitx-User", "secadmin"), ("X-Gitx-Roles", "admin")],
        &json!({
            "files": {
                ".env": format!("DATABASE_URL=postgres://prod:{secret_canary}@db.internal/app\n")
            },
            "visibility_domain": "secret:prod",
            "message": format!("Rotate production credentials {secret_msg_canary}"),
            "author_name": "SecAdmin",
            "author_email": "secadmin@acme.dev"
        }),
    )
    .await?;

    // 3. Private `team:core` code + private `team:core` context prompt
    let c_team: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/vault/commit"),
        &[("X-Gitx-User", "core-dev"), ("X-Gitx-Teams", "core")],
        &json!({
            "files": {
                "packages/private/internal.rs": format!(
                    "pub fn internal_secret() -> &'static str {{\n    \"{team_canary}\"\n}}\n"
                )
            },
            "message": format!("Internal core engine logic {team_msg_canary}"),
            "author_name": "CoreDev",
            "author_email": "core@acme.dev",
            "context_prompt": format!("Proprietary design note: {prompt_canary}")
        }),
    )
    .await?;

    // 4. Embargoed CVE patch (`embargo:cve-2026-sim`)
    let c_embargo: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/vault/commit"),
        &[
            ("X-Gitx-User", "sec-lead"),
            ("X-Gitx-Teams", "core"),
            ("X-Gitx-Roles", "admin"),
        ],
        &json!({
            "files": {
                "src/security.rs": format!(
                    "pub fn mitigate_cve_2026() -> &'static str {{\n    \"{embargo_canary}\"\n}}\n"
                )
            },
            "embargo_advisory": "cve-2026-sim",
            "embargo_allowed_teams": ["core"],
            "message": format!("Embargoed CVE-2026-SIM fix {embargo_msg_canary}"),
            "author_name": "SecLead",
            "author_email": "seclead@acme.dev",
            "context_prompt": format!("Embargo rationale {embargo_canary}")
        }),
    )
    .await?;

    // 5. Follow-up public commit so public history has multiple revisions over the protected data
    let c_public_2: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/vault/commit"),
        &[("X-Gitx-User", "alice")],
        &json!({
            "files": {
                "src/lib.rs": "pub fn public_api() -> &'static str {\n    \"public-ok\"\n}\n\npub fn public_v2() -> u32 {\n    2\n}\n"
            },
            "message": "Add public_v2 helper",
            "author_name": "Alice",
            "author_email": "alice@acme.dev"
        }),
    )
    .await?;

    // Warm derived indices (TrigramIndex, CommitGraphIndex, PathHistoryIndex) as an authorized
    // admin+core caller, AND sanity-check that authorized callers DO observe the canaries!
    let auth_headers = [
        ("X-Gitx-User", "sec-lead"),
        ("X-Gitx-Teams", "core"),
        ("X-Gitx-Roles", "admin"),
    ];
    let auth_tree = get_text(&client, &srv.url("/v1/repos/acme/vault/tree"), &auth_headers).await?;
    for required in [&secret_canary, &team_canary] {
        if !auth_tree.contains(required) {
            return Err(sim_err(format!(
                "authorized admin/core tree did not contain planted canary {required}"
            )));
        }
    }
    let auth_embargo_tree = get_text(
        &client,
        &srv.url(&format!(
            "/v1/repos/acme/vault/tree?rev={}",
            c_embargo.changeset_id
        )),
        &auth_headers,
    )
    .await?;
    if !auth_embargo_tree.contains(&embargo_canary) {
        return Err(sim_err(format!(
            "authorized admin/core embargo tree did not contain planted canary {embargo_canary}"
        )));
    }
    let auth_why = get_text(
        &client,
        &srv.url("/v1/repos/acme/vault/why?path=packages/private/internal.rs&line=1"),
        &[
            ("X-Gitx-User", "core-dev"),
            ("X-Gitx-Teams", "core"),
            ("X-Gitx-Roles", "admin"),
        ],
    )
    .await?;
    if !auth_why.contains(&prompt_canary) {
        return Err(sim_err(
            "authorized team:core /why did not contain planted private prompt canary",
        ));
    }
    for warm_url in [
        format!("/v1/repos/acme/vault/grep?q={secret_canary}"),
        format!("/v1/repos/acme/vault/grep?q={team_canary}"),
        format!(
            "/v1/repos/acme/vault/grep?q={embargo_canary}&rev={}",
            c_embargo.changeset_id
        ),
        "/v1/repos/acme/vault/blame?path=.env".to_string(),
        "/v1/repos/acme/vault/blame?path=packages/private/internal.rs".to_string(),
        format!(
            "/v1/repos/acme/vault/blame?path=src/security.rs&rev={}",
            c_embargo.changeset_id
        ),
    ] {
        let _ = get_text(&client, &srv.url(&warm_url), &auth_headers).await?;
    }

    // Build exhaustive + randomized anonymous attack matrix covering EVERY endpoint.
    let sensitive_revs = [
        c_secret.changeset_id.as_str(),
        c_team.changeset_id.as_str(),
        c_embargo.changeset_id.as_str(),
        c_public_1.changeset_id.as_str(),
        c_public_2.changeset_id.as_str(),
    ];
    let sensitive_domains = ["public", "secret:prod", "team:core", "embargo:cve-2026-sim"];
    let sensitive_paths = [
        ".env",
        "packages/private/internal.rs",
        "src/security.rs",
        "src/lib.rs",
        "README.md",
    ];

    let mut attack_urls: Vec<String> = Vec::new();

    // /tree attacks
    attack_urls.push("/v1/repos/acme/vault/tree".to_string());
    for dom in sensitive_domains {
        attack_urls.push(format!("/v1/repos/acme/vault/tree?domain={dom}"));
    }
    for rev in sensitive_revs {
        attack_urls.push(format!("/v1/repos/acme/vault/tree?rev={rev}"));
    }

    // /grep attacks (full canaries, prefixes, case-insensitive, and sensitive revs)
    for canary in &all_canaries {
        attack_urls.push(format!("/v1/repos/acme/vault/grep?q={canary}"));
        attack_urls.push(format!(
            "/v1/repos/acme/vault/grep?q={}&case_insensitive=true",
            canary.to_lowercase()
        ));
    }
    for q in ["CANARY_", "DATABASE_URL", "internal_secret", "mitigate_cve"] {
        attack_urls.push(format!("/v1/repos/acme/vault/grep?q={q}"));
        for rev in &sensitive_revs[..3] {
            attack_urls.push(format!("/v1/repos/acme/vault/grep?q={q}&rev={rev}"));
        }
    }

    // /diff attacks across every pair involving sensitive revisions
    attack_urls.push("/v1/repos/acme/vault/diff".to_string());
    for &from in &sensitive_revs {
        for &to in &sensitive_revs {
            if from != to {
                attack_urls.push(format!("/v1/repos/acme/vault/diff?from={from}&to={to}"));
            }
        }
    }

    // /blame attacks
    for path in sensitive_paths {
        attack_urls.push(format!("/v1/repos/acme/vault/blame?path={path}"));
        for &rev in &sensitive_revs[..3] {
            attack_urls.push(format!("/v1/repos/acme/vault/blame?path={path}&rev={rev}"));
        }
    }

    // /log attacks
    attack_urls.push("/v1/repos/acme/vault/log?limit=100".to_string());
    for &rev in &sensitive_revs {
        attack_urls.push(format!("/v1/repos/acme/vault/log?rev={rev}&limit=100"));
    }

    // /why attacks
    for path in sensitive_paths {
        attack_urls.push(format!("/v1/repos/acme/vault/why?path={path}&line=1"));
        attack_urls.push(format!("/v1/repos/acme/vault/why?path={path}&line=2"));
        for &rev in &sensitive_revs[..3] {
            attack_urls.push(format!(
                "/v1/repos/acme/vault/why?path={path}&line=1&rev={rev}"
            ));
        }
    }

    // /derived/stats attack
    attack_urls.push("/v1/repos/acme/vault/derived/stats".to_string());

    // Randomized seeded fuzz rounds slicing random substrings of canaries and combining params
    for _ in 0..config.acl_fuzz_rounds {
        let canary = &all_canaries[rng.gen_range(0..all_canaries.len())];
        let max_start = canary.len().saturating_sub(8);
        let start = rng.gen_range(0..=max_start);
        let slice = &canary[start..start + 8];
        let rev = sensitive_revs[rng.gen_range(0..sensitive_revs.len())];
        let path = sensitive_paths[rng.gen_range(0..sensitive_paths.len())];
        let line = rng.gen_range(1..=4);

        attack_urls.push(format!("/v1/repos/acme/vault/grep?q={slice}&rev={rev}"));
        attack_urls.push(format!(
            "/v1/repos/acme/vault/why?path={path}&line={line}&rev={rev}"
        ));
    }

    for url_path in &attack_urls {
        let resp = client
            .get(srv.url(url_path))
            .send()
            .await
            .map_err(|e| sim_err(format!("HTTP probe failed for {url_path}: {e}")))?;
        let body = resp
            .text()
            .await
            .map_err(|e| sim_err(format!("reading response body for {url_path}: {e}")))?;

        // For `/grep` responses, strip the echoed `query` field before scanning for canaries
        // and explicitly assert that zero matches were returned to an anonymous caller.
        let body_to_scan = if url_path.contains("/grep?") {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(matches) = val.get("matches").and_then(|m| m.as_array())
                    && !matches.is_empty()
                {
                    return Err(sim_err(format!(
                        "ACL LEAK DETECTED: anonymous GET {url_path} returned {} grep matches: {body}",
                        matches.len()
                    )));
                }
                if let Some(obj) = val.as_object_mut() {
                    obj.remove("query");
                }
                val.to_string()
            } else {
                body.clone()
            }
        } else {
            body.clone()
        };

        for canary in &all_canaries {
            if body_to_scan.contains(canary) {
                return Err(sim_err(format!(
                    "ACL LEAK DETECTED: canary '{canary}' appeared in anonymous GET {url_path}"
                )));
            }
        }
    }

    // Extra structural assertions on anonymous `/tree` and `/derived/stats`
    let anon_tree: TreeResponse = client
        .get(srv.url("/v1/repos/acme/vault/tree"))
        .send()
        .await
        .map_err(|e| sim_err(format!("anonymous /tree failed: {e}")))?
        .error_for_status()
        .map_err(|e| sim_err(format!("anonymous /tree status error: {e}")))?
        .json()
        .await
        .map_err(|e| sim_err(format!("anonymous /tree decode: {e}")))?;
    for forbidden_path in [".env", "packages/private/internal.rs", "src/security.rs"] {
        if anon_tree.files.iter().any(|f| f.path == forbidden_path) {
            return Err(sim_err(format!(
                "ACL LEAK DETECTED: forbidden path '{forbidden_path}' visible in anonymous /tree"
            )));
        }
    }

    let anon_stats: DerivedStats = client
        .get(srv.url("/v1/repos/acme/vault/derived/stats"))
        .send()
        .await
        .map_err(|e| sim_err(format!("anonymous /derived/stats failed: {e}")))?
        .error_for_status()
        .map_err(|e| sim_err(format!("anonymous /derived/stats status error: {e}")))?
        .json()
        .await
        .map_err(|e| sim_err(format!("anonymous /derived/stats decode: {e}")))?;
    for dom in &anon_stats.trigram_domains {
        if dom != "public" {
            return Err(sim_err(format!(
                "ACL LEAK DETECTED: non-public domain '{dom}' exposed in anonymous /derived/stats"
            )));
        }
    }

    // Real `git clone http://...` + `git fsck --full --strict` + exhaustive Git object scan!
    let clone_tmp = TempDir::new()?;
    let clone_dir = clone_tmp.path().join("cloned-vault");
    let clone_url = srv.url("/acme/vault.git");

    let clone_out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["clone", "--quiet", &clone_url])
        .arg(&clone_dir)
        .output()
        .await?;
    if !clone_out.status.success() {
        return Err(sim_err(format!(
            "git clone failed: {}",
            String::from_utf8_lossy(&clone_out.stderr)
        )));
    }

    let fsck_out = Command::new("git")
        .arg("-C")
        .arg(&clone_dir)
        .args(["fsck", "--full", "--strict"])
        .output()
        .await?;
    if !fsck_out.status.success() {
        return Err(sim_err(format!(
            "git fsck --full --strict failed: {}",
            String::from_utf8_lossy(&fsck_out.stderr)
        )));
    }

    // Verify no protected files exist in the cloned working tree and scan every checked-out file.
    for forbidden_path in [".env", "packages/private/internal.rs", "src/security.rs"] {
        if clone_dir.join(forbidden_path).exists() {
            return Err(sim_err(format!(
                "ACL LEAK DETECTED: '{forbidden_path}' present in anonymous git clone"
            )));
        }
    }
    let cloned_files = collect_non_git_files(&clone_dir)?;
    for file_path in &cloned_files {
        let bytes = fs::read(file_path)?;
        let text = String::from_utf8_lossy(&bytes);
        for canary in &all_canaries {
            if text.contains(canary) {
                return Err(sim_err(format!(
                    "ACL LEAK DETECTED: canary '{canary}' found in cloned file {}",
                    file_path.display()
                )));
            }
        }
    }

    // Inspect EVERY Git object (commits, trees, blobs) reachable in the cloned repository!
    let rev_list_out = Command::new("git")
        .arg("-C")
        .arg(&clone_dir)
        .args(["rev-list", "--all", "--objects"])
        .output()
        .await?;
    if !rev_list_out.status.success() {
        return Err(sim_err(format!(
            "git rev-list failed: {}",
            String::from_utf8_lossy(&rev_list_out.stderr)
        )));
    }
    let rev_list_str = String::from_utf8_lossy(&rev_list_out.stdout);
    let mut objects_inspected = 0usize;
    for line in rev_list_str.lines() {
        let Some(oid) = line.split_whitespace().next() else {
            continue;
        };
        let cat_out = Command::new("git")
            .arg("-C")
            .arg(&clone_dir)
            .args(["cat-file", "-p", oid])
            .output()
            .await?;
        if !cat_out.status.success() {
            return Err(sim_err(format!("git cat-file -p {oid} failed")));
        }
        let obj_text = String::from_utf8_lossy(&cat_out.stdout);
        for canary in &all_canaries {
            if obj_text.contains(canary) {
                return Err(sim_err(format!(
                    "ACL LEAK DETECTED: canary '{canary}' found inside cloned Git object {oid}"
                )));
            }
        }
        objects_inspected += 1;
    }

    Ok(AclFuzzReport {
        seed: config.seed,
        canaries_planted: all_canaries.len(),
        total_http_probes: attack_urls.len() + 2,
        cloned_git_objects_inspected: objects_inspected,
        cloned_files_inspected: cloned_files.len(),
        git_fsck_passed: true,
        leaks_detected: 0,
    })
}

// ---------------------------------------------------------------------------
// 3. 32-Agent Concurrent AST + JSON Merge Queue Stress Test
// ---------------------------------------------------------------------------

/// Spawns `config.concurrent_agents` (default: 32) concurrent Tokio agent tasks against a live
/// `gitx-server`. Every agent appends a unique Rust function (`pub fn agent_<i>() -> usize { <i> }`)
/// to the bottom of the SAME `src/lib.rs` AND adds a unique key (`"agent_<i>": <i>`) to the SAME
/// `package.json`, enqueues onto `master`, and drains the batched merge queue — asserting ALL
/// functions and ALL JSON keys exist with ZERO conflicts and strictly monotonic `land_seq`.
pub async fn run_concurrent_merge_queue_stress(
    config: &SimConfig,
) -> Result<MergeQueueStressReport> {
    let agent_count = config.concurrent_agents.max(1);
    let srv = LiveTestServer::start(None).await?;
    let client = Client::new();

    let base_rust = "//! Concurrent AST merge stress target.\n\npub fn base_entry() -> usize {\n    9999\n}\n";
    let base_pkg = "{\n  \"name\": \"gitx-concurrent-swarm\",\n  \"version\": \"1.0.0\"\n}\n";

    let base: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/swarm32/commit"),
        &[("X-Gitx-User", "bootstrap")],
        &json!({
            "files": {
                "src/lib.rs": base_rust,
                "package.json": base_pkg
            },
            "message": "Seed base src/lib.rs and package.json",
            "author_name": "Bootstrap",
            "author_email": "bootstrap@acme.dev"
        }),
    )
    .await?;

    // Launch all concurrent agent tasks simultaneously!
    let mut tasks = JoinSet::new();
    for idx in 0..agent_count {
        let client = client.clone();
        let commit_url = srv.url("/v1/repos/acme/swarm32/commit");
        let enqueue_url = srv.url("/v1/repos/acme/swarm32/queue/enqueue");
        let base_id = base.changeset_id.clone();

        tasks.spawn(async move {
            let agent_name = format!("agent-{idx:02}");
            let rust_body = format!("{base_rust}\npub fn agent_{idx}() -> usize {{ {idx} }}\n");
            let pkg_body = format!(
                "{{\n  \"name\": \"gitx-concurrent-swarm\",\n  \"version\": \"1.0.0\",\n  \"agent_{idx}\": {idx}\n}}\n"
            );

            let cs: CommitResponse = post_json(
                &client,
                &commit_url,
                &[("X-Gitx-User", agent_name.as_str())],
                &json!({
                    "files": {
                        "src/lib.rs": rust_body,
                        "package.json": pkg_body
                    },
                    "parent": base_id,
                    "update_target": false,
                    "message": format!("Agent {idx} appends agent_{idx}() and package.json key"),
                    "author_name": format!("Agent {idx}"),
                    "author_email": format!("agent{idx}@acme.dev"),
                    "actor_agent": {
                        "harness": "gitx-sim",
                        "model": "sim-agent-v1",
                        "session_id": format!("sim-sess-{idx:02}")
                    }
                }),
            )
            .await?;

            let enq: EnqueueResponse = post_json(
                &client,
                &enqueue_url,
                &[("X-Gitx-User", agent_name.as_str())],
                &json!({
                    "changeset_id": cs.changeset_id,
                    "target": "master"
                }),
            )
            .await?;

            if enq.entry.status != QueueStatus::Pending {
                return Err(sim_err(format!(
                    "expected Pending status for agent {idx}, got {:?}",
                    enq.entry.status
                )));
            }
            Ok::<_, GitxError>(cs.changeset_id)
        });
    }

    let mut enqueued_ids = Vec::with_capacity(agent_count);
    while let Some(res) = tasks.join_next().await {
        let cs_id = res.map_err(|e| sim_err(format!("agent task panicked: {e}")))??;
        enqueued_ids.push(cs_id);
    }
    if enqueued_ids.len() != agent_count {
        return Err(sim_err("did not collect all concurrent agent commits"));
    }

    // Confirm queue depth before draining.
    let before_queue: QueueListResponse = client
        .get(srv.url("/v1/repos/acme/swarm32/queue?target=master&pending_only=true"))
        .header("X-Gitx-User", "merge-bot")
        .send()
        .await
        .map_err(|e| sim_err(format!("queue list failed: {e}")))?
        .error_for_status()
        .map_err(|e| sim_err(format!("queue list status error: {e}")))?
        .json()
        .await
        .map_err(|e| sim_err(format!("queue list decode: {e}")))?;
    if before_queue.pending_count != agent_count {
        return Err(sim_err(format!(
            "expected {} pending entries, got {}",
            agent_count, before_queue.pending_count
        )));
    }

    // Drain batch 1 (all 32 agents atomically in one transaction!)
    let drain_1: DrainResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/swarm32/queue/drain"),
        &[("X-Gitx-User", "merge-bot")],
        &json!({ "target": "master" }),
    )
    .await?;

    if drain_1.landed.len() != agent_count
        || !drain_1.conflicted.is_empty()
        || !drain_1.rejected.is_empty()
    {
        return Err(sim_err(format!(
            "batch 1 drain unexpected result: landed={}, conflicted={}, rejected={}",
            drain_1.landed.len(),
            drain_1.conflicted.len(),
            drain_1.rejected.len()
        )));
    }

    let seq_1 = drain_1
        .land_seq
        .ok_or_else(|| sim_err("drain 1 returned None land_seq"))?;
    let head_1 = drain_1
        .new_head
        .clone()
        .ok_or_else(|| sim_err("drain 1 returned None new_head"))?;

    // Inspect final master tree and verify ALL 32 functions & ALL 32 JSON keys!
    let tree: TreeResponse = client
        .get(srv.url("/v1/repos/acme/swarm32/tree"))
        .send()
        .await
        .map_err(|e| sim_err(format!("tree fetch failed: {e}")))?
        .error_for_status()
        .map_err(|e| sim_err(format!("tree status error: {e}")))?
        .json()
        .await
        .map_err(|e| sim_err(format!("tree decode: {e}")))?;

    let merged_rust = tree
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .and_then(|f| f.content.as_deref())
        .ok_or_else(|| sim_err("src/lib.rs missing from final master tree"))?;

    if merged_rust.contains("<<<<<<<") || merged_rust.contains(">>>>>>>") {
        return Err(sim_err(
            "conflict markers leaked into final merged src/lib.rs",
        ));
    }

    let mut rust_functions_verified = 0usize;
    for idx in 0..agent_count {
        let expected_fn = format!("pub fn agent_{idx}() -> usize {{ {idx} }}");
        if !merged_rust.contains(&expected_fn) {
            return Err(sim_err(format!(
                "missing expected function '{expected_fn}' in merged src/lib.rs"
            )));
        }
        rust_functions_verified += 1;
    }

    let merged_pkg_str = tree
        .files
        .iter()
        .find(|f| f.path == "package.json")
        .and_then(|f| f.content.as_deref())
        .ok_or_else(|| sim_err("package.json missing from final master tree"))?;
    let merged_pkg: Value = serde_json::from_str(merged_pkg_str)
        .map_err(|e| sim_err(format!("final package.json is invalid JSON: {e}")))?;

    let mut json_keys_verified = 0usize;
    for idx in 0..agent_count {
        let key = format!("agent_{idx}");
        if merged_pkg.get(&key).and_then(Value::as_u64) != Some(idx as u64) {
            return Err(sim_err(format!(
                "missing or wrong package.json key '{key}': got {:?}",
                merged_pkg.get(&key)
            )));
        }
        json_keys_verified += 1;
    }

    // Run a follow-up batch to verify strictly monotonic `land_seq` across drains (1 -> 2).
    let mut followup_pkg = merged_pkg
        .as_object()
        .cloned()
        .ok_or_else(|| sim_err("package.json root is not an object"))?;
    followup_pkg.insert("followup_sentinel".to_string(), json!(true));
    let followup_pkg_str = serde_json::to_string_pretty(&followup_pkg)
        .map_err(|e| sim_err(format!("serialize followup pkg: {e}")))?;
    let followup_rust = format!("{merged_rust}\npub fn followup_sentinel() -> usize {{ 777 }}\n");

    let followup_cs: CommitResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/swarm32/commit"),
        &[("X-Gitx-User", "agent-followup")],
        &json!({
            "files": {
                "src/lib.rs": followup_rust,
                "package.json": followup_pkg_str
            },
            "parent": head_1,
            "update_target": false,
            "message": "Follow-up batch for monotonic land_seq verification"
        }),
    )
    .await?;

    let _: EnqueueResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/swarm32/queue/enqueue"),
        &[("X-Gitx-User", "agent-followup")],
        &json!({
            "changeset_id": followup_cs.changeset_id,
            "target": "master"
        }),
    )
    .await?;

    let drain_2: DrainResponse = post_json(
        &client,
        &srv.url("/v1/repos/acme/swarm32/queue/drain"),
        &[("X-Gitx-User", "merge-bot")],
        &json!({ "target": "master" }),
    )
    .await?;

    let seq_2 = drain_2
        .land_seq
        .ok_or_else(|| sim_err("drain 2 returned None land_seq"))?;
    if seq_2 <= seq_1 {
        return Err(sim_err(format!(
            "land_seq not strictly monotonic across drains: {seq_1} -> {seq_2}"
        )));
    }

    Ok(MergeQueueStressReport {
        agent_count,
        batch_landed: drain_1.landed.len(),
        conflicts: drain_1.conflicted.len() + drain_2.conflicted.len(),
        rejected: drain_1.rejected.len() + drain_2.rejected.len(),
        land_seqs: vec![seq_1, seq_2],
        rust_functions_verified,
        json_keys_verified,
    })
}

// ---------------------------------------------------------------------------
// HTTP & Filesystem Helpers
// ---------------------------------------------------------------------------

async fn post_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    headers: &[(&str, &str)],
    payload: &Value,
) -> Result<T> {
    let mut req = client.post(url).json(payload);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| sim_err(format!("POST {url} failed: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(sim_err(format!("POST {url} returned {status}: {body}")));
    }
    resp.json::<T>()
        .await
        .map_err(|e| sim_err(format!("decode JSON from POST {url}: {e}")))
}

async fn get_text(client: &Client, url: &str, headers: &[(&str, &str)]) -> Result<String> {
    let mut req = client.get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| sim_err(format!("GET {url} failed: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| sim_err(format!("reading body from GET {url}: {e}")))?;
    if !status.is_success() {
        return Err(sim_err(format!("GET {url} returned {status}: {body}")));
    }
    Ok(body)
}

fn collect_non_git_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_non_git_files_rec(root, &mut files)?;
    Ok(files)
}

fn collect_non_git_files_rec(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_non_git_files_rec(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}
