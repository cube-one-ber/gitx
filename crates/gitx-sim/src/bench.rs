use crate::sim::LiveTestServer;
use gitx_core::{DomainId, DomainTree, EntryKind, FileMode, GitxError, Result};
use gitx_merge::{MergeOutcome, merge_bytes};
use gitx_server::{CommitResponse, DerivedStats, DiffResponse, GrepResponse};
use gitx_store::{LocalStore, ObjectStore};
use gitx_vfs::{CowWorkspace, LazyWorkspace, MemVfs, WorkspaceBackend};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tokio::process::Command;

/// Configuration controlling benchmark scales.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchConfig {
    /// Number of files generated in the synthetic repository (default: 250).
    pub repo_file_count: usize,
    /// Workspace fan-out counts to benchmark (default: `[8, 32]`).
    pub fanout_counts: Vec<usize>,
    /// Number of agents appending functions to the same `src/lib.rs` (default: 16).
    pub merge_agent_count: usize,
    /// Number of warm TrigramIndex grep iterations to average (default: 10).
    pub warm_grep_iterations: usize,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            repo_file_count: 250,
            fanout_counts: vec![8, 32],
            merge_agent_count: 16,
            warm_grep_iterations: 10,
        }
    }
}

/// Measured workspace fan-out metrics for a single scale (`8x`, `32x`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceFanOutResult {
    pub workspace_count: usize,
    pub repo_file_count: usize,
    pub git_worktree_ms: f64,
    pub git_worktree_files_written: usize,
    pub cow_workspace_ms: f64,
    pub cow_workspace_files_written: usize,
    pub lazy_workspace_ms: f64,
    pub lazy_workspace_files_written: usize,
    pub mem_vfs_ms: f64,
    pub mem_vfs_files_written: usize,
}

/// Measured multi-agent same-file merge results (baseline Git 3-way vs GitX AST merge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeBenchResult {
    pub agent_count: usize,
    pub total_merges: usize,
    pub git_line_merge_conflicts: usize,
    pub git_line_merge_ms: f64,
    pub gitx_ast_merge_conflicts: usize,
    pub gitx_ast_merge_ms: f64,
}

/// Measured zero-clone server grep & diff latency vs full local `git clone` + grep/diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerQueryBenchResult {
    pub repo_file_count: usize,
    pub git_clone_and_grep_ms: f64,
    pub git_local_diff_ms: f64,
    pub gitx_cold_grep_ms: f64,
    pub gitx_warm_grep_ms: f64,
    pub gitx_zero_clone_diff_ms: f64,
    pub warm_trigram_cache_hits: u64,
}

/// Complete structured benchmark report returned by [`run_benchmarks`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub workspace_fanout: Vec<WorkspaceFanOutResult>,
    pub same_file_merge: MergeBenchResult,
    pub server_query: ServerQueryBenchResult,
}

fn bench_err(msg: impl Into<String>) -> GitxError {
    GitxError::Storage(msg.into())
}

/// Run the full GitX-vs-Git benchmark suite using default parameters:
/// - 8x and 32x workspace fan-out on a 250-file repo
/// - 16-agent same-file Rust merge (baseline Git line merge vs GitX Tree-sitter AST merge)
/// - Zero-clone server grep (cold vs warm `TrigramIndex`) & diff vs full `git clone` + grep
pub async fn run_benchmarks() -> Result<BenchReport> {
    run_benchmarks_with_config(&BenchConfig::default()).await
}

/// Run the GitX-vs-Git benchmark suite with custom scale parameters.
pub async fn run_benchmarks_with_config(config: &BenchConfig) -> Result<BenchReport> {
    let synthetic_files = generate_synthetic_repo_files(config.repo_file_count);

    let mut workspace_fanout = Vec::with_capacity(config.fanout_counts.len());
    for &count in &config.fanout_counts {
        let res = bench_workspace_fanout(&synthetic_files, count).await?;
        workspace_fanout.push(res);
    }

    let same_file_merge = bench_multi_agent_same_file_merge(config.merge_agent_count).await?;
    let server_query =
        bench_zero_clone_server_grep_and_diff(&synthetic_files, config.warm_grep_iterations)
            .await?;

    Ok(BenchReport {
        workspace_fanout,
        same_file_merge,
        server_query,
    })
}

/// Format a [`BenchReport`] as a clean Markdown summary table suitable for CLI or PR output.
pub fn format_markdown_report(report: &BenchReport) -> String {
    let mut out = String::new();
    out.push_str("# GitX vs Git Benchmark Report\n\n");

    // 1. Workspace Fan-Out
    out.push_str("## 1. Workspace Fan-Out\n\n");
    out.push_str(
        "| Scale | Backend | Wall-Clock (ms) | Working Files Written to Disk | Speedup vs Git |\n",
    );
    out.push_str("| --- | --- | ---: | ---: | ---: |\n");
    for row in &report.workspace_fanout {
        let scale = format!("{}x ({} files)", row.workspace_count, row.repo_file_count);
        let cow_speedup = safe_speedup(row.git_worktree_ms, row.cow_workspace_ms);
        let lazy_speedup = safe_speedup(row.git_worktree_ms, row.lazy_workspace_ms);
        let mem_speedup = safe_speedup(row.git_worktree_ms, row.mem_vfs_ms);

        out.push_str(&format!(
            "| {scale} | Git (`git worktree add`) | {:.2} | {} | 1.0x |\n",
            row.git_worktree_ms, row.git_worktree_files_written
        ));
        out.push_str(&format!(
            "| {scale} | GitX `CowWorkspace` (reflink) | {:.2} | {} | {:.1}x |\n",
            row.cow_workspace_ms, row.cow_workspace_files_written, cow_speedup
        ));
        out.push_str(&format!(
            "| {scale} | GitX `LazyWorkspace` (demand-paged) | {:.2} | {} | {:.1}x |\n",
            row.lazy_workspace_ms, row.lazy_workspace_files_written, lazy_speedup
        ));
        out.push_str(&format!(
            "| {scale} | GitX `MemVfs` (zero-disk CoW) | {:.2} | {} | {:.1}x |\n",
            row.mem_vfs_ms, row.mem_vfs_files_written, mem_speedup
        ));
    }

    // 2. Multi-Agent Same-File Merge
    let m = &report.same_file_merge;
    let git_pct = if m.total_merges == 0 {
        0.0
    } else {
        (m.git_line_merge_conflicts as f64 / m.total_merges as f64) * 100.0
    };
    let gitx_pct = if m.total_merges == 0 {
        0.0
    } else {
        (m.gitx_ast_merge_conflicts as f64 / m.total_merges as f64) * 100.0
    };

    out.push_str(&format!(
        "\n## 2. Multi-Agent Same-File Merge ({} agents appending to `src/lib.rs`)\n\n",
        m.agent_count
    ));
    out.push_str("| Merge Engine | Conflicts | Conflict Rate | Wall-Clock (ms) |\n");
    out.push_str("| --- | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| Baseline Git (`git merge-file` 3-way line) | {}/{} | {:.1}% | {:.2} |\n",
        m.git_line_merge_conflicts, m.total_merges, git_pct, m.git_line_merge_ms
    ));
    out.push_str(&format!(
        "| GitX Tree-sitter AST Merge | {}/{} | {:.1}% | {:.2} |\n",
        m.gitx_ast_merge_conflicts, m.total_merges, gitx_pct, m.gitx_ast_merge_ms
    ));

    // 3. Zero-Clone Server Grep & Diff
    let q = &report.server_query;
    let cold_speedup = safe_speedup(q.git_clone_and_grep_ms, q.gitx_cold_grep_ms);
    let warm_speedup = safe_speedup(q.git_clone_and_grep_ms, q.gitx_warm_grep_ms);
    let diff_speedup = safe_speedup(
        q.git_clone_and_grep_ms + q.git_local_diff_ms,
        q.gitx_zero_clone_diff_ms,
    );

    out.push_str(&format!(
        "\n## 3. Zero-Clone Server Grep & Diff ({} files)\n\n",
        q.repo_file_count
    ));
    out.push_str("| Operation | Latency (ms) | Speedup vs Git Clone | Notes |\n");
    out.push_str("| --- | ---: | ---: | --- |\n");
    out.push_str(&format!(
        "| Baseline Git (`git clone` + `git grep`) | {:.2} | 1.0x | Full local clone required |\n",
        q.git_clone_and_grep_ms
    ));
    out.push_str(&format!(
        "| GitX Server `/grep` (cold `TrigramIndex`) | {:.2} | {:.1}x | Zero-clone; builds index on demand |\n",
        q.gitx_cold_grep_ms, cold_speedup
    ));
    out.push_str(&format!(
        "| GitX Server `/grep` (warm `TrigramIndex`) | {:.2} | {:.1}x | Zero-clone; {} trigram cache hits |\n",
        q.gitx_warm_grep_ms, warm_speedup, q.warm_trigram_cache_hits
    ));
    out.push_str(&format!(
        "| GitX Server `/diff` (zero-clone) | {:.2} | {:.1}x | vs clone+diff ({:.2} ms total; local diff {:.2} ms) |\n",
        q.gitx_zero_clone_diff_ms,
        diff_speedup,
        q.git_clone_and_grep_ms + q.git_local_diff_ms,
        q.git_local_diff_ms
    ));

    out
}

fn safe_speedup(baseline_ms: f64, candidate_ms: f64) -> f64 {
    if candidate_ms <= 0.0001 {
        baseline_ms / 0.0001
    } else {
        baseline_ms / candidate_ms
    }
}

// ---------------------------------------------------------------------------
// Synthetic Repository Generator
// ---------------------------------------------------------------------------

fn generate_synthetic_repo_files(file_count: usize) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let count = file_count.max(1);
    for i in 0..count {
        let pkg = i / 25;
        let module = i % 25;
        let path = format!("crates/pkg_{pkg:02}/src/mod_{module:02}.rs");
        let content = format!(
            "//! Synthetic module {i} in package {pkg}.\n\
             \n\
             pub struct Service_{i} {{\n\
                 pub id: usize,\n\
                 pub weight: u64,\n\
             }}\n\
             \n\
             impl Service_{i} {{\n\
                 pub fn new() -> Self {{\n\
                     Self {{ id: {i}, weight: {} }}\n\
                 }}\n\
             \n\
                 pub fn compute(&self, input: u64) -> u64 {{\n\
                     input.wrapping_mul(31).wrapping_add(self.weight)\n\
                 }}\n\
             }}\n",
            (i as u64 + 1) * 17
        );
        files.insert(path, content);
    }
    files
}

// ---------------------------------------------------------------------------
// Benchmark 1: Workspace Fan-Out
// ---------------------------------------------------------------------------

async fn bench_workspace_fanout(
    files: &BTreeMap<String, String>,
    workspace_count: usize,
) -> Result<WorkspaceFanOutResult> {
    let tmp = TempDir::new()?;

    // 1A. Baseline Git: prepare source repo and fan out N worktrees via `git worktree add --detach`
    let git_repo_dir = tmp.path().join("git-origin");
    fs::create_dir_all(&git_repo_dir)?;
    run_git(&git_repo_dir, &["init", "--quiet"]).await?;
    run_git(&git_repo_dir, &["config", "user.name", "GitX Bench"]).await?;
    run_git(&git_repo_dir, &["config", "user.email", "bench@gitx.local"]).await?;

    for (rel_path, content) in files {
        let full = git_repo_dir.join(rel_path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full, content.as_bytes())?;
    }
    run_git(&git_repo_dir, &["add", "."]).await?;
    run_git(&git_repo_dir, &["commit", "--quiet", "-m", "initial 250-file repo"]).await?;

    let git_wt_root = tmp.path().join("git-worktrees");
    fs::create_dir_all(&git_wt_root)?;

    let t_git = Instant::now();
    for idx in 0..workspace_count {
        let wt_dir = git_wt_root.join(format!("wt-{idx:02}"));
        let wt_str = wt_dir.to_string_lossy().to_string();
        run_git(
            &git_repo_dir,
            &["worktree", "add", "--quiet", "--detach", &wt_str, "HEAD"],
        )
        .await?;
    }
    let git_worktree_ms = t_git.elapsed().as_secs_f64() * 1000.0;
    let git_worktree_files_written = count_working_files_recursive(&git_wt_root)?;

    // Prepare GitX LocalStore + DomainTree with the exact same 250 files
    let store_dir = tmp.path().join("gitx-store");
    let store = Arc::new(LocalStore::open(&store_dir)?);
    let mut base_tree = DomainTree::new(DomainId::public());
    for (rel_path, content) in files {
        let blob = store.put_blob_bytes(content.as_bytes())?;
        base_tree.insert(
            rel_path.clone(),
            EntryKind::File {
                blob_hash: blob.manifest_hash(),
                mode: FileMode::Regular,
                size: blob.total_size,
            },
        );
    }
    let _ = store.put_tree(&base_tree)?;

    // 1B. GitX CowWorkspace (reflink pool)
    let cow_pool_dir = tmp.path().join("cow-pool");
    let cow_root = tmp.path().join("cow-workspaces");
    fs::create_dir_all(&cow_root)?;

    let t_cow = Instant::now();
    let mut cow_workspaces = Vec::with_capacity(workspace_count);
    for idx in 0..workspace_count {
        let ws_dir = cow_root.join(format!("ws-{idx:02}"));
        let mut ws = CowWorkspace::open(&ws_dir, &cow_pool_dir)?;
        ws.materialize_tree(&base_tree, store.as_ref())?;
        cow_workspaces.push(ws);
    }
    let cow_workspace_ms = t_cow.elapsed().as_secs_f64() * 1000.0;
    let cow_workspace_files_written = count_working_files_recursive(&cow_root)?;
    if cow_workspaces.len() != workspace_count {
        return Err(bench_err("unexpected CowWorkspace count"));
    }

    // 1C. GitX LazyWorkspace (O(1) demand-paged virtual mount, zero base disk writes)
    let lazy_root = tmp.path().join("lazy-workspaces");
    fs::create_dir_all(&lazy_root)?;
    let store_dyn: Arc<dyn ObjectStore> = store.clone();

    let t_lazy = Instant::now();
    let mut lazy_workspaces = Vec::with_capacity(workspace_count);
    for idx in 0..workspace_count {
        let overlay_dir = lazy_root.join(format!("ws-{idx:02}"));
        let ws = LazyWorkspace::mount(&overlay_dir, Arc::clone(&store_dyn), base_tree.clone())?;
        lazy_workspaces.push(ws);
    }
    let lazy_workspace_ms = t_lazy.elapsed().as_secs_f64() * 1000.0;
    let lazy_workspace_files_written = count_working_files_recursive(&lazy_root)?;
    if lazy_workspaces[0].list_files()?.len() != files.len() {
        return Err(bench_err("LazyWorkspace virtual file count mismatch"));
    }

    // 1D. GitX MemVfs (O(1) Arc CoW in-memory fork, zero disk writes)
    let base_mem = MemVfs::from_tree(&base_tree, store.as_ref())?;
    let t_mem = Instant::now();
    let mut mem_workspaces = Vec::with_capacity(workspace_count);
    for _ in 0..workspace_count {
        mem_workspaces.push(base_mem.clone_instant());
    }
    let mem_vfs_ms = t_mem.elapsed().as_secs_f64() * 1000.0;
    if mem_workspaces[0].len() != files.len() {
        return Err(bench_err("MemVfs file count mismatch"));
    }

    Ok(WorkspaceFanOutResult {
        workspace_count,
        repo_file_count: files.len(),
        git_worktree_ms,
        git_worktree_files_written,
        cow_workspace_ms,
        cow_workspace_files_written,
        lazy_workspace_ms,
        lazy_workspace_files_written,
        mem_vfs_ms,
        mem_vfs_files_written: 0,
    })
}

// ---------------------------------------------------------------------------
// Benchmark 2: Multi-Agent Same-File Merge
// ---------------------------------------------------------------------------

async fn bench_multi_agent_same_file_merge(agent_count: usize) -> Result<MergeBenchResult> {
    let agents = agent_count.max(2);
    let base_src = "//! Shared service entrypoints.\n\npub fn base_service() -> usize {\n    0\n}\n";
    let agent_versions: Vec<String> = (0..agents)
        .map(|i| format!("{base_src}\npub fn agent_{i}_handler() -> usize {{ {i} }}\n"))
        .collect();
    let total_merges = agents - 1;

    // 2A. Baseline Git 3-way line merge via real `git merge-file`
    let tmp = TempDir::new()?;
    let base_path = tmp.path().join("base.rs");
    let ours_path = tmp.path().join("ours.rs");
    let theirs_path = tmp.path().join("theirs.rs");
    fs::write(&base_path, base_src)?;

    let mut git_conflicts = 0usize;
    let mut git_accum = agent_versions[0].clone();
    let t_git = Instant::now();
    for (idx, version) in agent_versions.iter().enumerate().skip(1) {
        fs::write(&ours_path, &git_accum)?;
        fs::write(&theirs_path, version)?;

        let out = Command::new("git")
            .args(["merge-file", "-p"])
            .arg(&ours_path)
            .arg(&base_path)
            .arg(&theirs_path)
            .output()
            .await?;

        if !out.status.success() {
            git_conflicts += 1;
            // Simulate human conflict resolution so the next agent also merges against evolving master
            git_accum.push_str(&format!(
                "\npub fn agent_{idx}_handler() -> usize {{ {idx} }}\n"
            ));
        } else {
            git_accum = String::from_utf8_lossy(&out.stdout).into_owned();
        }
    }
    let git_line_merge_ms = t_git.elapsed().as_secs_f64() * 1000.0;

    // 2B. GitX Tree-sitter AST merge via `gitx_merge::merge_bytes`
    let mut gitx_conflicts = 0usize;
    let mut gitx_accum = agent_versions[0].as_bytes().to_vec();
    let t_gitx = Instant::now();
    for version in agent_versions.iter().skip(1) {
        match merge_bytes(
            "src/lib.rs",
            base_src.as_bytes(),
            &gitx_accum,
            version.as_bytes(),
        ) {
            MergeOutcome::Clean(merged) => {
                gitx_accum = merged;
            }
            MergeOutcome::Conflict { materialized, .. } => {
                gitx_conflicts += 1;
                gitx_accum = materialized;
            }
        }
    }
    let gitx_ast_merge_ms = t_gitx.elapsed().as_secs_f64() * 1000.0;

    let final_rust = String::from_utf8_lossy(&gitx_accum);
    for i in 0..agents {
        let needle = format!("pub fn agent_{i}_handler() -> usize {{ {i} }}");
        if !final_rust.contains(&needle) {
            return Err(bench_err(format!(
                "GitX AST merge missing expected function '{needle}'"
            )));
        }
    }

    Ok(MergeBenchResult {
        agent_count: agents,
        total_merges,
        git_line_merge_conflicts: git_conflicts,
        git_line_merge_ms,
        gitx_ast_merge_conflicts: gitx_conflicts,
        gitx_ast_merge_ms,
    })
}

// ---------------------------------------------------------------------------
// Benchmark 3: Zero-Clone Server Grep (Cold vs Warm TrigramIndex) & Diff
// ---------------------------------------------------------------------------

async fn bench_zero_clone_server_grep_and_diff(
    files: &BTreeMap<String, String>,
    warm_iterations: usize,
) -> Result<ServerQueryBenchResult> {
    let srv = LiveTestServer::start(None).await?;
    let client = Client::new();
    let needle = "quantum_trigram_needle_2026";

    // Commit 1: all 250 synthetic files
    let c1: CommitResponse = client
        .post(srv.url("/v1/repos/bench/monorepo/commit"))
        .header("X-Gitx-User", "bench-bot")
        .json(&json!({
            "files": files,
            "message": "Initial 250-file monorepo commit",
            "author_name": "BenchBot",
            "author_email": "bench@gitx.local"
        }))
        .send()
        .await
        .map_err(|e| bench_err(format!("seed commit 1 failed: {e}")))?
        .error_for_status()
        .map_err(|e| bench_err(format!("seed commit 1 status: {e}")))?
        .json()
        .await
        .map_err(|e| bench_err(format!("seed commit 1 decode: {e}")))?;

    // Commit 2: modify 3 files and insert the unique grep needle
    let mut changed_files = BTreeMap::new();
    let first_key = files
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| bench_err("synthetic files empty"))?;
    let mut updated_first = files[&first_key].clone();
    updated_first.push_str(&format!("\npub fn {needle}() -> u64 {{ 42 }}\n"));
    changed_files.insert(first_key, updated_first);

    for key in files.keys().skip(1).take(2) {
        let mut body = files[key].clone();
        body.push_str("\n// updated in commit 2 for diff benchmark\n");
        changed_files.insert(key.clone(), body);
    }

    let c2: CommitResponse = client
        .post(srv.url("/v1/repos/bench/monorepo/commit"))
        .header("X-Gitx-User", "bench-bot")
        .json(&json!({
            "files": changed_files,
            "message": "Add quantum_trigram_needle_2026 and update 2 modules",
            "author_name": "BenchBot",
            "author_email": "bench@gitx.local"
        }))
        .send()
        .await
        .map_err(|e| bench_err(format!("seed commit 2 failed: {e}")))?
        .error_for_status()
        .map_err(|e| bench_err(format!("seed commit 2 status: {e}")))?
        .json()
        .await
        .map_err(|e| bench_err(format!("seed commit 2 decode: {e}")))?;

    // 3A. Baseline Git: full `git clone http://...` + `git grep` + `git diff HEAD~1 HEAD`
    let clone_tmp = TempDir::new()?;
    let clone_dir = clone_tmp.path().join("cloned-monorepo");
    let clone_url = srv.url("/bench/monorepo.git");

    let t_git_clone_grep = Instant::now();
    let clone_out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["clone", "--quiet", &clone_url])
        .arg(&clone_dir)
        .output()
        .await?;
    if !clone_out.status.success() {
        return Err(bench_err(format!(
            "benchmark git clone failed: {}",
            String::from_utf8_lossy(&clone_out.stderr)
        )));
    }
    let grep_out = Command::new("git")
        .arg("-C")
        .arg(&clone_dir)
        .args(["grep", needle])
        .output()
        .await?;
    if !grep_out.status.success() {
        return Err(bench_err(format!(
            "benchmark git grep failed: {}",
            String::from_utf8_lossy(&grep_out.stderr)
        )));
    }
    let git_clone_and_grep_ms = t_git_clone_grep.elapsed().as_secs_f64() * 1000.0;

    let t_git_diff = Instant::now();
    let diff_out = Command::new("git")
        .arg("-C")
        .arg(&clone_dir)
        .args(["diff", "HEAD~1", "HEAD"])
        .output()
        .await?;
    if !diff_out.status.success() {
        return Err(bench_err("benchmark git diff failed"));
    }
    let git_local_diff_ms = t_git_diff.elapsed().as_secs_f64() * 1000.0;

    // 3B. GitX Zero-Clone Server Grep — COLD TrigramIndex
    let grep_url = srv.url(&format!("/v1/repos/bench/monorepo/grep?q={needle}"));
    let t_cold = Instant::now();
    let cold_res: GrepResponse = client
        .get(&grep_url)
        .send()
        .await
        .map_err(|e| bench_err(format!("cold grep failed: {e}")))?
        .error_for_status()
        .map_err(|e| bench_err(format!("cold grep status: {e}")))?
        .json()
        .await
        .map_err(|e| bench_err(format!("cold grep decode: {e}")))?;
    let gitx_cold_grep_ms = t_cold.elapsed().as_secs_f64() * 1000.0;
    if cold_res.matches.is_empty() {
        return Err(bench_err("cold server grep returned zero matches"));
    }

    // 3C. GitX Zero-Clone Server Grep — WARM TrigramIndex (averaged over warm_iterations)
    let iters = warm_iterations.max(1);
    let t_warm = Instant::now();
    for _ in 0..iters {
        let warm_res: GrepResponse = client
            .get(&grep_url)
            .send()
            .await
            .map_err(|e| bench_err(format!("warm grep failed: {e}")))?
            .error_for_status()
            .map_err(|e| bench_err(format!("warm grep status: {e}")))?
            .json()
            .await
            .map_err(|e| bench_err(format!("warm grep decode: {e}")))?;
        if warm_res.matches.is_empty() {
            return Err(bench_err("warm server grep returned zero matches"));
        }
    }
    let gitx_warm_grep_ms = (t_warm.elapsed().as_secs_f64() * 1000.0) / (iters as f64);

    let stats: DerivedStats = client
        .get(srv.url("/v1/repos/bench/monorepo/derived/stats"))
        .send()
        .await
        .map_err(|e| bench_err(format!("derived stats failed: {e}")))?
        .error_for_status()
        .map_err(|e| bench_err(format!("derived stats status: {e}")))?
        .json()
        .await
        .map_err(|e| bench_err(format!("derived stats decode: {e}")))?;

    // 3D. GitX Zero-Clone Server Diff
    let diff_url = srv.url(&format!(
        "/v1/repos/bench/monorepo/diff?from={}&to={}",
        c1.changeset_id, c2.changeset_id
    ));
    let t_server_diff = Instant::now();
    let diff_res: DiffResponse = client
        .get(&diff_url)
        .send()
        .await
        .map_err(|e| bench_err(format!("server diff failed: {e}")))?
        .error_for_status()
        .map_err(|e| bench_err(format!("server diff status: {e}")))?
        .json()
        .await
        .map_err(|e| bench_err(format!("server diff decode: {e}")))?;
    let gitx_zero_clone_diff_ms = t_server_diff.elapsed().as_secs_f64() * 1000.0;
    if diff_res.files.len() != changed_files.len() {
        return Err(bench_err(format!(
            "server diff file count mismatch: expected {}, got {}",
            changed_files.len(),
            diff_res.files.len()
        )));
    }

    Ok(ServerQueryBenchResult {
        repo_file_count: files.len(),
        git_clone_and_grep_ms,
        git_local_diff_ms,
        gitx_cold_grep_ms,
        gitx_warm_grep_ms,
        gitx_zero_clone_diff_ms,
        warm_trigram_cache_hits: stats.trigram_cache_hits,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn run_git(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .await?;
    if !out.status.success() {
        return Err(bench_err(format!(
            "git {:?} failed in {}: {}",
            args,
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn count_working_files_recursive(root: &Path) -> Result<usize> {
    let mut count = 0usize;
    count_working_files_inner(root, &mut count)?;
    Ok(count)
}

fn count_working_files_inner(dir: &Path, count: &mut usize) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        // Exclude Git's `.git` metadata pointer file/dir inside worktrees.
        if name == ".git" {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            count_working_files_inner(&entry.path(), count)?;
        } else {
            *count += 1;
        }
    }
    Ok(())
}
