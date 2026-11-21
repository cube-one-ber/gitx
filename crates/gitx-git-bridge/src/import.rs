//! Colocated Git repository importer (`git` CLI -> `gitx-store`).

use chrono::{DateTime, Utc};
use gitx_core::{
    Actor, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, GitxError, Identity,
    ObjectHash, Result, VisibilityPolicy,
};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Summary of an import from an existing Git repository into `gitx-store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub imported_commits: usize,
    pub head_changeset: Option<ObjectHash>,
    pub branch: String,
}

struct ParsedCommitMeta {
    parents: Vec<String>,
    author: Identity,
    committer: Identity,
    created_at: DateTime<Utc>,
    description: String,
}

struct ParsedTreeEntry {
    mode: FileMode,
    blob_sha: String,
    path: String,
}

fn run_git_output(git_worktree: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(git_worktree)
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitxError::GitBridge(format!(
            "git {} failed (status {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

fn detect_branch_name(git_worktree: &Path) -> String {
    match Command::new("git")
        .arg("-C")
        .arg(git_worktree)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if name.is_empty() {
                "HEAD".to_string()
            } else {
                name
            }
        }
        _ => "HEAD".to_string(),
    }
}

fn head_exists(git_worktree: &Path) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(git_worktree)
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()?;
    Ok(output.status.success())
}

fn read_commit_meta(git_worktree: &Path, sha: &str) -> Result<ParsedCommitMeta> {
    let raw = run_git_output(
        git_worktree,
        &[
            "show",
            "-s",
            "--pretty=format:%P%x00%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%B",
            sha,
        ],
    )?;

    let text = String::from_utf8_lossy(&raw);
    let parts: Vec<&str> = text.splitn(8, '\0').collect();
    if parts.len() != 8 {
        return Err(GitxError::GitBridge(format!(
            "unexpected git show output for commit {sha}: got {} fields",
            parts.len()
        )));
    }

    let parents: Vec<String> = parts[0]
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    let author_name = parts[1].to_string();
    let author_email = parts[2].to_string();
    let author_ts: i64 = parts[3].trim().parse().map_err(|e| {
        GitxError::GitBridge(format!(
            "invalid author timestamp '{}' in commit {sha}: {e}",
            parts[3]
        ))
    })?;
    let committer_name = parts[4].to_string();
    let committer_email = parts[5].to_string();
    let _committer_ts: i64 = parts[6].trim().parse().map_err(|e| {
        GitxError::GitBridge(format!(
            "invalid committer timestamp '{}' in commit {sha}: {e}",
            parts[6]
        ))
    })?;

    // Strip the single trailing newline that Git appends to standard commit messages.
    let description = parts[7]
        .strip_suffix('\n')
        .unwrap_or(parts[7])
        .to_string();

    let created_at = DateTime::from_timestamp(author_ts, 0).unwrap_or_else(Utc::now);

    Ok(ParsedCommitMeta {
        parents,
        author: Identity {
            name: author_name,
            email: author_email,
            key_fingerprint: None,
        },
        committer: Identity {
            name: committer_name,
            email: committer_email,
            key_fingerprint: None,
        },
        created_at,
        description,
    })
}

fn list_tree_entries(git_worktree: &Path, sha: &str) -> Result<Vec<ParsedTreeEntry>> {
    let raw = run_git_output(git_worktree, &["ls-tree", "-r", "-z", sha])?;
    let mut entries = Vec::new();

    for record in raw.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        let tab_pos = record.iter().position(|&b| b == b'\t').ok_or_else(|| {
            GitxError::GitBridge(format!("malformed ls-tree record in commit {sha}"))
        })?;
        let meta = std::str::from_utf8(&record[..tab_pos]).map_err(|e| {
            GitxError::GitBridge(format!("non-UTF8 ls-tree metadata in commit {sha}: {e}"))
        })?;
        let path = String::from_utf8(record[tab_pos + 1..].to_vec()).map_err(|e| {
            GitxError::GitBridge(format!("non-UTF8 file path in commit {sha}: {e}"))
        })?;

        let mut meta_parts = meta.split(' ');
        let mode_str = meta_parts.next().unwrap_or("");
        let kind = meta_parts.next().unwrap_or("");
        let blob_sha = meta_parts.next().unwrap_or("");

        if kind != "blob" {
            // Skip gitlinks (submodules, mode 160000) or non-blob entries.
            continue;
        }

        let mode = match mode_str {
            "100644" => FileMode::Regular,
            "100755" => FileMode::Executable,
            "120000" => FileMode::Symlink,
            other => {
                return Err(GitxError::GitBridge(format!(
                    "unsupported git blob mode '{other}' for '{path}' in commit {sha}"
                )));
            }
        };

        entries.push(ParsedTreeEntry {
            mode,
            blob_sha: blob_sha.to_string(),
            path,
        });
    }

    Ok(entries)
}

/// Reads a batch of Git blobs cleanly using a single `git cat-file --batch` invocation.
fn read_blobs_batch(
    git_worktree: &Path,
    blob_shas: &[String],
) -> Result<HashMap<String, Vec<u8>>> {
    if blob_shas.is_empty() {
        return Ok(HashMap::new());
    }

    let mut child = Command::new("git")
        .arg("-C")
        .arg(git_worktree)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitxError::GitBridge("failed to open stdin for git cat-file".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| GitxError::GitBridge("failed to open stdout for git cat-file".into()))?;

    // Write all requested blob SHAs on a helper thread so large batches cannot deadlock pipes.
    let input_bytes: Vec<u8> = {
        let mut buf = Vec::with_capacity(blob_shas.len() * 41);
        for sha in blob_shas {
            buf.extend_from_slice(sha.as_bytes());
            buf.push(b'\n');
        }
        buf
    };
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        stdin.write_all(&input_bytes)?;
        stdin.flush()?;
        drop(stdin);
        Ok(())
    });

    let mut reader = BufReader::new(stdout);
    let mut results = HashMap::with_capacity(blob_shas.len());

    for expected_sha in blob_shas {
        let mut header_line = String::new();
        let n = reader.read_line(&mut header_line)?;
        if n == 0 {
            return Err(GitxError::GitBridge(format!(
                "unexpected EOF from git cat-file --batch while reading blob {expected_sha}"
            )));
        }
        let header = header_line.trim_end_matches(['\r', '\n']);
        let parts: Vec<&str> = header.split(' ').collect();
        if parts.len() != 3 || parts[1] != "blob" {
            return Err(GitxError::GitBridge(format!(
                "unexpected git cat-file --batch header for {expected_sha}: '{header}'"
            )));
        }
        let size: usize = parts[2].parse().map_err(|e| {
            GitxError::GitBridge(format!(
                "invalid blob size '{}' for {expected_sha}: {e}",
                parts[2]
            ))
        })?;

        let mut data = vec![0u8; size];
        reader.read_exact(&mut data)?;

        // Consume trailing LF after payload.
        let mut lf = [0u8; 1];
        reader.read_exact(&mut lf)?;

        results.insert(expected_sha.clone(), data);
    }

    writer
        .join()
        .map_err(|_| GitxError::GitBridge("git cat-file stdin writer thread panicked".into()))??;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitxError::GitBridge(format!(
            "git cat-file --batch failed: {}",
            stderr.trim()
        )));
    }

    Ok(results)
}

/// Imports an existing Git repository (working tree or bare repo) losslessly into `store`
/// under `target_domain`.
///
/// Uses the real `git` CLI (`rev-list`, `ls-tree`, `cat-file --batch`, `show`) so packed objects,
/// delta packs, symlinks, executable bits, and arbitrary binary blobs import cleanly.
pub fn import_from_git_repo(
    git_worktree: &Path,
    store: &dyn ObjectStore,
    target_domain: DomainId,
) -> Result<ImportReport> {
    // Verify the directory is a valid Git repository.
    run_git_output(git_worktree, &["rev-parse", "--git-dir"])?;

    let branch = detect_branch_name(git_worktree);
    if !head_exists(git_worktree)? {
        return Ok(ImportReport {
            imported_commits: 0,
            head_changeset: None,
            branch,
        });
    }

    let rev_list_raw =
        run_git_output(git_worktree, &["rev-list", "--topo-order", "--reverse", "HEAD"])?;
    let commits: Vec<String> = String::from_utf8_lossy(&rev_list_raw)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToString::to_string)
        .collect();

    let mut git_to_gitx: HashMap<String, ObjectHash> = HashMap::with_capacity(commits.len());
    let mut git_to_pub_proj: HashMap<String, ObjectHash> = HashMap::with_capacity(commits.len());
    // Cache git blob SHA -> (ChunkedBlob manifest hash, byte size).
    let mut blob_cache: HashMap<String, (ObjectHash, u64)> = HashMap::new();
    let mut head_changeset: Option<ObjectHash> = None;

    let visibility = if target_domain.is_public() {
        VisibilityPolicy::public()
    } else {
        VisibilityPolicy::private(target_domain.clone(), false)
    };

    for sha in &commits {
        let meta = read_commit_meta(git_worktree, sha)?;
        let tree_entries = list_tree_entries(git_worktree, sha)?;

        // Batch-read all blobs not yet cached in this import pass.
        let mut missing_blobs: Vec<String> = Vec::new();
        for entry in &tree_entries {
            if !blob_cache.contains_key(&entry.blob_sha)
                && !missing_blobs.contains(&entry.blob_sha)
            {
                missing_blobs.push(entry.blob_sha.clone());
            }
        }

        if !missing_blobs.is_empty() {
            let fetched = read_blobs_batch(git_worktree, &missing_blobs)?;
            for (blob_sha, bytes) in fetched {
                let blob = store.put_blob_bytes(&bytes)?;
                blob_cache.insert(blob_sha, (blob.manifest_hash(), blob.total_size));
            }
        }

        let mut domain_tree = DomainTree::new(target_domain.clone());
        for entry in tree_entries {
            let &(manifest_hash, size) = blob_cache.get(&entry.blob_sha).ok_or_else(|| {
                GitxError::GitBridge(format!(
                    "missing cached blob {} for path '{}'",
                    entry.blob_sha, entry.path
                ))
            })?;
            domain_tree.insert(
                entry.path,
                EntryKind::File {
                    blob_hash: manifest_hash,
                    mode: entry.mode,
                    size,
                },
            );
        }

        let tree_hash = store.put_tree(&domain_tree)?;

        let parents: Vec<ObjectHash> = meta
            .parents
            .iter()
            .filter_map(|p| git_to_gitx.get(p).copied())
            .collect();

        let public_parents: Vec<ObjectHash> = if target_domain.is_public() {
            meta.parents
                .iter()
                .filter_map(|p| git_to_pub_proj.get(p).copied())
                .collect()
        } else {
            Vec::new()
        };

        let cs = ChangeSetBuilder::new(meta.author)
            .committer(Actor::Human(meta.committer))
            .parents(parents)
            .public_parents(public_parents)
            .domain_tree(target_domain.clone(), tree_hash)
            .visibility(visibility.clone())
            .created_at(meta.created_at)
            .description(meta.description)
            .build();

        let cs_id = store.put_changeset(&cs)?;
        git_to_gitx.insert(sha.clone(), cs_id);
        git_to_pub_proj.insert(sha.clone(), cs.public_projection_hash);
        head_changeset = Some(cs_id);
    }

    if let Some(head_id) = head_changeset {
        store.set_bookmark(&branch, head_id)?;
    }

    Ok(ImportReport {
        imported_commits: commits.len(),
        head_changeset,
        branch,
    })
}
