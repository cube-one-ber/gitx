use crate::repo::Repo;
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use gitx_context::{Checkpoint, CodeAnchor, ContextId, ContextKind, ContextRecord};
use gitx_core::{Actor, ChangeSetBuilder, DomainId, DomainTree, EntryKind, ObjectHash, OpKind};
use gitx_merge::revert_agent_tree_step;
use gitx_store::ObjectStore;
use gitx_vfs::normalize_rel_path;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use ulid::Ulid;

pub fn cmd_context_add(
    prompt: String,
    path: String,
    lines: String,
    model: Option<String>,
    harness: Option<String>,
    visibility: String,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cur = snap.changeset;

    let norm_path = normalize_rel_path(&path)?;
    let (line_start, line_end) = parse_line_range(&lines)?;
    let vis_domain = DomainId::new(&visibility)?;

    let content = read_current_file_text(&repo, &cur, &norm_path)?;
    let anchor = CodeAnchor::from_file_lines(&norm_path, &content, line_start, line_end);

    let session_id = Ulid::new().to_string().to_lowercase();
    let model_name = model.clone().unwrap_or_else(|| "unknown".to_string());
    let harness_name = harness.clone().unwrap_or_else(|| "cli".to_string());
    let actor = if model.is_some() || harness.is_some() {
        Actor::Agent {
            harness: harness_name.clone(),
            model: model_name.clone(),
            session_id: session_id.clone(),
            initiated_by: repo.config.author.clone(),
        }
    } else {
        Actor::Human(repo.config.author.clone())
    };

    let record = ContextRecord {
        id: ContextId::new(),
        change_id: cur.change_id,
        revision: cur.id,
        visibility: vis_domain.clone(),
        author: actor,
        kind: ContextKind::Prompt {
            prompt,
            model: model_name,
            harness: harness_name,
            session_id,
        },
        anchors: vec![anchor.clone()],
        created_at: Utc::now(),
    };

    repo.context.add_record(&record)?;

    println!(
        "Added context {} on {}:{}-{} [{}]{}",
        record.id.short(),
        anchor.path,
        anchor.line_start,
        anchor.line_end,
        vis_domain,
        anchor
            .symbol
            .as_deref()
            .map(|s| format!(" (symbol: {s})"))
            .unwrap_or_default()
    );
    Ok(())
}

pub fn cmd_why(target: String, domains: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let (raw_path, raw_line) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected <path>:<line>, got '{target}'"))?;
    let norm_path = normalize_rel_path(raw_path)?;
    let line: u32 = raw_line
        .parse()
        .with_context(|| format!("invalid line number '{raw_line}'"))?;

    let allowed_domains: Vec<DomainId> = domains
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(DomainId::new)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let cur = repo.current_changeset()?;
    let content = read_current_file_text(&repo, &cur, &norm_path)?;

    let matches = repo
        .context
        .why(&norm_path, line, &content, &allowed_domains)?;

    if matches.is_empty() {
        println!("No context records found for {norm_path}:{line} in domains [{domains}].");
        return Ok(());
    }

    println!(
        "Context for {norm_path}:{line} ({} match(es)):",
        matches.len()
    );
    for m in matches {
        let (rel_start, rel_end) = m.relocated_lines;
        let sym = m
            .matched_anchor
            .symbol
            .as_deref()
            .map(|s| format!(" symbol={s}"))
            .unwrap_or_default();
        println!(
            "- [{}] {} lines {}-{} (originally {}-{}){sym}",
            m.record.visibility,
            m.record.id.short(),
            rel_start,
            rel_end,
            m.matched_anchor.line_start,
            m.matched_anchor.line_end
        );
        match &m.record.kind {
            ContextKind::Prompt {
                prompt,
                model,
                harness,
                ..
            } => {
                println!("  prompt ({harness}:{model}): {prompt}");
            }
            ContextKind::AgentTrace { summary, .. } => {
                println!("  trace: {summary}");
            }
            ContextKind::ReviewThread { reviewer, body, .. } => {
                println!("  review ({}): {body}", reviewer.name);
            }
            ContextKind::DesignDecision { title, rationale } => {
                println!("  decision ({title}): {rationale}");
            }
            ContextKind::IssueLink { tracker, key, url } => {
                println!(
                    "  issue ({tracker} {key}): {}",
                    url.as_deref().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

pub fn cmd_checkpoint_save(message: String, session: Option<String>) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let acl = repo.load_acl()?;
    let cow = repo.open_cow_workspace()?;
    let scanned = cow.snapshot_by_domain(repo.store.as_ref(), |p| acl.domain_for_path(p))?;
    let pub_tree = scanned
        .get(&DomainId::public())
        .cloned()
        .unwrap_or_else(|| DomainTree::new(DomainId::public()));
    let tree_hash = repo.store.put_tree(&pub_tree)?;

    let session_id = session.unwrap_or_else(|| "default".to_string());
    let existing = repo
        .context
        .list_checkpoints(&repo.config.active_workspace, 64)?;
    let parent_checkpoint = existing
        .iter()
        .find(|cp| cp.session_id == session_id)
        .map(|cp| cp.id);

    let actor = Actor::Agent {
        harness: "cli".to_string(),
        model: "checkpoint".to_string(),
        session_id: session_id.clone(),
        initiated_by: repo.config.author.clone(),
    };

    let cp = Checkpoint::new(
        repo.config.active_workspace.clone(),
        session_id.clone(),
        actor,
        message.clone(),
        tree_hash,
        parent_checkpoint,
    );
    repo.context.save_checkpoint(&cp)?;

    let prompt_hash = ObjectHash::of_bytes(message.as_bytes());
    repo.append_op(
        OpKind::AgentCheckpoint {
            session_id,
            prompt_hash,
        },
        format!("Saved checkpoint {} ({message})", cp.id),
    )?;

    println!(
        "Saved checkpoint {} (session: {}, tree: {}): {}",
        cp.id,
        cp.session_id,
        cp.tree_hash.short(),
        cp.prompt_summary
    );
    Ok(())
}

pub fn cmd_checkpoint_list() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let checkpoints = repo
        .context
        .list_checkpoints(&repo.config.active_workspace, 50)?;
    if checkpoints.is_empty() {
        println!("No checkpoints found.");
        return Ok(());
    }
    for cp in checkpoints {
        let parent = cp
            .parent_checkpoint
            .map(|p| format!(" parent={p}"))
            .unwrap_or_default();
        println!(
            "{} [session={}] tree={}{parent} — {}",
            cp.id,
            cp.session_id,
            cp.tree_hash.short(),
            cp.prompt_summary
        );
    }
    Ok(())
}

pub fn cmd_checkpoint_undo(checkpoint_id: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let cp = resolve_checkpoint(&repo, &checkpoint_id)?;

    let after_tree = repo.store.get_tree(cp.tree_hash)?;
    let cur_cs = repo.current_changeset()?;

    // Determine `before_agent`: use parent checkpoint if available, otherwise `@`'s parent ChangeSet.
    let before_tree = if let Some(parent_cp_id) = cp.parent_checkpoint {
        let parent_cp = repo
            .context
            .get_checkpoint(parent_cp_id)?
            .ok_or_else(|| anyhow!("parent checkpoint '{parent_cp_id}' not found"))?;
        repo.store.get_tree(parent_cp.tree_hash)?
    } else if let Some(&parent_cs_hash) = cur_cs.parents.first() {
        let parent_cs = repo.store.get_changeset(parent_cs_hash)?;
        repo.get_domain_tree_or_empty(Some(&parent_cs), &DomainId::public())?
    } else {
        DomainTree::new(DomainId::public())
    };

    // Snapshot the live working directory (containing subsequent human edits) without mutating `@`.
    let acl = repo.load_acl()?;
    let cow = repo.open_cow_workspace()?;
    let scanned = cow.snapshot_by_domain(repo.store.as_ref(), |p| acl.domain_for_path(p))?;
    let current_tree = scanned
        .get(&DomainId::public())
        .cloned()
        .unwrap_or_else(|| DomainTree::new(DomainId::public()));

    let merge_result = revert_agent_tree_step(
        &before_tree,
        &after_tree,
        &current_tree,
        |h| repo.store.read_blob_bytes(h),
        |bytes| {
            let blob = repo.store.put_blob_bytes(bytes)?;
            Ok((blob.manifest_hash(), blob.total_size))
        },
    )?;

    let new_pub_hash = repo.store.put_tree(&merge_result.tree)?;
    let mut new_trees = cur_cs.domain_trees.clone();
    new_trees.insert(DomainId::public(), new_pub_hash);
    let has_conflicts =
        !merge_result.conflict_paths.is_empty() || repo.trees_have_conflicts(&new_trees)?;

    let updated = ChangeSetBuilder::new(cur_cs.author.clone())
        .change_id(cur_cs.change_id)
        .previous_revision(Some(cur_cs.id))
        .parents(cur_cs.parents.clone())
        .public_parents(cur_cs.public_parents.clone())
        .domain_trees(new_trees)
        .committer(cur_cs.committer.clone())
        .visibility(cur_cs.visibility.clone())
        .has_conflicts(has_conflicts)
        .description(cur_cs.description.clone())
        .build();

    repo.store.put_changeset(&updated)?;
    repo.update_active_workspace_head(&updated)?;
    repo.materialize_domain_tree(&merge_result.tree, &BTreeSet::new())?;

    repo.append_op(
        OpKind::Snapshot {
            workspace: repo.config.active_workspace.clone(),
        },
        format!("Undid agent checkpoint {}", cp.id),
    )?;

    println!(
        "Undid checkpoint {} (clean: {}, conflicts: {})",
        cp.id,
        merge_result.clean_paths.len(),
        merge_result.conflict_paths.len()
    );
    if !merge_result.conflict_paths.is_empty() {
        println!("  conflicts: {}", merge_result.conflict_paths.join(", "));
    }
    Ok(())
}

fn resolve_checkpoint(repo: &Repo, spec: &str) -> Result<Checkpoint> {
    let trimmed = spec.trim();
    if trimmed.eq_ignore_ascii_case("latest") {
        return repo
            .context
            .list_checkpoints(&repo.config.active_workspace, 1)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no checkpoints found"));
    }
    if let Ok(ulid) = Ulid::from_string(trimmed)
        && let Some(cp) = repo.context.get_checkpoint(ulid)?
    {
        return Ok(cp);
    }

    let lower = trimmed.to_lowercase();
    let all = repo
        .context
        .list_checkpoints(&repo.config.active_workspace, 500)?;
    all.into_iter()
        .find(|cp| cp.id.to_string().to_lowercase().starts_with(&lower))
        .ok_or_else(|| anyhow!("checkpoint '{spec}' not found"))
}

fn parse_line_range(spec: &str) -> Result<(u32, u32)> {
    if let Some((a, b)) = spec.split_once('-') {
        let start: u32 = a
            .trim()
            .parse()
            .with_context(|| format!("invalid start line in '{spec}'"))?;
        let end: u32 = b
            .trim()
            .parse()
            .with_context(|| format!("invalid end line in '{spec}'"))?;
        if start == 0 || end < start {
            bail!("invalid line range '{spec}' (expected 1-based start-end)");
        }
        Ok((start, end))
    } else {
        let line: u32 = spec
            .trim()
            .parse()
            .with_context(|| format!("invalid line number '{spec}'"))?;
        if line == 0 {
            bail!("line number must be >= 1");
        }
        Ok((line, line))
    }
}

fn read_current_file_text(
    repo: &Repo,
    cs: &gitx_core::ChangeSet,
    norm_path: &str,
) -> Result<String> {
    let disk = repo.root.join(norm_path);
    if disk.is_file() {
        return Ok(fs::read_to_string(&disk)?);
    }
    for &tree_hash in cs.domain_trees.values() {
        let tree = repo.store.get_tree(tree_hash)?;
        if let Some(EntryKind::File { blob_hash, .. }) = tree.entries.get(norm_path) {
            let bytes = repo.store.read_blob_bytes(*blob_hash)?;
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    bail!("file '{norm_path}' not found in workspace or current changeset")
}
