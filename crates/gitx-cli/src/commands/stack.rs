use crate::repo::Repo;
use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use gitx_core::{
    ChangeSetBuilder, DomainId, OpKind, Stack, StackState, VisibilityPolicy,
};
use gitx_store::ObjectStore;
use std::env;

pub fn cmd_stack_create(name: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let head = snap.changeset;

    let master_hash = repo.store.get_bookmark(&repo.config.default_branch)?;
    let changes = repo.collect_change_ids_since(head.id, master_hash)?;
    let now = Utc::now();

    let stack = Stack {
        name: name.clone(),
        base_target: repo.config.default_branch.clone(),
        changes: changes.clone(),
        visibility: head.visibility.clone(),
        state: StackState::Draft,
        created_at: now,
        updated_at: now,
    };
    repo.store.put_stack(&stack)?;

    println!(
        "Created stack '{}' (base: {}, {} change(s))",
        stack.name,
        stack.base_target,
        stack.changes.len()
    );
    for cid in &stack.changes {
        println!("  - {}", cid.short());
    }
    Ok(())
}

pub fn cmd_stack_list() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let stacks = repo.store.list_stacks()?;
    if stacks.is_empty() {
        println!("No stacks found.");
        return Ok(());
    }
    for stack in stacks {
        let ids: Vec<String> = stack.changes.iter().map(|c| c.short()).collect();
        println!(
            "{} [{:?}] base={} domain={} changes=[{}]",
            stack.name,
            stack.state,
            stack.base_target,
            stack.visibility.primary_domain,
            ids.join(", ")
        );
    }
    Ok(())
}

pub fn cmd_stack_sync() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let active_ws = repo.active_workspace_ref()?;
    let _ = snap;

    let master_hash = repo
        .store
        .get_bookmark(&repo.config.default_branch)?
        .ok_or_else(|| anyhow!("bookmark '{}' not found", repo.config.default_branch))?;
    let master_cs = repo.store.get_changeset(master_hash)?;

    let stacks = repo.store.list_stacks()?;
    let mut total_restacked = 0usize;
    let mut total_pruned = 0usize;
    let mut conflicted_changes = Vec::new();

    for mut stack in stacks {
        if matches!(stack.state, StackState::Landed | StackState::Abandoned) {
            continue;
        }

        let target_hash = repo
            .store
            .get_bookmark(&stack.base_target)?
            .unwrap_or(master_hash);
        let mut current_base = repo.store.get_changeset(target_hash)?;
        let mut remaining_changes = Vec::new();

        for cid in &stack.changes {
            let revisions = repo.store.get_revisions_for_change(*cid)?;
            let Some(latest_cs) = revisions.last().cloned() else {
                total_pruned += 1;
                continue;
            };

            if repo.is_ancestor(latest_cs.id, target_hash)? {
                total_pruned += 1;
                continue;
            }

            if latest_cs.parents.as_slice() == [current_base.id] {
                remaining_changes.push(*cid);
                current_base = latest_cs;
                continue;
            }

            let old_base = match latest_cs.parents.first() {
                Some(&p) => Some(repo.store.get_changeset(p)?),
                None => None,
            };

            let (merged_trees, conflicts) =
                repo.merge_changeset_trees(old_base.as_ref(), &latest_cs, &current_base)?;
            let has_conflicts = !conflicts.is_empty() || repo.trees_have_conflicts(&merged_trees)?;

            let restacked_cs = ChangeSetBuilder::new(latest_cs.author.clone())
                .change_id(latest_cs.change_id)
                .previous_revision(Some(latest_cs.id))
                .parents(vec![current_base.id])
                .public_parents(vec![current_base.public_projection_hash])
                .domain_trees(merged_trees)
                .committer(latest_cs.committer.clone())
                .visibility(latest_cs.visibility.clone())
                .has_conflicts(has_conflicts)
                .description(latest_cs.description.clone())
                .build();

            repo.store.put_changeset(&restacked_cs)?;
            total_restacked += 1;
            if has_conflicts {
                conflicted_changes.push((restacked_cs.change_id, conflicts));
            }

            if active_ws.head_change_id == restacked_cs.change_id {
                repo.update_active_workspace_head(&restacked_cs)?;
                repo.materialize_changeset(&restacked_cs)?;
            }

            remaining_changes.push(*cid);
            current_base = restacked_cs;
        }

        stack.changes = remaining_changes;
        stack.updated_at = Utc::now();
        if stack.changes.is_empty() {
            stack.state = StackState::Landed;
        }
        repo.store.put_stack(&stack)?;
    }

    let _ = master_cs;
    repo.append_op(
        OpKind::StackSync {
            restacked: total_restacked,
            pruned: total_pruned,
        },
        format!("Synced stacks (restacked={total_restacked}, pruned={total_pruned})"),
    )?;

    println!("Stack sync complete: restacked {total_restacked}, pruned {total_pruned}");
    for (cid, paths) in conflicted_changes {
        println!(
            "  [CONFLICT] ChangeId {} has unresolved conflicts in: {}",
            cid.short(),
            paths.join(", ")
        );
    }
    Ok(())
}

pub fn cmd_land(target: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let head = snap.changeset;

    if head.has_conflicts {
        bail!(
            "cannot land ChangeSet {} while it contains unresolved conflicts",
            head.change_id.short()
        );
    }

    let current_target_hash = repo.store.get_bookmark(&target)?;
    if current_target_hash == Some(head.id) {
        println!("Already up to date with '{target}' ({}).", head.id.short());
        return Ok(());
    }

    let mut need_materialize = false;
    let landed_cs = match current_target_hash {
        None => promote_if_reveal_on_land(&repo, &head)?,
        Some(target_hash) => {
            if repo.is_ancestor(target_hash, head.id)? {
                promote_if_reveal_on_land(&repo, &head)?
            } else {
                // `target` advanced concurrently: 3-way semantic merge!
                let target_cs = repo.store.get_changeset(target_hash)?;
                let base_cs = match repo.find_common_ancestor(target_hash, head.id)? {
                    Some(base_hash) => Some(repo.store.get_changeset(base_hash)?),
                    None => None,
                };
                let (merged_trees, conflicts) =
                    repo.merge_changeset_trees(base_cs.as_ref(), &target_cs, &head)?;
                if !conflicts.is_empty() {
                    bail!(
                        "auto-merge conflict landing onto '{target}' in: {}",
                        conflicts.join(", ")
                    );
                }

                let vis = if head.visibility.reveal_on_land {
                    VisibilityPolicy::public()
                } else {
                    head.visibility.clone()
                };

                let merged_cs = ChangeSetBuilder::new(head.author.clone())
                    .change_id(head.change_id)
                    .previous_revision(Some(head.id))
                    .parents(vec![target_hash, head.id])
                    .public_parents(vec![
                        target_cs.public_projection_hash,
                        head.public_projection_hash,
                    ])
                    .domain_trees(merged_trees)
                    .committer(head.committer.clone())
                    .visibility(vis)
                    .has_conflicts(false)
                    .description(if head.description.is_empty() {
                        format!("Merge {} into {target}", head.change_id.short())
                    } else {
                        head.description.clone()
                    })
                    .build();
                repo.store.put_changeset(&merged_cs)?;
                need_materialize = true;
                merged_cs
            }
        }
    };

    let landed_changes = repo.collect_change_ids_since(head.id, current_target_hash)?;
    let record = repo.store.record_land(
        &target,
        current_target_hash,
        landed_cs.id,
        landed_changes.clone(),
    )?;

    repo.update_active_workspace_head(&landed_cs)?;
    if need_materialize {
        repo.materialize_changeset(&landed_cs)?;
    }

    repo.append_op(
        OpKind::Land {
            target: target.clone(),
            land_seq: record.land_seq,
            changes: landed_changes,
        },
        format!(
            "Landed onto {target} (land_seq={}, head={})",
            record.land_seq,
            landed_cs.id.short()
        ),
    )?;

    println!(
        "Landed onto '{}' (land_seq: {}, head: {})",
        record.target,
        record.land_seq,
        record.new_head.short()
    );
    Ok(())
}

fn promote_if_reveal_on_land(repo: &Repo, cs: &gitx_core::ChangeSet) -> Result<gitx_core::ChangeSet> {
    if !cs.visibility.reveal_on_land || cs.visibility.primary_domain.is_public() {
        return Ok(cs.clone());
    }

    let mut trees = cs.domain_trees.clone();
    if let Some(&priv_hash) = trees.get(&cs.visibility.primary_domain) {
        let priv_tree = repo.store.get_tree(priv_hash)?;
        let mut pub_tree = repo.get_domain_tree_or_empty(Some(cs), &DomainId::public())?;
        for (path, kind) in priv_tree.entries {
            pub_tree.insert(path, kind);
        }
        let pub_hash = repo.store.put_tree(&pub_tree)?;
        trees.insert(DomainId::public(), pub_hash);
    }

    let promoted = ChangeSetBuilder::new(cs.author.clone())
        .change_id(cs.change_id)
        .previous_revision(Some(cs.id))
        .parents(cs.parents.clone())
        .public_parents(cs.public_parents.clone())
        .domain_trees(trees)
        .committer(cs.committer.clone())
        .visibility(VisibilityPolicy::public())
        .has_conflicts(cs.has_conflicts)
        .description(cs.description.clone())
        .build();
    repo.store.put_changeset(&promoted)?;
    Ok(promoted)
}

pub fn cmd_revert(land_seq: u64) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let land = repo.store.get_land(land_seq)?;
    if let Some(reverter) = land.reverted_by {
        bail!("land_seq {land_seq} was already reverted by land_seq {reverter}");
    }
    let prev_head = land.previous_head.ok_or_else(|| {
        anyhow!("land_seq {land_seq} has no previous_head to restore")
    })?;

    let current_head = repo.store.get_bookmark(&land.target)?;
    let revert_record = repo.store.record_land(
        &land.target,
        current_head,
        prev_head,
        Vec::new(),
    )?;
    repo.store.mark_reverted(land_seq, revert_record.land_seq)?;

    let prev_cs = repo.store.get_changeset(prev_head)?;
    repo.update_active_workspace_head(&prev_cs)?;
    repo.materialize_changeset(&prev_cs)?;

    repo.append_op(
        OpKind::Revert { land_seq },
        format!(
            "Reverted land_seq {land_seq} on {} -> {}",
            land.target,
            prev_head.short()
        ),
    )?;

    println!(
        "Reverted land_seq {} on '{}' -> restored {} (revert land_seq: {})",
        land_seq,
        land.target,
        prev_head.short(),
        revert_record.land_seq
    );
    Ok(())
}

pub fn cmd_op_log(limit: usize) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let ops = repo.store.list_ops(limit)?;
    if ops.is_empty() {
        println!("Operation log is empty.");
        return Ok(());
    }
    for op in ops {
        let short_id = {
            let s = op.id.0.to_string().to_lowercase();
            s[s.len().saturating_sub(8)..].to_string()
        };
        println!(
            "{} {} {:?} — {}",
            short_id,
            op.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            op.kind,
            op.summary
        );
    }
    Ok(())
}

pub fn cmd_undo() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let Some(latest) = repo.store.latest_op()? else {
        bail!("operation log is empty; nothing to undo");
    };

    // Walk back through consecutive undos so running `gitx undo` repeatedly steps backward.
    let target_op_id = match latest.kind {
        OpKind::Undo { target_op } => {
            let restored = repo.store.get_op(target_op)?;
            restored
                .parent
                .ok_or_else(|| anyhow!("cannot undo past initial operation"))?
        }
        _ => latest
            .parent
            .ok_or_else(|| anyhow!("cannot undo past initial operation"))?,
    };

    let target_op = repo.store.get_op(target_op_id)?;

    // Restore bookmarks
    for (name, hash) in &target_op.bookmarks {
        repo.store.set_bookmark(name, *hash)?;
    }

    // Restore workspaces
    let current_workspaces = repo.store.list_workspaces()?;
    for existing_name in current_workspaces.keys() {
        if !target_op.workspaces.contains_key(existing_name) {
            repo.store.remove_workspace(existing_name)?;
        }
    }
    for ws in target_op.workspaces.values() {
        repo.store.put_workspace(ws)?;
    }

    // Materialize restored active workspace head
    if let Some(active_ws) = target_op.workspaces.get(&repo.config.active_workspace) {
        let restored_cs = repo.store.get_changeset(active_ws.head_changeset)?;
        repo.materialize_changeset(&restored_cs)?;
    }

    repo.append_op(
        OpKind::Undo {
            target_op: target_op.id,
        },
        format!("Undo to '{}'", target_op.summary),
    )?;

    println!("Undid '{}' -> restored '{}'", latest.summary, target_op.summary);
    Ok(())
}

pub fn cmd_op_restore(op_spec: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let spec = op_spec.trim().to_lowercase();
    if spec.is_empty() {
        bail!("op id prefix must not be empty");
    }

    let ops = repo.store.list_ops(500)?;
    let target_op = ops
        .into_iter()
        .find(|op| {
            let full = op.id.0.to_string().to_lowercase();
            let short = &full[full.len().saturating_sub(8)..];
            full == spec || full.starts_with(&spec) || short == spec || full.ends_with(&spec)
        })
        .ok_or_else(|| anyhow!("no operation log entry matching '{op_spec}'"))?;

    for (name, hash) in &target_op.bookmarks {
        repo.store.set_bookmark(name, *hash)?;
    }

    let current_workspaces = repo.store.list_workspaces()?;
    for existing_name in current_workspaces.keys() {
        if !target_op.workspaces.contains_key(existing_name) {
            repo.store.remove_workspace(existing_name)?;
        }
    }
    for ws in target_op.workspaces.values() {
        repo.store.put_workspace(ws)?;
    }

    if let Some(active_ws) = target_op.workspaces.get(&repo.config.active_workspace) {
        let restored_cs = repo.store.get_changeset(active_ws.head_changeset)?;
        repo.materialize_changeset(&restored_cs)?;
    }

    repo.append_op(
        OpKind::Undo {
            target_op: target_op.id,
        },
        format!("Restored op '{}' ({})", op_spec, target_op.summary),
    )?;

    println!("Restored operation '{}' — {}", op_spec, target_op.summary);
    Ok(())
}

pub fn cmd_squash(message: Option<String>) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cur = snap.changeset;

    let Some(&parent_hash) = cur.parents.first() else {
        bail!("cannot squash root ChangeSet {} (no parent)", cur.change_id.short());
    };
    let parent = repo.store.get_changeset(parent_hash)?;

    let combined_desc = match message.filter(|m| !m.trim().is_empty()) {
        Some(m) => m,
        None => match (parent.description.trim(), cur.description.trim()) {
            ("", c) => c.to_string(),
            (p, "") => p.to_string(),
            (p, c) => format!("{p}\n\n{c}"),
        },
    };

    let squashed = ChangeSetBuilder::new(parent.author.clone())
        .change_id(parent.change_id)
        .previous_revision(Some(parent.id))
        .parents(parent.parents.clone())
        .public_parents(parent.public_parents.clone())
        .domain_trees(cur.domain_trees.clone())
        .committer(cur.committer.clone())
        .visibility(parent.visibility.clone())
        .has_conflicts(cur.has_conflicts)
        .description(combined_desc)
        .build();

    repo.store.put_changeset(&squashed)?;

    // Advance any bookmark that previously pointed at `parent.id` or `cur.id`.
    for (bm, hash) in repo.store.list_bookmarks()? {
        if hash == parent.id || hash == cur.id {
            repo.store.set_bookmark(&bm, squashed.id)?;
        }
    }

    // Start a clean working copy `@` on top of the squashed ChangeSet.
    let next_working = ChangeSetBuilder::new(repo.config.author.clone())
        .parents(vec![squashed.id])
        .public_parents(vec![squashed.public_projection_hash])
        .domain_trees(squashed.domain_trees.clone())
        .visibility(VisibilityPolicy::public())
        .description("")
        .build();
    repo.store.put_changeset(&next_working)?;
    repo.update_active_workspace_head(&next_working)?;

    repo.append_op(
        OpKind::Squash {
            from: cur.change_id,
            into: parent.change_id,
        },
        format!(
            "Squashed {} into {} ({})",
            cur.change_id.short(),
            squashed.change_id.short(),
            squashed.id.short()
        ),
    )?;

    println!(
        "Squashed {} into {} ({}); active @ is now {}",
        cur.change_id.short(),
        squashed.change_id.short(),
        squashed.id.short(),
        next_working.change_id.short()
    );
    Ok(())
}

pub fn cmd_split(paths: Vec<String>, message: Option<String>) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cur = snap.changeset;

    let selected: std::collections::BTreeSet<String> = paths
        .into_iter()
        .flat_map(|item| {
            item.split(',')
                .map(|s| s.trim().trim_start_matches("./").to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .collect();
    if selected.is_empty() {
        bail!("specify at least one path via --paths <path1,path2>");
    }

    let parent_cs = match cur.parents.first() {
        Some(&p) => Some(repo.store.get_changeset(p)?),
        None => None,
    };

    let mut all_domains = std::collections::BTreeSet::new();
    if let Some(ref p) = parent_cs {
        all_domains.extend(p.domain_trees.keys().cloned());
    }
    all_domains.extend(cur.domain_trees.keys().cloned());
    all_domains.insert(DomainId::public());

    let mut first_domain_trees = std::collections::BTreeMap::new();
    let mut moved_any = false;

    for dom in &all_domains {
        let mut first_tree = repo.get_domain_tree_or_empty(parent_cs.as_ref(), dom)?;
        let cur_tree = repo.get_domain_tree_or_empty(Some(&cur), dom)?;

        for path in &selected {
            match cur_tree.entries.get(path) {
                Some(entry) => {
                    if first_tree.entries.get(path) != Some(entry) {
                        first_tree.insert(path.clone(), entry.clone());
                        moved_any = true;
                    }
                }
                None => {
                    if first_tree.entries.remove(path).is_some() {
                        moved_any = true;
                    }
                }
            }
        }

        if dom.is_public() || !first_tree.entries.is_empty() {
            let hash = repo.store.put_tree(&first_tree)?;
            first_domain_trees.insert(dom.clone(), hash);
        }
    }

    if !moved_any {
        bail!(
            "none of the selected paths ({}) differ from parent in {}",
            selected.into_iter().collect::<Vec<_>>().join(", "),
            cur.change_id.short()
        );
    }

    let first_desc = message
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| {
            if cur.description.trim().is_empty() {
                format!(
                    "Split ({})",
                    selected.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            } else {
                cur.description.clone()
            }
        });

    let first_has_conflicts = repo.trees_have_conflicts(&first_domain_trees)?;
    let first_cs = ChangeSetBuilder::new(cur.author.clone())
        .parents(cur.parents.clone())
        .public_parents(cur.public_parents.clone())
        .domain_trees(first_domain_trees)
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(first_has_conflicts)
        .description(first_desc)
        .build();
    repo.store.put_changeset(&first_cs)?;

    // Remaining changes sit in a new revision of `cur.change_id` stacked directly on top of `first_cs`.
    let remainder_cs = ChangeSetBuilder::new(cur.author.clone())
        .change_id(cur.change_id)
        .previous_revision(Some(cur.id))
        .parents(vec![first_cs.id])
        .public_parents(vec![first_cs.public_projection_hash])
        .domain_trees(cur.domain_trees.clone())
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(cur.has_conflicts)
        .description(cur.description.clone())
        .build();
    repo.store.put_changeset(&remainder_cs)?;
    repo.update_active_workspace_head(&remainder_cs)?;

    repo.append_op(
        OpKind::Split {
            source: cur.change_id,
            created: first_cs.change_id,
        },
        format!(
            "Split {} -> base {} + remainder {}",
            cur.change_id.short(),
            first_cs.change_id.short(),
            remainder_cs.change_id.short()
        ),
    )?;

    println!(
        "Split {} into stack:\n  base:      {} ({}) — {}\n  remainder: {} ({})",
        cur.change_id.short(),
        first_cs.change_id.short(),
        first_cs.id.short(),
        first_cs.description,
        remainder_cs.change_id.short(),
        remainder_cs.id.short(),
    );
    Ok(())
}

pub fn cmd_rebase(onto: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cur = snap.changeset;
    let onto_cs = repo.resolve_changeset(&onto)?;

    if cur.parents.as_slice() == [onto_cs.id] {
        println!(
            "ChangeSet {} is already based on {} ({}).",
            cur.change_id.short(),
            onto,
            onto_cs.id.short()
        );
        return Ok(());
    }

    let old_base = match cur.parents.first() {
        Some(&p) => Some(repo.store.get_changeset(p)?),
        None => None,
    };

    let (merged_trees, conflicts) = repo.merge_changeset_trees(old_base.as_ref(), &cur, &onto_cs)?;
    let has_conflicts = !conflicts.is_empty() || repo.trees_have_conflicts(&merged_trees)?;

    let rebased = ChangeSetBuilder::new(cur.author.clone())
        .change_id(cur.change_id)
        .previous_revision(Some(cur.id))
        .parents(vec![onto_cs.id])
        .public_parents(vec![onto_cs.public_projection_hash])
        .domain_trees(merged_trees)
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(has_conflicts)
        .description(cur.description.clone())
        .build();

    repo.store.put_changeset(&rebased)?;
    repo.update_active_workspace_head(&rebased)?;
    repo.materialize_changeset(&rebased)?;

    repo.append_op(
        OpKind::Rebase {
            moved: vec![rebased.change_id],
        },
        format!(
            "Rebased {} onto {} ({})",
            rebased.change_id.short(),
            onto,
            onto_cs.id.short()
        ),
    )?;

    println!(
        "Rebased {} ({} -> {}) onto {} ({})",
        rebased.change_id.short(),
        cur.id.short(),
        rebased.id.short(),
        onto,
        onto_cs.id.short()
    );
    if !conflicts.is_empty() {
        println!(
            "  [CONFLICT] First-class conflicts recorded in: {} (repo is NOT blocked; resolve at your own pace)",
            conflicts.join(", ")
        );
    }
    Ok(())
}
