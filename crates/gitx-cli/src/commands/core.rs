use crate::repo::{Repo, parse_agent_spec};
use anyhow::Result;
use gitx_core::{
    Actor, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, ObjectHash,
    OpKind, VisibilityPolicy,
};
use gitx_merge::{DiffStatus, diff_trees, materialize_conflict, render_interdiff, unified_diff};
use gitx_store::ObjectStore;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::env;

pub fn cmd_init(colocate: bool, name: Option<String>, email: Option<String>) -> Result<()> {
    let cwd = env::current_dir()?;
    let summary = Repo::init(&cwd, colocate, name, email)?;
    println!("Initialized gitx repository at {}", summary.root.display());
    println!("  master:    {}", summary.master_hash.short());
    println!(
        "  workspace: default (@ {} / {})",
        summary.working_changeset.change_id.short(),
        summary.working_changeset.id.short()
    );
    println!("  key:       {}", summary.key_fingerprint);
    if let Some(count) = summary.imported_commits {
        println!("  colocated: imported {count} commit(s) from Git");
    }
    Ok(())
}

pub fn cmd_status() -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cs = &snap.changeset;

    println!("Workspace:  {} (@)", repo.config.active_workspace);
    println!("ChangeId:   {} ({})", cs.change_id.short(), cs.change_id);
    println!("Revision:   {}", cs.id.short());
    println!("Visibility: {}", format_visibility(&cs.visibility));
    let desc = if cs.description.is_empty() {
        "(no description)"
    } else {
        cs.description.as_str()
    };
    println!("Description: {desc}");
    if cs.has_conflicts {
        println!("Conflicts:  YES (unresolved first-class conflicts present)");
    }

    // Files grouped by Visibility Domain
    println!("\nFiles by Visibility Domain:");
    let mut conflict_paths = Vec::new();
    for (domain, &tree_hash) in &cs.domain_trees {
        let tree = repo.store.get_tree(tree_hash)?;
        println!("  [{}] ({} file(s))", domain, tree.entries.len());
        for (path, kind) in &tree.entries {
            match kind {
                EntryKind::File { size, .. } => {
                    println!("    {path} ({size} bytes)");
                }
                EntryKind::EncryptedSecret { key_epoch, .. } => {
                    println!("    {path} [encrypted, epoch={key_epoch}]");
                }
                EntryKind::Conflict { .. } => {
                    println!("    {path} [CONFLICT]");
                    conflict_paths.push(format!("{domain}:{path}"));
                }
            }
        }
    }

    // Diffs vs parent
    let parent_cs = match cs.parents.first() {
        Some(&p) => Some(repo.store.get_changeset(p)?),
        None => None,
    };

    let mut domains = BTreeSet::new();
    if let Some(ref p) = parent_cs {
        domains.extend(p.domain_trees.keys().cloned());
    }
    domains.extend(cs.domain_trees.keys().cloned());

    let mut diff_lines = Vec::new();
    for domain in &domains {
        let old_tree = repo.get_domain_tree_or_empty(parent_cs.as_ref(), domain)?;
        let new_tree = repo.get_domain_tree_or_empty(Some(cs), domain)?;
        for entry in diff_trees(&old_tree, &new_tree) {
            let code = match entry.status {
                DiffStatus::Added => "A",
                DiffStatus::Modified => "M",
                DiffStatus::Deleted => "D",
                DiffStatus::Conflicted => "C",
            };
            diff_lines.push(format!("  {code} [{domain}] {}", entry.path));
        }
    }

    println!("\nChanges vs parent:");
    if diff_lines.is_empty() {
        println!("  (no changes)");
    } else {
        for line in diff_lines {
            println!("{line}");
        }
    }

    if !conflict_paths.is_empty() {
        println!("\nUnresolved conflicts:");
        for p in conflict_paths {
            println!("  ! {p}");
        }
    }

    if !snap.warnings.is_empty() {
        println!("\nSecret scanner warnings:");
        for w in &snap.warnings {
            let loc = match w.line {
                Some(l) => format!("{}:{l}", w.path),
                None => w.path.clone(),
            };
            println!(
                "  [{:?}] {loc}: {} ({})",
                w.severity, w.message, w.redacted_match
            );
        }
    }

    Ok(())
}

pub fn cmd_diff(interdiff: bool, from: Option<String>, to: Option<String>) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;

    if interdiff {
        let v2 = match to {
            Some(ref spec) => repo.resolve_changeset(spec)?,
            None => snap.changeset.clone(),
        };
        let v1 = match from {
            Some(ref spec) => Some(repo.resolve_changeset(spec)?),
            None => find_interdiff_previous(&repo, &v2)?,
        };

        let Some(v1) = v1 else {
            println!("No previous revision for ChangeId {}", v2.change_id.short());
            return Ok(());
        };

        let v1_parent = match v1.parents.first() {
            Some(&p) => Some(repo.store.get_changeset(p)?),
            None => None,
        };
        let v2_parent = match v2.parents.first() {
            Some(&p) => Some(repo.store.get_changeset(p)?),
            None => None,
        };

        let mut domains = BTreeSet::new();
        domains.extend(v1.domain_trees.keys().cloned());
        domains.extend(v2.domain_trees.keys().cloned());

        println!(
            "# Interdiff for ChangeId {} ({} -> {})",
            v2.change_id.short(),
            v1.id.short(),
            v2.id.short()
        );

        let mut printed_any = false;
        for domain in domains {
            if domain.is_secret() {
                continue;
            }
            let v1_base = repo.get_domain_tree_or_empty(v1_parent.as_ref(), &domain)?;
            let v1_head = repo.get_domain_tree_or_empty(Some(&v1), &domain)?;
            let v2_base = repo.get_domain_tree_or_empty(v2_parent.as_ref(), &domain)?;
            let v2_head = repo.get_domain_tree_or_empty(Some(&v2), &domain)?;

            let patch = render_interdiff(&v1_base, &v1_head, &v2_base, &v2_head, |h| {
                repo.store.read_blob_bytes(h)
            })?;
            if !patch.is_empty() {
                print!("{patch}");
                printed_any = true;
            }
        }
        if !printed_any {
            println!("(no tree differences between revisions)");
        }
        return Ok(());
    }

    let to_cs = match to {
        Some(ref spec) => repo.resolve_changeset(spec)?,
        None => snap.changeset.clone(),
    };
    let from_cs = match from {
        Some(ref spec) => Some(repo.resolve_changeset(spec)?),
        None => match to_cs.parents.first() {
            Some(&p) => Some(repo.store.get_changeset(p)?),
            None => None,
        },
    };

    let mut domains = BTreeSet::new();
    if let Some(ref f) = from_cs {
        domains.extend(f.domain_trees.keys().cloned());
    }
    domains.extend(to_cs.domain_trees.keys().cloned());

    let mut printed_any = false;
    for domain in domains {
        if domain.is_secret() {
            continue;
        }
        let old_tree = repo.get_domain_tree_or_empty(from_cs.as_ref(), &domain)?;
        let new_tree = repo.get_domain_tree_or_empty(Some(&to_cs), &domain)?;
        for entry in diff_trees(&old_tree, &new_tree) {
            let old_bytes = read_entry_bytes(&repo, &old_tree, &entry.path)?;
            let new_bytes = read_entry_bytes(&repo, &new_tree, &entry.path)?;
            let patch = unified_diff(&entry.path, &old_bytes, &new_bytes);
            if !patch.is_empty() {
                print!("{patch}");
                printed_any = true;
            }
        }
    }
    if !printed_any {
        println!("(no differences)");
    }
    Ok(())
}

pub fn cmd_log(limit: usize, all_domains: bool) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let head = snap.changeset;

    let bookmarks = repo.store.list_bookmarks()?;
    let mut bookmarks_by_hash: BTreeMap<ObjectHash, Vec<String>> = BTreeMap::new();
    for (name, hash) in &bookmarks {
        bookmarks_by_hash
            .entry(*hash)
            .or_default()
            .push(name.clone());
    }

    let changesets = if all_domains {
        let mut all = repo.store.list_changesets()?;
        // Deduplicate by ChangeId (keep latest revision) or show latest-first across all domains
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        all
    } else {
        // Walk reachable DAG from `@` and all bookmarks
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(head.id);
        visited.insert(head.id);
        for &h in bookmarks.values() {
            if visited.insert(h) {
                queue.push_back(h);
            }
        }
        let mut list = Vec::new();
        while let Some(id) = queue.pop_front() {
            if let Ok(cs) = repo.store.get_changeset(id) {
                for &p in &cs.parents {
                    if visited.insert(p) {
                        queue.push_back(p);
                    }
                }
                list.push(cs);
            }
        }
        list.sort_by(|a, b| {
            // Put `@` first, then newest first
            let a_is_head = a.id == head.id;
            let b_is_head = b.id == head.id;
            b_is_head
                .cmp(&a_is_head)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| b.id.cmp(&a.id))
        });
        list
    };

    for cs in changesets.into_iter().take(limit) {
        let marker = if cs.id == head.id { "@" } else { "o" };
        let bm = bookmarks_by_hash
            .get(&cs.id)
            .map(|names| format!(" [{}]", names.join(", ")))
            .unwrap_or_default();
        let conflict = if cs.has_conflicts { " [CONFLICT]" } else { "" };
        let vis = format_visibility(&cs.visibility);
        let committer_str = match &cs.committer {
            Actor::Human(_) => String::new(),
            Actor::Agent { harness, model, .. } => format!(" agent={harness}:{model}"),
        };
        let desc = if cs.description.is_empty() {
            "(no description)"
        } else {
            cs.description.lines().next().unwrap_or("")
        };

        println!(
            "{marker} {} {} [{vis}]{bm}{conflict} {} <{}>{committer_str}",
            cs.change_id.short(),
            cs.id.short(),
            cs.author.name,
            cs.author.email
        );
        println!("    {desc}");
    }

    Ok(())
}

pub fn cmd_new(
    message: Option<String>,
    visibility: Option<String>,
    reveal_on_land: bool,
    agent: Option<String>,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let parent = snap.changeset;

    let vis_policy = match visibility {
        Some(ref raw) if raw != "public" => {
            let domain = DomainId::new(raw)?;
            VisibilityPolicy::private(domain, reveal_on_land)
        }
        _ => VisibilityPolicy {
            primary_domain: DomainId::public(),
            reveal_on_land,
            embargo: None,
        },
    };

    let committer = match agent {
        Some(ref spec) => parse_agent_spec(spec, repo.config.author.clone()),
        None => Actor::Human(repo.config.author.clone()),
    };

    let new_cs = ChangeSetBuilder::new(repo.config.author.clone())
        .parents(vec![parent.id])
        .public_parents(vec![parent.public_projection_hash])
        .domain_trees(parent.domain_trees.clone())
        .committer(committer)
        .visibility(vis_policy)
        .has_conflicts(parent.has_conflicts)
        .description(message.unwrap_or_default())
        .build();

    repo.store.put_changeset(&new_cs)?;
    repo.update_active_workspace_head(&new_cs)?;
    repo.append_op(
        OpKind::NewChange {
            change_id: new_cs.change_id,
        },
        format!(
            "Created new ChangeSet {} ({})",
            new_cs.change_id.short(),
            new_cs.id.short()
        ),
    )?;

    println!(
        "Working copy now at {} ({}) [{}]",
        new_cs.change_id.short(),
        new_cs.id.short(),
        format_visibility(&new_cs.visibility)
    );
    Ok(())
}

pub fn cmd_describe(message: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cur = snap.changeset;

    let updated = ChangeSetBuilder::new(cur.author.clone())
        .change_id(cur.change_id)
        .previous_revision(Some(cur.id))
        .parents(cur.parents.clone())
        .public_parents(cur.public_parents.clone())
        .domain_trees(cur.domain_trees.clone())
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(cur.has_conflicts)
        .description(message.clone())
        .build();

    repo.store.put_changeset(&updated)?;
    repo.update_active_workspace_head(&updated)?;
    repo.append_op(
        OpKind::Describe {
            change_id: updated.change_id,
        },
        format!("Described {}: {}", updated.change_id.short(), message),
    )?;

    println!(
        "Updated {} ({} -> {}): {}",
        updated.change_id.short(),
        cur.id.short(),
        updated.id.short(),
        updated.description
    );
    Ok(())
}

fn find_interdiff_previous(repo: &Repo, current: &ChangeSet) -> Result<Option<ChangeSet>> {
    let Some(first_prev_id) = current.previous_revision else {
        return Ok(None);
    };
    let first_prev = repo.store.get_changeset(first_prev_id)?;
    if first_prev.domain_trees != current.domain_trees {
        return Ok(Some(first_prev));
    }

    // Walk back through metadata-only revisions (e.g. `describe`) to find the latest revision
    // that had a distinct tree state, falling back to `first_prev` if none differ.
    let mut cursor = first_prev.previous_revision;
    let mut hops = 0usize;
    while let Some(prev_id) = cursor {
        hops += 1;
        if hops > 64 {
            break;
        }
        let candidate = repo.store.get_changeset(prev_id)?;
        if candidate.domain_trees != current.domain_trees {
            return Ok(Some(candidate));
        }
        cursor = candidate.previous_revision;
    }

    Ok(Some(first_prev))
}

fn read_entry_bytes(repo: &Repo, tree: &DomainTree, path: &str) -> Result<Vec<u8>> {
    match tree.entries.get(path) {
        None => Ok(Vec::new()),
        Some(EntryKind::File { blob_hash, .. }) => Ok(repo.store.read_blob_bytes(*blob_hash)?),
        Some(EntryKind::EncryptedSecret { .. }) => Ok(b"[encrypted secret]\n".to_vec()),
        Some(EntryKind::Conflict { term, .. }) => Ok(materialize_conflict(term, path, |h| {
            repo.store.read_blob_bytes(h)
        })?),
    }
}

pub fn format_visibility(vis: &VisibilityPolicy) -> String {
    match &vis.embargo {
        Some(EmbargoState::Active { advisory_id, .. }) => {
            format!("embargo:{advisory_id} ACTIVE")
        }
        Some(EmbargoState::Published { advisory_id, .. }) => {
            format!("{} (embargo:{advisory_id} PUBLISHED)", vis.primary_domain)
        }
        None => {
            if vis.reveal_on_land && !vis.primary_domain.is_public() {
                format!("{} (reveal-on-land)", vis.primary_domain)
            } else {
                vis.primary_domain.to_string()
            }
        }
    }
}
