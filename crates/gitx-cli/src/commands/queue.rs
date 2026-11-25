use crate::commands::remote::{
    AuthHeaders, ResolvedRemote, build_commit_payload, build_http_client, build_push_delta,
    collect_pushable_files, decode_tree_file_bytes, fetch_remote_tree_optional, load_remotes,
    parse_json_response, parse_remote_url, resolve_auth_headers, resolve_rpc_target, run_async,
    save_remotes, select_remote_entry, short_hex, short_id,
};
use crate::repo::Repo;
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use gitx_server::{CommitResponse, DrainResponse, EnqueueResponse, QueueListResponse, QueueStatus};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;

pub fn cmd_queue_enqueue(
    remote: Option<String>,
    url: Option<String>,
    target: Option<String>,
    message: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let cs = snap.changeset;

    if cs.has_conflicts {
        bail!(
            "cannot enqueue ChangeSet {} while it contains unresolved conflicts",
            cs.change_id.short()
        );
    }

    let target_bm = target.unwrap_or_else(|| repo.config.default_branch.clone());
    let (resolved, auth, base_rev_hint) = if let Some(ref direct_url) = url {
        let (base_url, owner, repo_name) = parse_remote_url(direct_url, None, None)?;
        let resolved = ResolvedRemote {
            name: None,
            base_url,
            owner,
            repo: repo_name,
        };
        let auth = resolve_auth_headers(token.as_deref(), None, Some(&repo.config.author));
        (resolved, auth, None)
    } else {
        let cfg = load_remotes(&repo.gitx_dir)?;
        let (name, entry) = select_remote_entry(&cfg, remote.as_deref())?;
        let auth = resolve_auth_headers(
            token.as_deref(),
            entry.token.as_deref(),
            Some(&repo.config.author),
        );
        let base_hint = entry
            .remote_heads
            .get(&target_bm)
            .cloned()
            .or_else(|| entry.last_pulled_head.clone())
            .or_else(|| entry.last_pushed_head.clone());
        let resolved = ResolvedRemote {
            name: Some(name),
            base_url: entry.url.clone(),
            owner: entry.owner.clone(),
            repo: entry.repo.clone(),
        };
        (resolved, auth, base_hint)
    };

    let (local_files, is_default_acl) = collect_pushable_files(&repo, &cs)?;
    let commit_msg = message
        .filter(|m| !m.trim().is_empty())
        .or_else(|| {
            if !cs.description.trim().is_empty() {
                Some(cs.description.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("Queue {} onto {target_bm}", cs.change_id.short()));

    let enq: EnqueueResponse = run_async(async {
        let client = build_http_client()?;

        // Compare against base_rev_hint if available on server, otherwise against target bookmark.
        let mut base_rev = base_rev_hint.as_deref();
        let mut remote_tree = if let Some(rev) = base_rev {
            fetch_remote_tree_optional(&client, &resolved, &auth, Some(rev)).await?
        } else {
            None
        };
        if remote_tree.is_none() {
            base_rev = None;
            remote_tree =
                fetch_remote_tree_optional(&client, &resolved, &auth, Some(&target_bm)).await?;
        }

        let parent_for_commit = base_rev
            .map(ToString::to_string)
            .or_else(|| remote_tree.as_ref().and_then(|t| t.rev.clone()));

        let mut remote_files = BTreeMap::new();
        if let Some(ref tree) = remote_tree {
            for entry in &tree.files {
                remote_files.insert(entry.path.clone(), decode_tree_file_bytes(entry)?);
            }
        }

        let (mut upload, deletions) = build_push_delta(&local_files, is_default_acl, &remote_files);
        if upload.is_empty() && deletions.is_empty() {
            if let Some(acl_bytes) = local_files.get(".gitxacl") {
                upload.insert(".gitxacl".to_string(), BASE64_STANDARD.encode(acl_bytes));
            } else {
                bail!("nothing to enqueue (no local changes compared to remote base)");
            }
        }

        // 1. Lock-free server-side commit (`update_target: false`).
        let payload = build_commit_payload(
            &cs,
            &upload,
            &deletions,
            &commit_msg,
            &target_bm,
            parent_for_commit.as_deref(),
            false,
        );
        let commit_resp = auth
            .apply(client.post(resolved.api_url("commit")))
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("failed to upload changeset to {}", resolved.base_url))?;
        let committed: CommitResponse =
            parse_json_response(commit_resp, "upload changeset for merge queue").await?;

        // 2. Enqueue onto target bookmark.
        let enq_resp = auth
            .apply(client.post(resolved.api_url("queue/enqueue")))
            .json(&json!({
                "changeset_id": committed.changeset_id,
                "target": target_bm,
            }))
            .send()
            .await
            .with_context(|| format!("failed to enqueue changeset on {}", resolved.base_url))?;
        parse_json_response(enq_resp, "enqueue changeset").await
    })?;

    println!(
        "Enqueued ChangeSet on {} (target: {}):",
        resolved.full_name(),
        enq.entry.target
    );
    println!("  queue_id:     #{}", enq.entry.id);
    println!("  changeset_id: {}", enq.entry.changeset_id);
    println!("  change_id:    {}", enq.entry.change_id);
    println!("  status:       {}", format_queue_status(&enq.entry.status));
    println!("  queue_depth:  {}", enq.queue_depth);
    Ok(())
}

pub fn cmd_queue_list(
    remote: Option<String>,
    url: Option<String>,
    target: Option<String>,
    pending_only: bool,
    token: Option<String>,
) -> Result<()> {
    let (resolved, auth) = resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;
    let target_bm = target.unwrap_or_else(|| "master".to_string());

    let list: QueueListResponse = run_async(async {
        let client = build_http_client()?;
        let mut params: Vec<(&str, String)> = vec![("target", target_bm.clone())];
        if pending_only {
            params.push(("pending_only", "true".to_string()));
        }
        let resp = auth
            .apply(client.get(resolved.api_url("queue")))
            .query(&params)
            .send()
            .await
            .with_context(|| format!("failed to list merge queue on {}", resolved.base_url))?;
        parse_json_response(resp, "list merge queue").await
    })?;

    println!(
        "Merge queue for {} (target: {}, pending: {}):",
        resolved.full_name(),
        list.target,
        list.pending_count
    );
    if list.entries.is_empty() {
        println!("  (empty)");
        return Ok(());
    }

    for entry in &list.entries {
        println!(
            "  #{} [{}] {} ({}) by {} at {}",
            entry.id,
            format_queue_status(&entry.status),
            short_hex(&entry.changeset_id),
            short_id(&entry.change_id, 10),
            entry.submitted_by,
            entry.enqueued_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
    Ok(())
}

pub fn cmd_queue_drain(
    remote: Option<String>,
    url: Option<String>,
    target: Option<String>,
    max_batch_size: Option<usize>,
    token: Option<String>,
) -> Result<()> {
    let cwd = env::current_dir()?;
    let maybe_repo = Repo::open(&cwd).ok();
    let target_bm = target.unwrap_or_else(|| {
        maybe_repo
            .as_ref()
            .map(|r| r.config.default_branch.clone())
            .unwrap_or_else(|| "master".to_string())
    });

    let (resolved, mut auth) =
        resolve_rpc_target(remote.as_deref(), url.as_deref(), token.as_deref())?;

    // Drain requires an authenticated principal unless caller explicitly passed anonymous token.
    let explicit_anon = token.as_deref().is_some_and(|t| {
        let tr = t.trim();
        tr.is_empty() || tr.eq_ignore_ascii_case("anonymous") || tr.eq_ignore_ascii_case("anon")
    });
    if auth.is_anonymous() && !explicit_anon {
        if let Some(ref repo) = maybe_repo {
            auth = AuthHeaders::from_repo_author(&repo.config.author);
        } else {
            auth.user = Some("gitx-cli".to_string());
        }
    }

    let drain: DrainResponse = run_async(async {
        let client = build_http_client()?;
        let mut body = json!({ "target": target_bm });
        if let Some(limit) = max_batch_size
            && let Some(map) = body.as_object_mut()
        {
            map.insert("max_batch_size".to_string(), json!(limit));
        }

        let resp = auth
            .apply(client.post(resolved.api_url("queue/drain")))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("failed to drain merge queue on {}", resolved.base_url))?;
        parse_json_response(resp, "drain merge queue").await
    })?;

    if let (Some(repo), Some(remote_name), Some(new_head)) = (
        maybe_repo.as_ref(),
        resolved.name.as_deref(),
        drain.new_head.as_deref(),
    ) && let Ok(mut cfg) = load_remotes(&repo.gitx_dir)
        && let Some(entry) = cfg.remotes.get_mut(remote_name)
    {
        entry
            .remote_heads
            .insert(drain.target.clone(), new_head.to_string());
        let _ = save_remotes(&repo.gitx_dir, &cfg);
    }

    println!(
        "Drained merge queue for {} (target: {}):",
        resolved.full_name(),
        drain.target
    );
    println!(
        "  land_seq:   {}",
        drain
            .land_seq
            .map(|n| n.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "  new_head:   {}",
        drain.new_head.as_deref().unwrap_or("none")
    );
    println!("  landed:     {}", drain.landed.len());
    println!("  conflicted: {}", drain.conflicted.len());
    println!("  rejected:   {}", drain.rejected.len());
    if !drain.resolved_conflicts.is_empty() {
        println!("  resolved:   {}", drain.resolved_conflicts.join(", "));
    }
    for e in &drain.landed {
        println!(
            "    [landed] #{} {} ({})",
            e.id,
            short_hex(&e.changeset_id),
            short_id(&e.change_id, 10)
        );
    }
    for e in &drain.conflicted {
        println!(
            "    [conflicted] #{} {}: {}",
            e.id,
            short_hex(&e.changeset_id),
            format_queue_status(&e.status)
        );
    }
    for e in &drain.rejected {
        println!(
            "    [rejected] #{} {}: {}",
            e.id,
            short_hex(&e.changeset_id),
            format_queue_status(&e.status)
        );
    }
    Ok(())
}

fn format_queue_status(status: &QueueStatus) -> String {
    match status {
        QueueStatus::Pending => "pending".to_string(),
        QueueStatus::Landed { land_seq } => format!("landed(seq={land_seq})"),
        QueueStatus::Conflicted { conflict_paths } => {
            format!("conflicted({})", conflict_paths.join(", "))
        }
        QueueStatus::Rejected { reason } => format!("rejected({reason})"),
    }
}
