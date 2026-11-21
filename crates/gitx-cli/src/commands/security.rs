use crate::repo::{Repo, save_json_file};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use gitx_core::{
    ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, FileMode, OpKind,
    VisibilityPolicy,
};
use gitx_crypto::{
    PublicKeyBundle, UserKeyPair, decrypt_secret, encrypt_secret, rotate_secret,
};
use gitx_store::ObjectStore;
use gitx_vfs::normalize_rel_path;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn cmd_secret_set(path: String, domain_raw: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let domain = DomainId::new(&domain_raw)?;
    if !domain.is_secret() {
        bail!("secret domain must start with 'secret:' (got '{domain}')");
    }

    let norm_path = normalize_rel_path(&path)?;
    let disk_path = repo.root.join(&norm_path);
    let plaintext = fs::read(&disk_path)
        .with_context(|| format!("failed to read secret file '{}'", disk_path.display()))?;

    let keyring = repo.load_keyring()?;
    let recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();

    let cur = repo.current_changeset()?;
    let mut secret_tree = repo.get_domain_tree_or_empty(Some(&cur), &domain)?;
    let key_epoch = match secret_tree.entries.get(&norm_path) {
        Some(EntryKind::EncryptedSecret { key_epoch, .. }) => *key_epoch,
        _ => 1,
    };

    let envelope = encrypt_secret(&domain, &norm_path, key_epoch, &plaintext, &recipients)?;
    let envelope_hash = repo.put_envelope(&envelope)?;

    secret_tree.insert(
        norm_path.clone(),
        EntryKind::EncryptedSecret {
            envelope_hash,
            key_epoch,
            mode: FileMode::Regular,
        },
    );
    let tree_hash = repo.store.put_tree(&secret_tree)?;

    let mut new_trees = cur.domain_trees.clone();
    new_trees.insert(domain.clone(), tree_hash);

    let updated = ChangeSetBuilder::new(cur.author.clone())
        .change_id(cur.change_id)
        .previous_revision(Some(cur.id))
        .parents(cur.parents.clone())
        .public_parents(cur.public_parents.clone())
        .domain_trees(new_trees)
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(cur.has_conflicts)
        .description(cur.description.clone())
        .build();

    repo.store.put_changeset(&updated)?;
    repo.update_active_workspace_head(&updated)?;
    repo.append_op(
        OpKind::SecretUpdate {
            domain: domain.to_string(),
            path: norm_path.clone(),
            key_epoch,
        },
        format!("Encrypted secret '{norm_path}' in {domain} (epoch {key_epoch})"),
    )?;

    println!(
        "Stored encrypted secret '{}' in domain '{}' (epoch {}, recipients: {}, envelope: {})",
        norm_path,
        domain,
        key_epoch,
        recipients.len(),
        envelope_hash.short()
    );
    Ok(())
}

pub fn cmd_secret_get(path: String, domain_raw: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let domain = DomainId::new(&domain_raw)?;
    let norm_path = normalize_rel_path(&path)?;

    let cur = repo.current_changeset()?;
    let secret_tree = repo.get_domain_tree_or_empty(Some(&cur), &domain)?;
    let entry = secret_tree
        .entries
        .get(&norm_path)
        .ok_or_else(|| anyhow!("secret '{norm_path}' not found in domain '{domain}'"))?;

    let EntryKind::EncryptedSecret {
        envelope_hash,
        key_epoch,
        ..
    } = entry
    else {
        bail!("entry '{norm_path}' in '{domain}' is not an encrypted secret");
    };

    let envelope = repo.get_envelope(*envelope_hash)?;
    let keypair = repo.load_local_keypair()?;
    let plaintext = decrypt_secret(&envelope, &norm_path, &keypair)?;

    if let Ok(mut audit) = repo.load_audit_log() {
        audit.record_decrypt(keypair.fingerprint(), domain, &norm_path, *key_epoch);
        let _ = repo.save_audit_log(&audit);
    }

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&plaintext)?;
    stdout.flush()?;
    Ok(())
}

pub fn cmd_secret_keygen(name: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let keypair = UserKeyPair::generate_with_label(&name);
    let key_file = repo.keys_dir().join(format!("{name}.key.json"));
    save_json_file(&key_file, &keypair.to_secret_bundle())?;

    let pub_json = serde_json::to_string(&keypair.public_bundle())?;
    eprintln!(
        "Generated keypair '{}' (fingerprint: {}, saved: {})",
        name,
        keypair.fingerprint(),
        key_file.display()
    );
    println!("{pub_json}");
    Ok(())
}

pub fn cmd_secret_grant(name: String, pubkey_json: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let raw_json = if Path::new(&pubkey_json).is_file() {
        fs::read_to_string(&pubkey_json)?
    } else {
        pubkey_json
    };

    let bundle: PublicKeyBundle = serde_json::from_str(&raw_json)
        .context("failed to parse PublicKeyBundle JSON")?;
    let fp = bundle.fingerprint();

    let mut keyring = repo.load_keyring()?;
    keyring.recipients.insert(name.clone(), bundle);
    repo.save_keyring(&keyring)?;

    println!("Granted secret recipient '{}' (fingerprint: {})", name, fp);
    Ok(())
}

pub fn cmd_secret_rotate(
    path: String,
    domain_raw: String,
    drop: Option<String>,
) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let domain = DomainId::new(&domain_raw)?;
    let norm_path = normalize_rel_path(&path)?;

    let mut keyring = repo.load_keyring()?;
    let keypair = UserKeyPair::from_secret_bundle(&keyring.local)?;

    let mut dropped_fps = Vec::new();
    if let Some(ref drop_spec) = drop {
        let keys_to_remove: Vec<String> = keyring
            .recipients
            .iter()
            .filter(|(name, bundle)| *name == drop_spec || bundle.fingerprint() == *drop_spec)
            .map(|(name, bundle)| {
                dropped_fps.push(bundle.fingerprint());
                name.clone()
            })
            .collect();
        for k in keys_to_remove {
            keyring.recipients.remove(&k);
        }
        if dropped_fps.is_empty() {
            dropped_fps.push(drop_spec.clone());
        }
        repo.save_keyring(&keyring)?;
    }

    let recipients: Vec<PublicKeyBundle> = keyring.recipients.values().cloned().collect();
    if recipients.is_empty() {
        bail!("cannot rotate secret: zero remaining recipients");
    }

    let cur = repo.current_changeset()?;
    let mut secret_tree = repo.get_domain_tree_or_empty(Some(&cur), &domain)?;
    let entry = secret_tree
        .entries
        .get(&norm_path)
        .ok_or_else(|| anyhow!("secret '{norm_path}' not found in domain '{domain}'"))?;

    let EntryKind::EncryptedSecret {
        envelope_hash,
        mode,
        ..
    } = *entry
    else {
        bail!("entry '{norm_path}' in '{domain}' is not an encrypted secret");
    };

    let old_env = repo.get_envelope(envelope_hash)?;
    let rotated = rotate_secret(&old_env, &norm_path, &keypair, &recipients)?;
    let new_hash = repo.put_envelope(&rotated)?;

    secret_tree.insert(
        norm_path.clone(),
        EntryKind::EncryptedSecret {
            envelope_hash: new_hash,
            key_epoch: rotated.key_epoch,
            mode,
        },
    );
    let tree_hash = repo.store.put_tree(&secret_tree)?;
    let mut new_trees = cur.domain_trees.clone();
    new_trees.insert(domain.clone(), tree_hash);

    let updated = ChangeSetBuilder::new(cur.author.clone())
        .change_id(cur.change_id)
        .previous_revision(Some(cur.id))
        .parents(cur.parents.clone())
        .public_parents(cur.public_parents.clone())
        .domain_trees(new_trees)
        .committer(cur.committer.clone())
        .visibility(cur.visibility.clone())
        .has_conflicts(cur.has_conflicts)
        .description(cur.description.clone())
        .build();

    repo.store.put_changeset(&updated)?;
    repo.update_active_workspace_head(&updated)?;
    repo.append_op(
        OpKind::SecretUpdate {
            domain: domain.to_string(),
            path: norm_path.clone(),
            key_epoch: rotated.key_epoch,
        },
        format!(
            "Rotated secret '{norm_path}' in {domain} to epoch {}",
            rotated.key_epoch
        ),
    )?;

    if let Ok(mut audit) = repo.load_audit_log() {
        for fp in &dropped_fps {
            audit.record_revoke(fp.clone(), domain.clone());
            let exposed = audit.rotation_report_for_revoked(fp);
            if !exposed.is_empty() {
                println!(
                    "Rotation audit for revoked key '{}': {} exposed version(s)",
                    fp,
                    exposed.len()
                );
            }
        }
        let _ = repo.save_audit_log(&audit);
    }

    println!(
        "Rotated secret '{}' in '{}' to epoch {} (recipients: {}, envelope: {})",
        norm_path,
        domain,
        rotated.key_epoch,
        rotated.recipients().len(),
        new_hash.short()
    );
    Ok(())
}

pub fn cmd_embargo_create(advisory: String, allow: Vec<String>, message: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let parent = snap.changeset;

    let mut allowed_domains = Vec::new();
    for item in allow {
        for part in item.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let domain = if part.contains(':') {
                DomainId::new(part)?
            } else {
                DomainId::team(part)?
            };
            allowed_domains.push(domain);
        }
    }

    let policy = VisibilityPolicy::embargoed(&advisory, allowed_domains.clone(), None)?;
    let embargo_domain = policy.primary_domain.clone();

    // Isolate files inside the embargo domain tree so nothing leaks into `public`.
    let pub_tree = repo.get_domain_tree_or_empty(Some(&parent), &DomainId::public())?;
    let mut embargo_tree = DomainTree::new(embargo_domain.clone());
    embargo_tree.entries = pub_tree.entries;
    let embargo_tree_hash = repo.store.put_tree(&embargo_tree)?;

    let mut domain_trees = parent.domain_trees.clone();
    domain_trees.insert(embargo_domain.clone(), embargo_tree_hash);

    let cs = ChangeSetBuilder::new(repo.config.author.clone())
        .parents(vec![parent.id])
        .public_parents(vec![parent.public_projection_hash])
        .domain_trees(domain_trees)
        .visibility(policy)
        .description(message)
        .build();

    repo.store.put_changeset(&cs)?;
    repo.update_active_workspace_head(&cs)?;
    repo.append_op(
        OpKind::NewChange {
            change_id: cs.change_id,
        },
        format!("Created embargo '{advisory}' ({})", cs.id.short()),
    )?;

    let allowed_list: Vec<String> = allowed_domains.iter().map(ToString::to_string).collect();
    println!(
        "Created embargoed ChangeSet {} ({}) domain={} allowed=[{}]",
        cs.change_id.short(),
        cs.id.short(),
        embargo_domain,
        allowed_list.join(", ")
    );
    Ok(())
}

pub fn cmd_embargo_publish(advisory: String) -> Result<()> {
    let repo = Repo::open(&env::current_dir()?)?;
    let snap = repo.snapshot_working_copy()?;
    let current = snap.changeset;

    let target_cs = if matches!(
        &current.visibility.embargo,
        Some(EmbargoState::Active { advisory_id, .. }) if advisory_id == &advisory
    ) {
        current.clone()
    } else {
        repo.store
            .list_changesets()?
            .into_iter()
            .rev()
            .find(|cs| {
                matches!(
                    &cs.visibility.embargo,
                    Some(EmbargoState::Active { advisory_id, .. }) if advisory_id == &advisory
                )
            })
            .ok_or_else(|| anyhow!("no active embargo found for advisory '{advisory}'"))?
    };

    let embargo_domain = DomainId::embargo(&advisory)?;
    let embargo_tree = repo.get_domain_tree_or_empty(Some(&target_cs), &embargo_domain)?;
    let mut pub_tree = repo.get_domain_tree_or_empty(Some(&target_cs), &DomainId::public())?;
    for (path, kind) in embargo_tree.entries {
        pub_tree.insert(path, kind);
    }
    let pub_tree_hash = repo.store.put_tree(&pub_tree)?;

    let mut new_trees = target_cs.domain_trees.clone();
    new_trees.remove(&embargo_domain);
    new_trees.insert(DomainId::public(), pub_tree_hash);

    let published_policy = VisibilityPolicy {
        primary_domain: DomainId::public(),
        reveal_on_land: false,
        embargo: Some(EmbargoState::Published {
            advisory_id: advisory.clone(),
            published_at: Utc::now(),
        }),
    };

    let published_cs = ChangeSetBuilder::new(target_cs.author.clone())
        .change_id(target_cs.change_id)
        .previous_revision(Some(target_cs.id))
        .parents(target_cs.parents.clone())
        .public_parents(target_cs.public_parents.clone())
        .domain_trees(new_trees)
        .committer(target_cs.committer.clone())
        .visibility(published_policy)
        .has_conflicts(target_cs.has_conflicts)
        .description(target_cs.description.clone())
        .build();

    repo.store.put_changeset(&published_cs)?;
    if current.change_id == published_cs.change_id {
        repo.update_active_workspace_head(&published_cs)?;
    }

    repo.append_op(
        OpKind::EmbargoPublish {
            advisory_id: advisory.clone(),
        },
        format!("Published embargo '{advisory}' -> {}", published_cs.id.short()),
    )?;

    println!(
        "Published embargo '{}' -> ChangeSet {} ({}) is now public",
        advisory,
        published_cs.change_id.short(),
        published_cs.id.short()
    );
    Ok(())
}
