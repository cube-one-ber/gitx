use chrono::{Duration, Utc};
use gitx_context::{
    Checkpoint, CodeAnchor, ContextId, ContextKind, ContextRecord, ContextStore,
    compute_hunk_fingerprint, extract_symbol_hint, relocate_anchor,
};
use gitx_core::{Actor, ChangeId, DomainId, Identity, ObjectHash};
use tempfile::tempdir;
use ulid::Ulid;

fn human_identity(name: &str) -> Identity {
    Identity {
        name: name.to_string(),
        email: format!("{name}@example.com"),
        key_fingerprint: None,
    }
}

fn agent_actor(session_id: &str) -> Actor {
    Actor::Agent {
        harness: "claude-code".to_string(),
        model: "claude-opus-4".to_string(),
        session_id: session_id.to_string(),
        initiated_by: human_identity("remy"),
    }
}

#[test]
fn anchor_relocation_survives_200_line_rebase_shift_and_reindentation() {
    let original_file = "\
pub fn validate_token(token: &str) -> bool {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.starts_with(\"gx_\") && trimmed.len() > 12
}
";
    let anchor = CodeAnchor::from_file_lines("src/auth.rs", original_file, 2, 6);
    assert_eq!(anchor.symbol.as_deref(), Some("validate_token"));

    // Exact position match on unchanged file.
    assert_eq!(relocate_anchor(&anchor, original_file), Some((2, 6)));

    // Simulate a rebase that inserts 210 unrelated lines above and re-indents the block.
    let mut shifted_file = String::new();
    for i in 1..=210 {
        shifted_file.push_str(&format!("// inserted rebase line {i}\n"));
    }
    shifted_file.push_str(
        "pub fn validate_token(token: &str) -> bool {\n\
             if true {\n\
                 let trimmed = token.trim();\n\
                 if trimmed.is_empty() {\n\
                     return false;\n\
                 }\n\
                 trimmed.starts_with(\"gx_\") && trimmed.len() > 12\n\
             } else {\n\
                 false\n\
             }\n\
         }\n",
    );

    // Original lines 2..=6 now start at line 213 (210 comments + fn header + `if true {`).
    assert_eq!(relocate_anchor(&anchor, &shifted_file), Some((213, 217)));
}

#[test]
fn anchor_relocation_fuzzy_matches_modified_hunk_and_rejects_deleted_hunk() {
    let original_file = "\
pub fn compute_rate(base: u64, tier: u8) -> u64 {
    let multiplier = match tier {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    base * multiplier
}
";
    let anchor = CodeAnchor::from_file_lines("src/billing.rs", original_file, 2, 8);

    // Shift down 50 lines AND modify 1 of 7 lines (ratio ~0.857 >= 0.6).
    let mut edited_file = String::new();
    for i in 1..=50 {
        edited_file.push_str(&format!("// header {i}\n"));
    }
    edited_file.push_str(
        "pub fn compute_rate(base: u64, tier: u8) -> u64 {\n\
             let multiplier = match tier {\n\
                 0 => 1,\n\
                 1 => 3,\n\
                 2 => 4,\n\
                 _ => 8,\n\
             };\n\
             base * multiplier\n\
         }\n",
    );

    let relocated = relocate_anchor(&anchor, &edited_file);
    assert_eq!(relocated, Some((52, 58)));

    // Completely unrelated file content should return None.
    let unrelated = "\
pub struct CompletelyDifferent {
    pub field_a: String,
    pub field_b: Vec<u8>,
}
";
    assert_eq!(relocate_anchor(&anchor, unrelated), None);
}

#[test]
fn strict_visibility_domain_filtering_blocks_private_prompts_from_public() {
    let store = ContextStore::in_memory().expect("in-memory store");
    let change_id = ChangeId::new();
    let rev = ObjectHash::of_bytes(b"rev-1");

    let file_v1 = "\
pub fn parse_webhook(payload: &[u8]) -> Result<(), String> {
    if payload.len() > 1024 * 1024 {
        return Err(\"payload too large\".into());
    }
    Ok(())
}
";
    let anchor = CodeAnchor::from_file_lines("src/webhook.rs", file_v1, 2, 4);

    let public_domain = DomainId::public();
    let private_domain = DomainId::private_user("remy").unwrap();
    let team_domain = DomainId::team("security").unwrap();

    // 1. Public design decision.
    let public_rec = ContextRecord {
        id: ContextId::new(),
        change_id,
        revision: rev,
        visibility: public_domain.clone(),
        author: Actor::Human(human_identity("remy")),
        kind: ContextKind::DesignDecision {
            title: "Cap webhook body at 1 MiB".to_string(),
            rationale: "Prevents unbounded memory allocation on unauthenticated endpoints."
                .to_string(),
        },
        anchors: vec![anchor.clone()],
        created_at: Utc::now() - Duration::seconds(10),
    };

    // 2. Private AI prompt (MUST NEVER leak to `public` queries!).
    let private_prompt = ContextRecord {
        id: ContextId::new(),
        change_id,
        revision: rev,
        visibility: private_domain.clone(),
        author: agent_actor("sess-secret-42"),
        kind: ContextKind::Prompt {
            prompt: "INTERNAL: customer Acme hit OOM on webhook endpoint, add 1MiB cap".to_string(),
            model: "claude-opus-4".to_string(),
            harness: "claude-code".to_string(),
            session_id: "sess-secret-42".to_string(),
        },
        anchors: vec![anchor.clone()],
        created_at: Utc::now() - Duration::seconds(5),
    };

    // 3. Security-team-only review thread.
    let team_review = ContextRecord {
        id: ContextId::new(),
        change_id,
        revision: rev,
        visibility: team_domain.clone(),
        author: Actor::Human(human_identity("alice")),
        kind: ContextKind::ReviewThread {
            reviewer: human_identity("alice"),
            body: "Matches internal DoS mitigation ticket SEC-91.".to_string(),
            resolved: true,
        },
        anchors: vec![anchor],
        created_at: Utc::now(),
    };

    store.add_record(&public_rec).unwrap();
    store.add_record(&private_prompt).unwrap();
    store.add_record(&team_review).unwrap();

    // Query with empty allowed_domains -> returns nothing.
    assert!(store.records_for_change(change_id, &[]).unwrap().is_empty());
    assert!(
        store
            .why("src/webhook.rs", 3, file_v1, &[])
            .unwrap()
            .is_empty()
    );

    // Public-only caller sees ONLY the public design decision.
    let pub_records = store
        .records_for_change(change_id, std::slice::from_ref(&public_domain))
        .unwrap();
    assert_eq!(pub_records.len(), 1);
    assert_eq!(pub_records[0].id, public_rec.id);

    // Shift the file down 120 lines and run `why` with public-only authorization.
    let mut shifted = String::new();
    for i in 1..=120 {
        shifted.push_str(&format!("// prepended line {i}\n"));
    }
    shifted.push_str(file_v1);

    let pub_why = store
        .why(
            "src/webhook.rs",
            123,
            &shifted,
            std::slice::from_ref(&public_domain),
        )
        .unwrap();
    assert_eq!(pub_why.len(), 1);
    assert_eq!(pub_why[0].record.id, public_rec.id);
    assert_eq!(pub_why[0].relocated_lines, (122, 124));

    // Caller with `public` + `private:user:remy` sees public decision and private prompt,
    // still NOT `team:security`.
    let user_why = store
        .why(
            "src/webhook.rs",
            123,
            &shifted,
            &[public_domain.clone(), private_domain.clone()],
        )
        .unwrap();
    assert_eq!(user_why.len(), 2);
    let ids: Vec<ContextId> = user_why.iter().map(|m| m.record.id).collect();
    assert!(ids.contains(&public_rec.id));
    assert!(ids.contains(&private_prompt.id));
    assert!(!ids.contains(&team_review.id));

    // Caller with all 3 domains sees all 3 records.
    let all_records = store
        .records_for_change(change_id, &[public_domain, private_domain, team_domain])
        .unwrap();
    assert_eq!(all_records.len(), 3);
}

#[test]
fn sqlite_wal_checkpoint_and_record_persistence_across_reopen() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("nested").join("context.sqlite");

    let t0 = Utc::now() - Duration::seconds(30);
    let t1 = Utc::now() - Duration::seconds(20);
    let t2 = Utc::now() - Duration::seconds(10);

    let cp1 = Checkpoint {
        id: Ulid::new(),
        workspace: "ws-main".to_string(),
        session_id: "sess-1".to_string(),
        actor: agent_actor("sess-1"),
        prompt_summary: "Scaffold parser module".to_string(),
        tree_hash: ObjectHash::of_bytes(b"tree-1"),
        parent_checkpoint: None,
        created_at: t0,
    };
    let cp2 = Checkpoint {
        id: Ulid::new(),
        workspace: "ws-main".to_string(),
        session_id: "sess-1".to_string(),
        actor: agent_actor("sess-1"),
        prompt_summary: "Add error recovery".to_string(),
        tree_hash: ObjectHash::of_bytes(b"tree-2"),
        parent_checkpoint: Some(cp1.id),
        created_at: t1,
    };
    let cp3 = Checkpoint {
        id: Ulid::new(),
        workspace: "ws-main".to_string(),
        session_id: "sess-1".to_string(),
        actor: agent_actor("sess-1"),
        prompt_summary: "Add unit tests".to_string(),
        tree_hash: ObjectHash::of_bytes(b"tree-3"),
        parent_checkpoint: Some(cp2.id),
        created_at: t2,
    };
    let cp_other_ws = Checkpoint {
        id: Ulid::new(),
        workspace: "ws-other".to_string(),
        session_id: "sess-2".to_string(),
        actor: agent_actor("sess-2"),
        prompt_summary: "Unrelated workspace work".to_string(),
        tree_hash: ObjectHash::of_bytes(b"tree-other"),
        parent_checkpoint: None,
        created_at: Utc::now(),
    };

    let change_id = ChangeId::new();
    let trace_rec = ContextRecord {
        id: ContextId::new(),
        change_id,
        revision: ObjectHash::of_bytes(b"rev-persist"),
        visibility: DomainId::public(),
        author: agent_actor("sess-1"),
        kind: ContextKind::AgentTrace {
            summary: "Ran cargo test and fixed clippy lint".to_string(),
            tool_calls: vec!["read_file".to_string(), "edit_file".to_string()],
            session_id: "sess-1".to_string(),
        },
        anchors: vec![CodeAnchor {
            path: "src/lib.rs".to_string(),
            line_start: 1,
            line_end: 1,
            symbol: Some("init".to_string()),
            hunk_fingerprint: compute_hunk_fingerprint(&["pub fn init() {}"]),
            snippet: "pub fn init() {}".to_string(),
        }],
        created_at: t2,
    };

    // Write and drop first handle.
    {
        let store = ContextStore::open(&db_path).expect("open store");
        store.save_checkpoint(&cp1).unwrap();
        store.save_checkpoint(&cp2).unwrap();
        store.save_checkpoint(&cp3).unwrap();
        store.save_checkpoint(&cp_other_ws).unwrap();
        store.add_record(&trace_rec).unwrap();
    }

    // Reopen from disk and verify everything persisted cleanly.
    let reopened = ContextStore::open(&db_path).expect("reopen store");

    let fetched = reopened
        .get_checkpoint(cp2.id)
        .unwrap()
        .expect("cp2 exists");
    assert_eq!(fetched, cp2);
    assert_eq!(fetched.parent_checkpoint, Some(cp1.id));

    assert_eq!(reopened.get_checkpoint(Ulid::new()).unwrap(), None);

    // Listing respects workspace isolation, newest-first ordering, and limit.
    let top2 = reopened.list_checkpoints("ws-main", 2).unwrap();
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].id, cp3.id);
    assert_eq!(top2[1].id, cp2.id);

    let all_main = reopened.list_checkpoints("ws-main", 10).unwrap();
    assert_eq!(all_main.len(), 3);
    assert_eq!(all_main[2].id, cp1.id);

    let other = reopened.list_checkpoints("ws-other", 10).unwrap();
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].id, cp_other_ws.id);

    // Record persisted as well and supports `why` query.
    let matches = reopened
        .why("src/lib.rs", 1, "pub fn init() {}\n", &[DomainId::public()])
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].record, trace_rec);
}

#[test]
fn extract_symbol_hint_handles_all_supported_keywords() {
    let mixed = "\
export const CONFIG_KEY = 'abc';
  const inner = 1;

function legacyHandler(req) {
  return req;
}

class OrderProcessor {
  // fn not_a_real_fn() {}
  run() {}
}

def python_worker(arg):
    value = arg + 1
    return value
";
    assert_eq!(extract_symbol_hint(mixed, 2).as_deref(), Some("CONFIG_KEY"));
    assert_eq!(
        extract_symbol_hint(mixed, 5).as_deref(),
        Some("legacyHandler")
    );
    assert_eq!(
        extract_symbol_hint(mixed, 10).as_deref(),
        Some("OrderProcessor")
    );
    assert_eq!(
        extract_symbol_hint(mixed, 14).as_deref(),
        Some("python_worker")
    );
}

#[test]
fn duplicate_snippets_disambiguate_by_symbol_hint_and_issue_links_roundtrip() {
    let original = "\
pub fn alpha() -> i32 {
    let acc = 10;
    acc + 1
}

pub fn beta() -> i32 {
    let acc = 10;
    acc + 1
}
";
    let beta_anchor = CodeAnchor::from_file_lines("src/math.rs", original, 7, 8);
    assert_eq!(beta_anchor.symbol.as_deref(), Some("beta"));

    // Shift `beta` way down below `alpha` and another identical helper `gamma`.
    let mut moved = String::from(
        "pub fn alpha() -> i32 {\n    let acc = 10;\n    acc + 1\n}\n\n\
         pub fn gamma() -> i32 {\n    let acc = 10;\n    acc + 1\n}\n\n",
    );
    for i in 1..=80 {
        moved.push_str(&format!("// filler {i}\n"));
    }
    moved.push_str("pub fn beta() -> i32 {\n    let acc = 10;\n    acc + 1\n}\n");

    // Even though `alpha` and `gamma` are closer to line 7, `beta` matches the symbol hint.
    // Lines: 10 lines before filler + 80 filler lines = 90 lines; line 91 = `pub fn beta`, 92..=93 = body.
    assert_eq!(relocate_anchor(&beta_anchor, &moved), Some((92, 93)));

    // Verify IssueLink context record + upsert idempotency in ContextStore.
    let store = ContextStore::in_memory().unwrap();
    let change_id = ChangeId::new();
    let rec = ContextRecord {
        id: ContextId::new(),
        change_id,
        revision: ObjectHash::of_bytes(b"rev-issue"),
        visibility: DomainId::public(),
        author: Actor::Human(human_identity("remy")),
        kind: ContextKind::IssueLink {
            tracker: "linear".to_string(),
            key: "GITX-42".to_string(),
            url: Some("https://linear.app/gitx/issue/GITX-42".to_string()),
        },
        anchors: vec![beta_anchor],
        created_at: Utc::now(),
    };

    store.add_record(&rec).unwrap();
    // Adding the same record ID again replaces cleanly without duplicating anchor rows.
    store.add_record(&rec).unwrap();

    let why_hits = store
        .why("src/math.rs", 92, &moved, &[DomainId::public()])
        .unwrap();
    assert_eq!(why_hits.len(), 1);
    assert_eq!(why_hits[0].record, rec);
    assert_eq!(why_hits[0].relocated_lines, (92, 93));
}

#[test]
fn tree_sitter_ast_anchor_extracts_rust_and_ts_symbols_and_relocates_across_refactors() {
    let ts_src = "\
export class InvoiceEngine {
  async calculateTax(amount: number): Promise<number> {
    const rate = 0.08;
    return amount * rate;
  }

  async renderPdf(amount: number): Promise<number> {
    const rate = 0.08;
    return amount * rate;
  }
}
";
    // Line 8..=9 is inside `renderPdf` (not `calculateTax`, which has identical body lines).
    let ts_anchor = CodeAnchor::from_file_lines("src/invoice.ts", ts_src, 8, 9);
    let sym = ts_anchor
        .symbol
        .as_deref()
        .expect("expected AST symbol for TS method");
    assert!(
        sym.contains("renderPdf"),
        "expected Tree-sitter symbol containing 'renderPdf', got '{sym}'"
    );

    // Move `renderPdf` below extra helper methods; relocation should still find `renderPdf`!
    let ts_refactored = "\
export class InvoiceEngine {
  async calculateTax(amount: number): Promise<number> {
    const rate = 0.08;
    return amount * rate;
  }

  async estimateFee(amount: number): Promise<number> {
    const rate = 0.08;
    return amount * rate;
  }

  async renderPdf(amount: number): Promise<number> {
    const rate = 0.08;
    return amount * rate;
  }
}
";
    assert_eq!(relocate_anchor(&ts_anchor, ts_refactored), Some((13, 14)));

    // Rust impl method AST anchoring.
    let rs_src = "\
pub struct Billing;

impl Billing {
    pub fn charge_card(cents: u64) -> u64 {
        let fee = 30;
        cents + fee
    }
}
";
    let rs_anchor = CodeAnchor::from_file_lines("src/billing.rs", rs_src, 5, 6);
    let rs_sym = rs_anchor
        .symbol
        .as_deref()
        .expect("expected AST symbol for Rust impl method");
    assert!(
        rs_sym.contains("charge_card"),
        "expected Tree-sitter symbol containing 'charge_card', got '{rs_sym}'"
    );
}
