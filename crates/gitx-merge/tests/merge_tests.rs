use gitx_merge::{MergeOutcome, merge_bytes};
use proptest::prelude::*;
use std::collections::BTreeMap;

#[test]
fn fast_paths_clean() {
    let base = b"hello\n";
    let modified = b"world\n";

    assert_eq!(
        merge_bytes("a.txt", base, modified, modified),
        MergeOutcome::Clean(modified.to_vec())
    );
    assert_eq!(
        merge_bytes("a.txt", base, base, modified),
        MergeOutcome::Clean(modified.to_vec())
    );
    assert_eq!(
        merge_bytes("a.txt", base, modified, base),
        MergeOutcome::Clean(modified.to_vec())
    );
}

#[test]
fn line_merge_non_overlapping_edits_clean() {
    let base = b"line 1\nline 2\nline 3\nline 4\nline 5\n";
    let ours = b"LINE ONE\nline 2\nline 3\nline 4\nline 5\n";
    let theirs = b"line 1\nline 2\nline 3\nline 4\nLINE FIVE\n";

    let outcome = merge_bytes("notes.txt", base, ours, theirs);
    assert_eq!(
        outcome,
        MergeOutcome::Clean(b"LINE ONE\nline 2\nline 3\nline 4\nLINE FIVE\n".to_vec())
    );
}

#[test]
fn line_merge_convergent_edits_clean() {
    let base = b"a\nmid\nb\nc\nd\n";
    let ours = b"a\nmid\nB_FIXED\nc\nD_OURS\n";
    let theirs = b"A_THEIRS\nmid\nB_FIXED\nc\nd\n";

    let outcome = merge_bytes("file.rs", base, ours, theirs);
    assert_eq!(
        outcome,
        MergeOutcome::Clean(b"A_THEIRS\nmid\nB_FIXED\nc\nD_OURS\n".to_vec())
    );
}

#[test]
fn line_merge_overlapping_conflict_markers() {
    let base = b"header\nvalue = 1\nfooter\n";
    let ours = b"header\nvalue = 2\nfooter\n";
    let theirs = b"header\nvalue = 3\nfooter\n";

    let outcome = merge_bytes("config.rs", base, ours, theirs);
    match outcome {
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            assert_eq!(hunks, 1);
            let text = String::from_utf8(materialized).unwrap();
            assert_eq!(
                text,
                "header\n\
                 <<<<<<< OURS\n\
                 value = 2\n\
                 ||||||| BASE\n\
                 value = 1\n\
                 =======\n\
                 value = 3\n\
                 >>>>>>> THEIRS\n\
                 footer\n"
            );
        }
        MergeOutcome::Clean(_) => panic!("expected conflict"),
    }
}

#[test]
fn line_merge_multiple_conflict_hunks() {
    let base = b"a\nb\nc\nd\ne\n";
    let ours = b"A1\nb\nc\nD1\ne\n";
    let theirs = b"A2\nb\nc\nD2\ne\n";

    let outcome = merge_bytes("multi.txt", base, ours, theirs);
    match outcome {
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            assert_eq!(hunks, 2);
            let text = String::from_utf8(materialized).unwrap();
            assert!(text.contains("A1\n||||||| BASE\na\n=======\nA2\n"));
            assert!(text.contains("D1\n||||||| BASE\nd\n=======\nD2\n"));
        }
        MergeOutcome::Clean(_) => panic!("expected 2 conflict hunks"),
    }
}

#[test]
fn line_merge_same_point_insertions_conflict() {
    let base = b"start\nend\n";
    let ours = b"start\nfrom_ours\nend\n";
    let theirs = b"start\nfrom_theirs\nend\n";

    let outcome = merge_bytes("list.txt", base, ours, theirs);
    assert!(outcome.is_conflict());
    if let MergeOutcome::Conflict {
        materialized,
        hunks,
    } = outcome
    {
        assert_eq!(hunks, 1);
        let text = String::from_utf8(materialized).unwrap();
        assert!(text.contains("<<<<<<< OURS\nfrom_ours\n"));
        assert!(text.contains("||||||| BASE\n=======\nfrom_theirs\n>>>>>>> THEIRS\n"));
    }
}

#[test]
fn line_merge_transitive_overlapping_chain() {
    let base = b"0\n1\n2\n3\n4\n5\n6\n";
    // ours modifies [0,2) and [3,5); theirs modifies [1,4) bridging both!
    let ours = b"O0\nO1\n2\nO3\nO4\n5\n6\n";
    let theirs = b"0\nT1\nT2\nT3\n4\n5\n6\n";

    let outcome = merge_bytes("chain.txt", base, ours, theirs);
    match outcome {
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            assert_eq!(hunks, 1);
            let text = String::from_utf8(materialized).unwrap();
            assert!(text.contains("<<<<<<< OURS\nO0\nO1\n2\nO3\nO4\n"));
            assert!(text.contains("||||||| BASE\n0\n1\n2\n3\n4\n"));
            assert!(text.contains("=======\n0\nT1\nT2\nT3\n4\n>>>>>>> THEIRS\n5\n6\n"));
        }
        MergeOutcome::Clean(_) => panic!("expected single transitive conflict hunk"),
    }
}

#[test]
fn json_key_aware_merge_adjacent_additions_and_nested_objects() {
    let base = br#"{
  "name": "app",
  "deps": {
    "react": "18.0.0"
  }
}
"#;
    let ours = br#"{
  "name": "app",
  "deps": {
    "react": "18.0.0",
    "zod": "3.23.0"
  },
  "scripts": {
    "build": "vite build"
  }
}
"#;
    let theirs = br#"{
  "name": "app",
  "deps": {
    "react": "18.0.0",
    "axios": "1.7.0"
  },
  "scripts": {
    "test": "vitest"
  }
}
"#;

    let outcome = merge_bytes("package.json", base, ours, theirs);
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(val["name"], "app");
            assert_eq!(val["deps"]["react"], "18.0.0");
            assert_eq!(val["deps"]["zod"], "3.23.0");
            assert_eq!(val["deps"]["axios"], "1.7.0");
            assert_eq!(val["scripts"]["build"], "vite build");
            assert_eq!(val["scripts"]["test"], "vitest");
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean JSON merge, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn json_same_key_conflict_detected_even_with_reordered_keys() {
    let base = br#"{"a": 1, "b": 2}"#;
    let ours = br#"{"b": 2, "a": 10}"#;
    let theirs = br#"{"a": 20, "b": 2}"#;

    let outcome = merge_bytes("settings.json", base, ours, theirs);
    assert!(outcome.is_conflict());
    let text = String::from_utf8(outcome.into_bytes()).unwrap();
    assert!(text.contains("<<<<<<< OURS"));
    assert!(text.contains(">>>>>>> THEIRS"));
}

#[test]
fn toml_cargo_dependencies_merge_cleanly() {
    let base = br#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
"#;
    let ours = br#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }
"#;
    let theirs = br#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
axum = "0.8"
"#;

    let outcome = merge_bytes("Cargo.toml", base, ours, theirs);
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let parsed: toml::Table = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
            let deps = parsed["dependencies"].as_table().unwrap();
            assert_eq!(deps["serde"].as_str(), Some("1"));
            assert_eq!(deps["axum"].as_str(), Some("0.8"));
            assert_eq!(deps["tokio"]["version"].as_str(), Some("1"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean Cargo.toml merge, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn toml_same_dependency_version_conflict() {
    let base = b"[dependencies]\nserde = \"1.0\"\n";
    let ours = b"[dependencies]\nserde = \"1.0.200\"\n";
    let theirs = b"[dependencies]\nserde = \"1.0.210\"\n";

    let outcome = merge_bytes("Cargo.toml", base, ours, theirs);
    assert!(outcome.is_conflict());
    let text = String::from_utf8(outcome.into_bytes()).unwrap();
    assert!(text.contains("<<<<<<< OURS"));
    assert!(text.contains("||||||| BASE"));
    assert!(text.contains(">>>>>>> THEIRS"));
}

#[test]
fn binary_fallback_handles_non_utf8() {
    let base = [0x00, 0xFF, 0x01, 0xFE];
    let ours = [0x00, 0xFF, 0x02, 0xFE];
    let theirs = [0x00, 0xFF, 0x03, 0xFE];

    // Different binary edits -> conflict
    let conflict = merge_bytes("image.png", &base, &ours, &theirs);
    assert!(conflict.is_conflict());
    let markers = String::from_utf8(conflict.into_bytes()).unwrap();
    assert!(markers.contains("<<<<<<< OURS"));
    assert!(markers.contains("binary file image.png"));

    // Identical binary edits -> clean
    assert_eq!(
        merge_bytes("image.png", &base, &ours, &ours),
        MergeOutcome::Clean(ours.to_vec())
    );
    // Single-side binary edit -> clean
    assert_eq!(
        merge_bytes("image.png", &base, &base, &theirs),
        MergeOutcome::Clean(theirs.to_vec())
    );
}

proptest! {
    #[test]
    fn prop_merge_fast_path_invariants(
        base in proptest::collection::vec(any::<u8>(), 0..64),
        side in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assert_eq!(merge_bytes("f.txt", &base, &base, &side), MergeOutcome::Clean(side.clone()));
        prop_assert_eq!(merge_bytes("f.txt", &base, &side, &base), MergeOutcome::Clean(side.clone()));
        prop_assert_eq!(merge_bytes("f.txt", &base, &side, &side), MergeOutcome::Clean(side));
    }

    #[test]
    fn prop_line_merge_symmetry_of_cleanliness(
        base_lines in proptest::collection::vec("[a-e]{1,4}", 0..10),
        ours_lines in proptest::collection::vec("[a-e]{1,4}", 0..10),
        theirs_lines in proptest::collection::vec("[a-e]{1,4}", 0..10),
    ) {
        let to_bytes = |v: &[String]| {
            let mut s = v.join("\n");
            if !s.is_empty() { s.push('\n'); }
            s.into_bytes()
        };
        let b = to_bytes(&base_lines);
        let o = to_bytes(&ours_lines);
        let t = to_bytes(&theirs_lines);

        let ot = merge_bytes("doc.txt", &b, &o, &t);
        let to = merge_bytes("doc.txt", &b, &t, &o);
        prop_assert_eq!(ot.is_clean(), to.is_clean());
        if let (MergeOutcome::Clean(ab), MergeOutcome::Clean(ba)) = (ot, to) {
            prop_assert_eq!(ab, ba);
        }
    }

    #[test]
    fn prop_json_disjoint_key_additions_always_clean(
        ours_keys in proptest::collection::btree_map("o_[a-z]{1,6}", 0i64..1000, 1..6),
        theirs_keys in proptest::collection::btree_map("t_[a-z]{1,6}", 0i64..1000, 1..6),
    ) {
        let base_map: BTreeMap<String, i64> = [("base".to_string(), 0)].into_iter().collect();
        let mut ours_map = base_map.clone();
        ours_map.extend(ours_keys.clone());
        let mut theirs_map = base_map.clone();
        theirs_map.extend(theirs_keys.clone());

        let b = serde_json::to_vec_pretty(&base_map).unwrap();
        let o = serde_json::to_vec_pretty(&ours_map).unwrap();
        let t = serde_json::to_vec_pretty(&theirs_map).unwrap();

        let outcome = merge_bytes("data.json", &b, &o, &t);
        prop_assert!(outcome.is_clean());
        let merged: BTreeMap<String, i64> = serde_json::from_slice(outcome.as_bytes()).unwrap();
        prop_assert_eq!(merged.get("base"), Some(&0));
        for (k, v) in &ours_keys {
            prop_assert_eq!(merged.get(k), Some(v));
        }
        for (k, v) in &theirs_keys {
            prop_assert_eq!(merged.get(k), Some(v));
        }
    }

    #[test]
    fn prop_toml_disjoint_key_additions_always_clean(
        ours_keys in proptest::collection::btree_map("o_[a-z]{1,6}", "[0-9]\\.[0-9]", 1..5),
        theirs_keys in proptest::collection::btree_map("t_[a-z]{1,6}", "[0-9]\\.[0-9]", 1..5),
    ) {
        let make_toml = |deps: &BTreeMap<String, String>| {
            let mut s = String::from("[dependencies]\nbase = \"0.1\"\n");
            for (k, v) in deps {
                s.push_str(&format!("{k} = \"{v}\"\n"));
            }
            s.into_bytes()
        };

        let empty = BTreeMap::new();
        let b = make_toml(&empty);
        let o = make_toml(&ours_keys);
        let t = make_toml(&theirs_keys);

        let outcome = merge_bytes("Cargo.toml", &b, &o, &t);
        prop_assert!(outcome.is_clean());
        let parsed: toml::Table = std::str::from_utf8(outcome.as_bytes()).unwrap().parse().unwrap();
        let deps = parsed["dependencies"].as_table().unwrap();
        prop_assert_eq!(deps["base"].as_str(), Some("0.1"));
        for (k, v) in &ours_keys {
            prop_assert_eq!(deps[k].as_str(), Some(v.as_str()));
        }
        for (k, v) in &theirs_keys {
            prop_assert_eq!(deps[k].as_str(), Some(v.as_str()));
        }
    }
}

#[test]
fn yaml_nested_key_merge_clean_and_same_key_conflict() {
    let base = b"service:\n  name: gitx\n  port: 7878\nfeatures:\n  auth: true\n";
    let ours =
        b"service:\n  name: gitx\n  port: 7878\n  grpc_port: 50051\nfeatures:\n  auth: true\n";
    let theirs = b"service:\n  name: gitx\n  port: 7878\nfeatures:\n  auth: true\n  fleet: true\n";

    let outcome = merge_bytes("config.yaml", base, ours, theirs);
    assert!(
        outcome.is_clean(),
        "independent YAML keys must merge cleanly"
    );
    let text = String::from_utf8(outcome.into_bytes()).unwrap();
    assert!(text.contains("grpc_port: 50051"));
    assert!(text.contains("fleet: true"));

    // Conflicting edits on the same scalar key must produce a conflict.
    let ours_conflict = b"service:\n  port: 8080\n";
    let theirs_conflict = b"service:\n  port: 9090\n";
    let conflict = merge_bytes("config.yml", base, ours_conflict, theirs_conflict);
    assert!(conflict.is_conflict());
}
