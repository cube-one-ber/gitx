use gitx_merge::{AstSymbol, MergeOutcome, extract_ast_symbols, merge_bytes, symbol_at_line};

#[test]
fn rust_adjacent_pub_fn_additions_at_bottom_merge_cleanly() {
    let base = r#"pub fn existing(x: i32) -> i32 {
    x + 1
}
"#;
    let ours = r#"pub fn existing(x: i32) -> i32 {
    x + 1
}

/// Computes double the input.
#[inline]
pub fn double(x: i32) -> i32 {
    x * 2
}
"#;
    let theirs = r#"pub fn existing(x: i32) -> i32 {
    x + 1
}

/// Computes triple the input.
#[must_use]
pub fn triple(x: i32) -> i32 {
    x * 3
}
"#;

    let outcome = merge_bytes("src/math.rs", base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains("pub fn existing(x: i32) -> i32"));
            assert!(merged.contains("/// Computes double the input.\n#[inline]\npub fn double"));
            assert!(merged.contains("/// Computes triple the input.\n#[must_use]\npub fn triple"));
            // Verify merged output is valid Rust with all 3 functions
            let syms = extract_ast_symbols("src/math.rs", &merged);
            let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
            assert_eq!(names, vec!["existing", "double", "triple"]);
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean AST merge for disjoint Rust functions, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn rust_adjacent_use_imports_at_top_merge_cleanly() {
    let base = r#"use std::fmt;

pub fn greet() -> String {
    String::from("hi")
}
"#;
    let ours = r#"use std::fmt;
use std::collections::HashMap;

pub fn greet() -> String {
    String::from("hi")
}
"#;
    let theirs = r#"use std::fmt;
use std::path::PathBuf;

pub fn greet() -> String {
    String::from("hi")
}
"#;

    let outcome = merge_bytes("src/lib.rs", base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains("use std::fmt;"));
            assert!(merged.contains("use std::collections::HashMap;"));
            assert!(merged.contains("use std::path::PathBuf;"));
            assert!(merged.contains("pub fn greet() -> String"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean AST merge for Rust imports, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn rust_deduplicates_identical_additions_and_applies_clean_deletion() {
    let base = r#"pub fn keep() -> i32 {
    1
}

pub fn obsolete() -> i32 {
    0
}
"#;
    let ours = r#"pub fn keep() -> i32 {
    1
}

pub fn shared_helper() -> i32 {
    42
}

pub fn ours_only() -> i32 {
    10
}
"#;
    let theirs = r#"pub fn keep() -> i32 {
    1
}

pub fn obsolete() -> i32 {
    0
}

pub fn shared_helper() -> i32 {
    42
}

pub fn theirs_only() -> i32 {
    20
}
"#;

    let outcome = merge_bytes("src/ops.rs", base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains("pub fn keep()"));
            assert!(!merged.contains("pub fn obsolete()"));
            assert_eq!(merged.matches("pub fn shared_helper()").count(), 1);
            assert!(merged.contains("pub fn ours_only()"));
            assert!(merged.contains("pub fn theirs_only()"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean AST merge with deduplication and deletion, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn rust_disjoint_edits_inside_same_function_and_adjacent_additions_merge_cleanly() {
    let base = r#"pub fn process(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    d
}
"#;
    let ours = r#"pub fn process(x: i32) -> i32 {
    let a = x + 10;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    d
}

pub fn added_by_ours() -> bool {
    true
}
"#;
    let theirs = r#"pub fn process(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 40;
    d
}

pub fn added_by_theirs() -> bool {
    false
}
"#;

    let outcome = merge_bytes(
        "src/process.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains("let a = x + 10;"));
            assert!(merged.contains("let d = c + 40;"));
            assert!(merged.contains("pub fn added_by_ours()"));
            assert!(merged.contains("pub fn added_by_theirs()"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean AST merge combining body line-merge and disjoint additions, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn typescript_adjacent_export_function_and_interface_additions_merge_cleanly() {
    let base = r#"import { core } from "./core";

export interface BaseConfig {
  host: string;
}

export function init(cfg: BaseConfig): string {
  return core(cfg.host);
}
"#;
    let ours = r#"import { core } from "./core";
import { logger } from "./logger";

export interface BaseConfig {
  host: string;
}

export function init(cfg: BaseConfig): string {
  return core(cfg.host);
}

/** Auth token payload. */
export interface AuthOptions {
  token: string;
}

export function authenticate(opts: AuthOptions): boolean {
  return logger(opts.token);
}
"#;
    let theirs = r#"import { core } from "./core";
import { metrics } from "./metrics";

export interface BaseConfig {
  host: string;
}

export function init(cfg: BaseConfig): string {
  return core(cfg.host);
}

/** Telemetry settings. */
export interface MetricsConfig {
  enabled: boolean;
}

export function recordMetric(cfg: MetricsConfig): void {
  metrics(cfg.enabled);
}
"#;

    let outcome = merge_bytes(
        "src/service.ts",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains(r#"import { core } from "./core";"#));
            assert!(merged.contains(r#"import { logger } from "./logger";"#));
            assert!(merged.contains(r#"import { metrics } from "./metrics";"#));
            assert!(merged.contains("/** Auth token payload. */\nexport interface AuthOptions"));
            assert!(merged.contains("export function authenticate(opts: AuthOptions): boolean"));
            assert!(merged.contains("/** Telemetry settings. */\nexport interface MetricsConfig"));
            assert!(merged.contains("export function recordMetric(cfg: MetricsConfig): void"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean TypeScript AST merge, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn javascript_and_tsx_adjacent_additions_merge_cleanly() {
    let js_base = "export function baseFn() {\n  return 1;\n}\n";
    let js_ours = "export function baseFn() {\n  return 1;\n}\n\nexport const ALPHA = 2;\n";
    let js_theirs = "export function baseFn() {\n  return 1;\n}\n\nexport const BETA = 3;\n";

    let js_outcome = merge_bytes(
        "src/mod.mjs",
        js_base.as_bytes(),
        js_ours.as_bytes(),
        js_theirs.as_bytes(),
    );
    assert!(js_outcome.is_clean());
    let js_text = String::from_utf8(js_outcome.into_bytes()).unwrap();
    assert!(js_text.contains("export const ALPHA = 2;"));
    assert!(js_text.contains("export const BETA = 3;"));

    let tsx_base = "export function App() {\n  return <main />;\n}\n";
    let tsx_ours =
        "export function App() {\n  return <main />;\n}\n\nexport function Header() {\n  return <header />;\n}\n";
    let tsx_theirs =
        "export function App() {\n  return <main />;\n}\n\nexport function Footer() {\n  return <footer />;\n}\n";

    let tsx_outcome = merge_bytes(
        "src/App.tsx",
        tsx_base.as_bytes(),
        tsx_ours.as_bytes(),
        tsx_theirs.as_bytes(),
    );
    assert!(tsx_outcome.is_clean());
    let tsx_text = String::from_utf8(tsx_outcome.into_bytes()).unwrap();
    assert!(tsx_text.contains("export function Header()"));
    assert!(tsx_text.contains("export function Footer()"));
}

#[test]
fn incompatible_edit_to_same_line_of_same_function_conflicts() {
    let base = r#"pub fn compute(x: i32) -> i32 {
    x + 1
}
"#;
    let ours = r#"pub fn compute(x: i32) -> i32 {
    x + 2
}
"#;
    let theirs = r#"pub fn compute(x: i32) -> i32 {
    x + 3
}
"#;

    let outcome = merge_bytes(
        "src/compute.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            assert_eq!(hunks, 1);
            let text = String::from_utf8(materialized).unwrap();
            assert!(text.contains("<<<<<<< OURS"));
            assert!(text.contains("    x + 2"));
            assert!(text.contains("||||||| BASE"));
            assert!(text.contains("    x + 1"));
            assert!(text.contains("======="));
            assert!(text.contains("    x + 3"));
            assert!(text.contains(">>>>>>> THEIRS"));
        }
        MergeOutcome::Clean(bytes) => {
            panic!(
                "expected conflict on incompatible same-line edit, got clean:\n{}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
}

#[test]
fn syntax_broken_file_falls_back_cleanly_without_panicking() {
    let base = "pub fn broken( {\n    let x = 1;\n";
    let ours = "pub fn broken( {\n    let x = 2;\n";
    let theirs = "pub fn broken( {\n    let x = 3;\n";

    let outcome = merge_bytes(
        "src/broken.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            assert_eq!(hunks, 1);
            let text = String::from_utf8(materialized).unwrap();
            assert!(text.contains("<<<<<<< OURS"));
            assert!(text.contains("let x = 2;"));
            assert!(text.contains("let x = 3;"));
            assert!(text.contains(">>>>>>> THEIRS"));
        }
        MergeOutcome::Clean(_) => panic!("expected line-merge conflict fallback"),
    }

    // Symbol extraction on syntax-broken file also never panics.
    let _ = extract_ast_symbols("src/broken.rs", base);
    let _ = symbol_at_line("src/broken.rs", base, 1);
}

#[test]
fn extract_ast_symbols_and_symbol_at_line_rust() {
    let src = r#"use std::fmt;

/// A 2D point.
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn origin() -> Self {
        Self { x: 0.0, y: 0.0 }
    }
}

pub enum Direction {
    North,
    South,
}

pub fn distance(a: &Point, b: &Point) -> f64 {
    ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt()
}
"#;

    let symbols = extract_ast_symbols("src/geom.rs", src);
    assert_eq!(
        symbols,
        vec![
            AstSymbol {
                name: "Point".to_string(),
                kind: "struct".to_string(),
                line_start: 4,
                line_end: 7,
            },
            AstSymbol {
                name: "Point".to_string(),
                kind: "impl".to_string(),
                line_start: 9,
                line_end: 13,
            },
            AstSymbol {
                name: "origin".to_string(),
                kind: "method".to_string(),
                line_start: 10,
                line_end: 12,
            },
            AstSymbol {
                name: "Direction".to_string(),
                kind: "enum".to_string(),
                line_start: 15,
                line_end: 18,
            },
            AstSymbol {
                name: "distance".to_string(),
                kind: "fn".to_string(),
                line_start: 20,
                line_end: 22,
            },
        ]
    );

    assert_eq!(symbol_at_line("src/geom.rs", src, 0), None);
    assert_eq!(symbol_at_line("src/geom.rs", src, 1), None);
    assert_eq!(
        symbol_at_line("src/geom.rs", src, 5).map(|s| (s.kind, s.name)),
        Some(("struct".to_string(), "Point".to_string()))
    );
    // Line 9 is `impl Point {`, line 11 is inside `origin` method (innermost symbol)
    assert_eq!(
        symbol_at_line("src/geom.rs", src, 9).map(|s| (s.kind, s.name)),
        Some(("impl".to_string(), "Point".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/geom.rs", src, 11).map(|s| (s.kind, s.name)),
        Some(("method".to_string(), "origin".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/geom.rs", src, 21).map(|s| (s.kind, s.name)),
        Some(("fn".to_string(), "distance".to_string()))
    );
}

#[test]
fn extract_ast_symbols_and_symbol_at_line_typescript() {
    let src = r#"export interface User {
  id: string;
  name: string;
}

export type UserId = string;

export class UserStore {
  private users: User[] = [];

  findById(id: UserId): User | undefined {
    return this.users.find((u) => u.id === id);
  }
}

export const DEFAULT_LIMIT = 50;

export function formatUser(u: User): string {
  return `${u.id}:${u.name}`;
}
"#;

    let symbols = extract_ast_symbols("src/users.ts", src);
    assert_eq!(
        symbols,
        vec![
            AstSymbol {
                name: "User".to_string(),
                kind: "interface".to_string(),
                line_start: 1,
                line_end: 4,
            },
            AstSymbol {
                name: "UserId".to_string(),
                kind: "type".to_string(),
                line_start: 6,
                line_end: 6,
            },
            AstSymbol {
                name: "UserStore".to_string(),
                kind: "class".to_string(),
                line_start: 8,
                line_end: 14,
            },
            AstSymbol {
                name: "findById".to_string(),
                kind: "method".to_string(),
                line_start: 11,
                line_end: 13,
            },
            AstSymbol {
                name: "DEFAULT_LIMIT".to_string(),
                kind: "const".to_string(),
                line_start: 16,
                line_end: 16,
            },
            AstSymbol {
                name: "formatUser".to_string(),
                kind: "function".to_string(),
                line_start: 18,
                line_end: 20,
            },
        ]
    );

    assert_eq!(
        symbol_at_line("src/users.ts", src, 2).map(|s| (s.kind, s.name)),
        Some(("interface".to_string(), "User".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/users.ts", src, 9).map(|s| (s.kind, s.name)),
        Some(("class".to_string(), "UserStore".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/users.ts", src, 12).map(|s| (s.kind, s.name)),
        Some(("method".to_string(), "findById".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/users.ts", src, 16).map(|s| (s.kind, s.name)),
        Some(("const".to_string(), "DEFAULT_LIMIT".to_string()))
    );
    assert_eq!(
        symbol_at_line("src/users.ts", src, 19).map(|s| (s.kind, s.name)),
        Some(("function".to_string(), "formatUser".to_string()))
    );
    assert_eq!(symbol_at_line("notes.txt", src, 1), None);
}

#[test]
fn rust_same_slot_identical_and_disjoint_additions_deduplicate_cleanly() {
    let base = "pub fn base_fn() -> i32 {\n    1\n}\n";
    let ours = "pub fn base_fn() -> i32 {\n    1\n}\n\npub fn shared() -> i32 {\n    2\n}\n\npub fn from_ours() -> i32 {\n    3\n}\n";
    let theirs = "pub fn base_fn() -> i32 {\n    1\n}\n\npub fn shared() -> i32 {\n    2\n}\n\npub fn from_theirs() -> i32 {\n    4\n}\n";

    let outcome = merge_bytes(
        "src/dedup.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert_eq!(merged.matches("pub fn shared()").count(), 1);
            assert!(merged.contains("pub fn from_ours()"));
            assert!(merged.contains("pub fn from_theirs()"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean merge with deduplication, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }
}

#[test]
fn rust_modify_delete_same_item_conflicts() {
    let base = "pub fn a() -> i32 {\n    1\n}\n\npub fn b() -> i32 {\n    2\n}\n";
    let ours = "pub fn a() -> i32 {\n    1\n}\n";
    let theirs = "pub fn a() -> i32 {\n    1\n}\n\npub fn b() -> i32 {\n    20\n}\n";

    let outcome = merge_bytes(
        "src/mod_del.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    assert!(outcome.is_conflict());
    let text = String::from_utf8(outcome.into_bytes()).unwrap();
    assert!(text.contains("<<<<<<< OURS"));
    assert!(text.contains(">>>>>>> THEIRS"));
}

#[test]
fn ambiguous_duplicate_impl_blocks_fall_back_safely() {
    let base = "pub struct Foo;\n\nimpl Foo {\n    pub fn a(&self) {}\n}\n\nimpl Foo {\n    pub fn b(&self) {}\n}\n";
    let ours = "pub struct Foo;\n\nimpl Foo {\n    pub fn a(&self) {}\n}\n\nimpl Foo {\n    pub fn b(&self) {}\n}\n\npub fn x() {}\n";
    let theirs = "pub struct Foo;\n\nimpl Foo {\n    pub fn a(&self) {}\n}\n\nimpl Foo {\n    pub fn b(&self) {}\n}\n\npub fn y() {}\n";

    // Two `impl Foo` blocks make top-level keys ambiguous -> safely falls back to 3-way line merge (conflict) without panicking.
    let outcome = merge_bytes(
        "src/ambig.rs",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    assert!(outcome.is_conflict());
}

#[test]
fn python_symbol_extraction_and_parallel_ast_merge() {
    let base = "\
import os

class Service:
    def start(self):
        return True

def base_fn():
    return 1
";
    let ours = "\
import os
import json

class Service:
    def start(self):
        return True

def base_fn():
    return 1

def agent_one():
    return 'one'
";
    let theirs = "\
import os
import sys

class Service:
    def start(self):
        return True

def base_fn():
    return 1

@staticmethod
def agent_two():
    return 'two'
";

    let outcome = merge_bytes(
        "app/worker.py",
        base.as_bytes(),
        ours.as_bytes(),
        theirs.as_bytes(),
    );
    match outcome {
        MergeOutcome::Clean(bytes) => {
            let merged = String::from_utf8(bytes).unwrap();
            assert!(merged.contains("import json"));
            assert!(merged.contains("import sys"));
            assert!(merged.contains("def agent_one():"));
            assert!(merged.contains("def agent_two():"));

            let syms = extract_ast_symbols("app/worker.py", &merged);
            assert!(syms.iter().any(|s| s.name == "Service" && s.kind == "class"));
            assert!(syms.iter().any(|s| s.name == "start" && s.kind == "method"));
            assert!(syms.iter().any(|s| s.name == "agent_one" && s.kind == "fn"));
            assert!(syms.iter().any(|s| s.name == "agent_two" && s.kind == "fn"));
        }
        MergeOutcome::Conflict { materialized, .. } => {
            panic!(
                "expected clean Python AST merge, got conflict:\n{}",
                String::from_utf8_lossy(&materialized)
            );
        }
    }

    // Editing the same Python function body differently must still conflict.
    let ours_c = "def base_fn():\n    return 10\n";
    let theirs_c = "def base_fn():\n    return 20\n";
    let conflict = merge_bytes(
        "app/worker.py",
        "def base_fn():\n    return 1\n".as_bytes(),
        ours_c.as_bytes(),
        theirs_c.as_bytes(),
    );
    assert!(conflict.is_conflict());
}
