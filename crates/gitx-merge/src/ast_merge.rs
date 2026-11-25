use crate::merge::{MergeOutcome, merge_lines};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Tree};

/// A symbol extracted from a source file's Tree-sitter AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstSymbol {
    pub name: String,
    pub kind: String,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AstLanguage {
    Rust,
    TypeScript,
    Tsx,
    JavaScript,
    Python,
}

impl AstLanguage {
    fn from_path(path: &str) -> Option<Self> {
        let ext = Path::new(path).extension()?.to_str()?;
        if ext.eq_ignore_ascii_case("rs") {
            Some(Self::Rust)
        } else if ext.eq_ignore_ascii_case("ts") {
            Some(Self::TypeScript)
        } else if ext.eq_ignore_ascii_case("tsx") {
            Some(Self::Tsx)
        } else if ext.eq_ignore_ascii_case("js")
            || ext.eq_ignore_ascii_case("jsx")
            || ext.eq_ignore_ascii_case("mjs")
            || ext.eq_ignore_ascii_case("cjs")
        {
            Some(Self::JavaScript)
        } else if ext.eq_ignore_ascii_case("py") || ext.eq_ignore_ascii_case("pyi") {
            Some(Self::Python)
        } else {
            None
        }
    }

    fn ts_language(self) -> Language {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
        }
    }
}

fn parse_tree(lang: AstLanguage, source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&lang.ts_language()).ok()?;
    parser.parse(source, None)
}

// ---------------------------------------------------------------------------
// AST Symbol Extraction
// ---------------------------------------------------------------------------

/// Extract named declarations and methods from a supported source file using Tree-sitter.
///
/// Returns an empty vector for unsupported extensions or if parsing fails.
pub fn extract_ast_symbols(path: &str, source: &str) -> Vec<AstSymbol> {
    let Some(lang) = AstLanguage::from_path(path) else {
        return Vec::new();
    };
    let Some(tree) = parse_tree(lang, source) else {
        return Vec::new();
    };

    let mut symbols = Vec::new();
    let root = tree.root_node();
    match lang {
        AstLanguage::Rust => collect_rust_symbols(root, source, false, &mut symbols),
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => {
            collect_ts_js_symbols(root, source, &mut symbols);
        }
        AstLanguage::Python => {
            collect_python_symbols(root, source, false, &mut symbols);
        }
    }
    symbols
}

/// Return the innermost AST symbol covering the given 1-based line number, if any.
pub fn symbol_at_line(path: &str, source: &str, line_1based: u32) -> Option<AstSymbol> {
    if line_1based == 0 {
        return None;
    }
    extract_ast_symbols(path, source)
        .into_iter()
        .filter(|sym| sym.line_start <= line_1based && line_1based <= sym.line_end)
        .min_by_key(|sym| {
            (
                sym.line_end.saturating_sub(sym.line_start),
                std::cmp::Reverse(sym.line_start),
            )
        })
}

fn node_lines(node: Node<'_>) -> (u32, u32) {
    let start = node.start_position();
    let end = node.end_position();
    let line_start = start.row as u32 + 1;
    let line_end = if end.column == 0 && end.row > start.row {
        end.row as u32
    } else {
        end.row as u32 + 1
    };
    (line_start, line_end.max(line_start))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn collect_rust_symbols(
    node: Node<'_>,
    source: &str,
    in_type_body: bool,
    out: &mut Vec<AstSymbol>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        let (line_start, line_end) = node_lines(child);
        match child.kind() {
            "function_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(AstSymbol {
                        name: node_text(name_node, source).to_string(),
                        kind: if in_type_body {
                            "method".to_string()
                        } else {
                            "fn".to_string()
                        },
                        line_start,
                        line_end,
                    });
                }
            }
            "function_signature_item" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(AstSymbol {
                        name: node_text(name_node, source).to_string(),
                        kind: if in_type_body {
                            "method".to_string()
                        } else {
                            "fn".to_string()
                        },
                        line_start,
                        line_end,
                    });
                }
            }
            "struct_item" => push_named_symbol(child, source, "struct", line_start, line_end, out),
            "enum_item" => push_named_symbol(child, source, "enum", line_start, line_end, out),
            "union_item" => push_named_symbol(child, source, "union", line_start, line_end, out),
            "type_item" => push_named_symbol(child, source, "type", line_start, line_end, out),
            "const_item" => push_named_symbol(child, source, "const", line_start, line_end, out),
            "static_item" => push_named_symbol(child, source, "static", line_start, line_end, out),
            "macro_definition" => {
                push_named_symbol(child, source, "macro", line_start, line_end, out);
            }
            "trait_item" => {
                push_named_symbol(child, source, "trait", line_start, line_end, out);
                if let Some(body) = child.child_by_field_name("body") {
                    collect_rust_symbols(body, source, true, out);
                }
            }
            "impl_item" => {
                if let Some(name) = rust_impl_name(child, source) {
                    out.push(AstSymbol {
                        name,
                        kind: "impl".to_string(),
                        line_start,
                        line_end,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_rust_symbols(body, source, true, out);
                }
            }
            "mod_item" => {
                push_named_symbol(child, source, "mod", line_start, line_end, out);
                if let Some(body) = child.child_by_field_name("body") {
                    collect_rust_symbols(body, source, false, out);
                }
            }
            _ => {}
        }
    }
}

fn push_named_symbol(
    node: Node<'_>,
    source: &str,
    kind: &str,
    line_start: u32,
    line_end: u32,
    out: &mut Vec<AstSymbol>,
) {
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = node_text(name_node, source).trim();
        if !name.is_empty() {
            out.push(AstSymbol {
                name: name.to_string(),
                kind: kind.to_string(),
                line_start,
                line_end,
            });
        }
    }
}

fn rust_impl_name(node: Node<'_>, source: &str) -> Option<String> {
    let type_node = node.child_by_field_name("type")?;
    let ty = normalize_ws(node_text(type_node, source));
    if ty.is_empty() {
        return None;
    }
    if let Some(trait_node) = node.child_by_field_name("trait") {
        let tr = normalize_ws(node_text(trait_node, source));
        if !tr.is_empty() {
            return Some(format!("{tr} for {ty}"));
        }
    }
    Some(ty)
}

fn collect_ts_js_symbols(node: Node<'_>, source: &str, out: &mut Vec<AstSymbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        collect_ts_js_statement_symbol(child, child, source, out);
    }
}

fn collect_ts_js_statement_symbol(
    span_node: Node<'_>,
    decl_node: Node<'_>,
    source: &str,
    out: &mut Vec<AstSymbol>,
) {
    let (line_start, line_end) = node_lines(span_node);
    match decl_node.kind() {
        "export_statement" => {
            if let Some(inner) = decl_node.child_by_field_name("declaration") {
                collect_ts_js_statement_symbol(span_node, inner, source, out);
            }
        }
        "ambient_declaration" => {
            let mut cursor = decl_node.walk();
            for inner in decl_node.children(&mut cursor) {
                if inner.is_named() {
                    collect_ts_js_statement_symbol(span_node, inner, source, out);
                    break;
                }
            }
        }
        "function_declaration" | "generator_function_declaration" | "function_signature" => {
            push_named_symbol(decl_node, source, "function", line_start, line_end, out);
        }
        "class_declaration" | "abstract_class_declaration" => {
            push_named_symbol(decl_node, source, "class", line_start, line_end, out);
            if let Some(body) = decl_node.child_by_field_name("body") {
                collect_ts_js_class_methods(body, source, out);
            }
        }
        "interface_declaration" => {
            push_named_symbol(decl_node, source, "interface", line_start, line_end, out);
        }
        "type_alias_declaration" => {
            push_named_symbol(decl_node, source, "type", line_start, line_end, out);
        }
        "enum_declaration" => {
            push_named_symbol(decl_node, source, "enum", line_start, line_end, out);
        }
        "internal_module" | "module" => {
            push_named_symbol(decl_node, source, "namespace", line_start, line_end, out);
            if let Some(body) = decl_node.child_by_field_name("body") {
                collect_ts_js_symbols(body, source, out);
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            let var_kind = ts_js_var_kind(decl_node, source);
            let mut cursor = decl_node.walk();
            for child in decl_node.children(&mut cursor) {
                if child.kind() == "variable_declarator"
                    && let Some(name_node) = child.child_by_field_name("name")
                    && name_node.kind() == "identifier"
                {
                    let name = node_text(name_node, source).trim();
                    if !name.is_empty() {
                        out.push(AstSymbol {
                            name: name.to_string(),
                            kind: var_kind.to_string(),
                            line_start,
                            line_end,
                        });
                    }
                }
            }
        }
        _ => {}
    }
}

fn collect_ts_js_class_methods(body: Node<'_>, source: &str, out: &mut Vec<AstSymbol>) {
    let mut cursor = body.walk();
    for member in body.children(&mut cursor) {
        if matches!(
            member.kind(),
            "method_definition" | "abstract_method_signature" | "method_signature"
        ) && let Some(name_node) = member.child_by_field_name("name")
        {
            let name = node_text(name_node, source).trim();
            if !name.is_empty() {
                let (line_start, line_end) = node_lines(member);
                out.push(AstSymbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    line_start,
                    line_end,
                });
            }
        }
    }
}

fn ts_js_var_kind(decl_node: Node<'_>, source: &str) -> &'static str {
    if decl_node.kind() == "variable_declaration" {
        return "var";
    }
    let mut cursor = decl_node.walk();
    for child in decl_node.children(&mut cursor) {
        if !child.is_named() {
            let text = node_text(child, source).trim();
            if text == "const" {
                return "const";
            }
            if text == "let" {
                return "let";
            }
        }
    }
    "const"
}

// ---------------------------------------------------------------------------
// AST-Aware 3-Way Semantic Merge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ItemKey {
    kind: String,
    name: String,
}

impl ItemKey {
    fn is_import_like(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "use" | "import" | "import_type" | "extern_crate" | "inner_attribute"
        )
    }
}

#[derive(Debug, Clone)]
struct TopLevelItem {
    key: ItemKey,
    leading_ws: String,
    text: String,
    is_declaration: bool,
}

#[derive(Debug, Clone)]
struct ParsedDocument {
    preamble: String,
    items: Vec<TopLevelItem>,
    epilogue: String,
}

/// Attempt a Tree-sitter AST-aware 3-way semantic merge on supported source files.
///
/// Returns `None` if:
/// - the file extension is not a supported Tree-sitter language,
/// - any of `base`, `ours`, or `theirs` has syntax errors (`root.has_error()`),
/// - any side contains duplicate/ambiguous top-level declaration keys,
/// - surviving base items were reordered, or
/// - concurrent imperative top-level statements were added at the same slot.
///
/// Callers should fall back to standard 3-way line merge whenever `None` is returned.
pub fn try_ast_merge(path: &str, base: &str, ours: &str, theirs: &str) -> Option<MergeOutcome> {
    let lang = AstLanguage::from_path(path)?;

    let base_doc = parse_document(lang, base)?;
    let ours_doc = parse_document(lang, ours)?;
    let theirs_doc = parse_document(lang, theirs)?;

    merge_documents(&base_doc, &ours_doc, &theirs_doc)
}

/// Returns `true` if `source` parses cleanly in a supported language yet contains duplicate
/// top-level declaration keys (e.g., when a line-level merge silently duplicates an item
/// added by both sides around a deleted anchor).
pub(crate) fn has_duplicate_top_level_keys(path: &str, source: &str) -> bool {
    let Some(lang) = AstLanguage::from_path(path) else {
        return false;
    };
    let Some(tree) = parse_tree(lang, source) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let mut cursor = root.walk();
    let mut seen = HashSet::new();
    for child in root.children(&mut cursor) {
        if !child.is_named()
            || is_file_preamble_node(lang, child, source)
            || is_leading_trivia(lang, child.kind())
        {
            continue;
        }
        if let Some((key, _)) = extract_item_key(lang, child, source)
            && !seen.insert(key)
        {
            return true;
        }
    }
    false
}

fn parse_document(lang: AstLanguage, source: &str) -> Option<ParsedDocument> {
    let tree = parse_tree(lang, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut cursor = root.walk();
    let children: Vec<Node<'_>> = root.children(&mut cursor).collect();

    struct RawItem {
        key: ItemKey,
        start_byte: usize,
        end_byte: usize,
        end_row: usize,
        is_declaration: bool,
    }

    let mut preamble_end = 0usize;
    let mut pending_trivia_start: Option<usize> = None;
    let mut pending_trivia_end: usize = 0;
    let mut pending_has_sticky_trivia = false; // doc comments / attributes / decorators
    let mut raw_items: Vec<RawItem> = Vec::new();

    for child in children {
        let kind = child.kind();

        // Ignore punctuation / semicolons if they appear as top-level unnamed tokens
        if !child.is_named() {
            if kind == ";"
                && let Some(last) = raw_items.last_mut()
            {
                last.end_byte = child.end_byte();
                last.end_row = child.end_position().row;
            }
            continue;
        }

        // File-level shebangs and Rust inner doc comments stay in preamble before any items
        if raw_items.is_empty()
            && pending_trivia_start.is_none()
            && is_file_preamble_node(lang, child, source)
        {
            preamble_end = child.end_byte();
            continue;
        }

        // Trailing comment on the exact same line as the previous item stays with that item
        if is_comment_node(lang, kind)
            && pending_trivia_start.is_none()
            && let Some(last) = raw_items.last_mut()
            && child.start_position().row == last.end_row
        {
            last.end_byte = child.end_byte();
            last.end_row = child.end_position().row;
            continue;
        }

        // Comments, attributes, and decorators attach to the following item
        if is_leading_trivia(lang, kind) {
            if pending_trivia_start.is_none() {
                pending_trivia_start = Some(child.start_byte());
            } else if raw_items.is_empty() && !pending_has_sticky_trivia {
                // If there's a blank line between a regular header comment and the next comment/attribute,
                // keep the earlier header comment in the file preamble.
                let gap = &source[pending_trivia_end..child.start_byte()];
                if has_blank_line(gap) {
                    preamble_end = pending_trivia_end;
                    pending_trivia_start = Some(child.start_byte());
                }
            }
            if is_sticky_trivia(lang, child, source) {
                pending_has_sticky_trivia = true;
            }
            pending_trivia_end = child.end_byte();
            continue;
        }

        // If we had non-sticky leading comments before the first item separated by a blank line,
        // treat them as a file header preamble rather than attaching to item 0.
        if raw_items.is_empty()
            && let Some(_trivia_start) = pending_trivia_start
            && !pending_has_sticky_trivia
        {
            let gap = &source[pending_trivia_end..child.start_byte()];
            if has_blank_line(gap) {
                preamble_end = pending_trivia_end;
                pending_trivia_start = None;
            }
        }

        let (key, is_declaration) = extract_item_key(lang, child, source)?;
        let item_start = pending_trivia_start.unwrap_or_else(|| child.start_byte());
        pending_trivia_start = None;
        pending_has_sticky_trivia = false;

        raw_items.push(RawItem {
            key,
            start_byte: item_start,
            end_byte: child.end_byte(),
            end_row: child.end_position().row,
            is_declaration,
        });
    }

    // Check uniqueness of keys within this file
    let mut seen_keys = HashSet::with_capacity(raw_items.len());
    for item in &raw_items {
        if !seen_keys.insert(item.key.clone()) {
            return None;
        }
    }

    if raw_items.is_empty() {
        return Some(ParsedDocument {
            preamble: source[..preamble_end].to_string(),
            items: Vec::new(),
            epilogue: source[preamble_end..].to_string(),
        });
    }

    let preamble = source[..preamble_end].to_string();
    let mut items = Vec::with_capacity(raw_items.len());
    let mut prev_end = preamble_end;
    for raw in raw_items {
        let leading_ws = source[prev_end..raw.start_byte].to_string();
        let text = source[raw.start_byte..raw.end_byte].to_string();
        prev_end = raw.end_byte;
        items.push(TopLevelItem {
            key: raw.key,
            leading_ws,
            text,
            is_declaration: raw.is_declaration,
        });
    }
    let epilogue = source[prev_end..].to_string();

    Some(ParsedDocument {
        preamble,
        items,
        epilogue,
    })
}

fn has_blank_line(gap: &str) -> bool {
    let mut newlines = 0usize;
    for b in gap.bytes() {
        if b == b'\n' {
            newlines += 1;
            if newlines >= 2 {
                return true;
            }
        }
    }
    false
}

fn collect_python_symbols(
    node: Node<'_>,
    source: &str,
    in_class_body: bool,
    out: &mut Vec<AstSymbol>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        let (line_start, line_end) = node_lines(child);
        match child.kind() {
            "function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(AstSymbol {
                        name: node_text(name_node, source).to_string(),
                        kind: if in_class_body {
                            "method".to_string()
                        } else {
                            "fn".to_string()
                        },
                        line_start,
                        line_end,
                    });
                }
            }
            "class_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    out.push(AstSymbol {
                        name: node_text(name_node, source).to_string(),
                        kind: "class".to_string(),
                        line_start,
                        line_end,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_python_symbols(body, source, true, out);
                }
            }
            "decorated_definition" => {
                if let Some(def) = child.child_by_field_name("definition") {
                    match def.kind() {
                        "function_definition" => {
                            if let Some(name_node) = def.child_by_field_name("name") {
                                out.push(AstSymbol {
                                    name: node_text(name_node, source).to_string(),
                                    kind: if in_class_body {
                                        "method".to_string()
                                    } else {
                                        "fn".to_string()
                                    },
                                    line_start,
                                    line_end,
                                });
                            }
                        }
                        "class_definition" => {
                            if let Some(name_node) = def.child_by_field_name("name") {
                                out.push(AstSymbol {
                                    name: node_text(name_node, source).to_string(),
                                    kind: "class".to_string(),
                                    line_start,
                                    line_end,
                                });
                            }
                            if let Some(body) = def.child_by_field_name("body") {
                                collect_python_symbols(body, source, true, out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_comment_node(lang: AstLanguage, kind: &str) -> bool {
    match lang {
        AstLanguage::Rust => matches!(kind, "line_comment" | "block_comment"),
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => kind == "comment",
        AstLanguage::Python => kind == "comment",
    }
}

fn is_file_preamble_node(lang: AstLanguage, node: Node<'_>, source: &str) -> bool {
    match lang {
        AstLanguage::Rust => {
            if matches!(node.kind(), "line_comment" | "block_comment") {
                let text = node_text(node, source);
                text.starts_with("//!") || text.starts_with("/*!")
            } else {
                false
            }
        }
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => {
            node.kind() == "hash_bang_line"
        }
        AstLanguage::Python => {
            node.kind() == "comment" && node_text(node, source).starts_with("#!")
        }
    }
}

fn is_leading_trivia(lang: AstLanguage, kind: &str) -> bool {
    match lang {
        AstLanguage::Rust => matches!(kind, "line_comment" | "block_comment" | "attribute_item"),
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => {
            matches!(kind, "comment" | "decorator")
        }
        AstLanguage::Python => kind == "comment",
    }
}

fn is_sticky_trivia(lang: AstLanguage, node: Node<'_>, source: &str) -> bool {
    match lang {
        AstLanguage::Rust => match node.kind() {
            "attribute_item" => true,
            "line_comment" => {
                let text = node_text(node, source);
                text.starts_with("///") && !text.starts_with("////")
            }
            "block_comment" => {
                let text = node_text(node, source);
                text.starts_with("/**") && !text.starts_with("/***")
            }
            _ => false,
        },
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => match node.kind() {
            "decorator" => true,
            "comment" => node_text(node, source).starts_with("/**"),
            _ => false,
        },
        AstLanguage::Python => false,
    }
}

fn extract_item_key(lang: AstLanguage, node: Node<'_>, source: &str) -> Option<(ItemKey, bool)> {
    match lang {
        AstLanguage::Rust => extract_rust_item_key(node, source),
        AstLanguage::TypeScript | AstLanguage::Tsx | AstLanguage::JavaScript => {
            extract_ts_js_item_key(node, source)
        }
        AstLanguage::Python => extract_python_item_key(node, source),
    }
}

fn extract_python_item_key(node: Node<'_>, source: &str) -> Option<(ItemKey, bool)> {
    match node.kind() {
        "import_statement" | "import_from_statement" | "future_import_statement" => Some((
            ItemKey {
                kind: "import".to_string(),
                name: normalize_ws(node_text(node, source)),
            },
            true,
        )),
        "function_definition" => named_key(node, source, "fn", true),
        "class_definition" => named_key(node, source, "class", true),
        "decorated_definition" => {
            if let Some(def) = node.child_by_field_name("definition") {
                extract_python_item_key(def, source)
            } else {
                Some((
                    ItemKey {
                        kind: "py:decorated".to_string(),
                        name: normalize_ws(node_text(node, source)),
                    },
                    true,
                ))
            }
        }
        "expression_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "assignment"
                    && let Some(left) = child.child_by_field_name("left")
                {
                    let name = normalize_ws(node_text(left, source));
                    if !name.is_empty() {
                        return Some((
                            ItemKey {
                                kind: "assign".to_string(),
                                name,
                            },
                            true,
                        ));
                    }
                }
            }
            Some((
                ItemKey {
                    kind: "py:expr".to_string(),
                    name: normalize_ws(node_text(node, source)),
                },
                false,
            ))
        }
        kind => Some((
            ItemKey {
                kind: format!("py:{kind}"),
                name: normalize_ws(node_text(node, source)),
            },
            false,
        )),
    }
}

fn extract_rust_item_key(node: Node<'_>, source: &str) -> Option<(ItemKey, bool)> {
    let kind = node.kind();
    match kind {
        "function_item" => named_key(node, source, "fn", true),
        "function_signature_item" => named_key(node, source, "fn_sig", true),
        "struct_item" => named_key(node, source, "struct", true),
        "enum_item" => named_key(node, source, "enum", true),
        "union_item" => named_key(node, source, "union", true),
        "trait_item" => named_key(node, source, "trait", true),
        "type_item" => named_key(node, source, "type", true),
        "const_item" => named_key(node, source, "const", true),
        "static_item" => named_key(node, source, "static", true),
        "mod_item" => named_key(node, source, "mod", true),
        "macro_definition" => named_key(node, source, "macro", true),
        "extern_crate_declaration" => named_key(node, source, "extern_crate", true),
        "impl_item" => {
            let name = rust_impl_name(node, source)?;
            Some((
                ItemKey {
                    kind: "impl".to_string(),
                    name,
                },
                true,
            ))
        }
        "use_declaration" => {
            let name = rust_use_key(node, source)?;
            Some((
                ItemKey {
                    kind: "use".to_string(),
                    name,
                },
                true,
            ))
        }
        "inner_attribute_item" => Some((
            ItemKey {
                kind: "inner_attribute".to_string(),
                name: normalize_ws(node_text(node, source)),
            },
            true,
        )),
        "foreign_mod_item" => Some((
            ItemKey {
                kind: "extern".to_string(),
                name: normalize_ws(node_text(node, source)),
            },
            true,
        )),
        "macro_invocation" => Some((
            ItemKey {
                kind: "macro_invocation".to_string(),
                name: normalize_ws(node_text(node, source)),
            },
            true,
        )),
        _ => Some((
            ItemKey {
                kind: format!("rust:{kind}"),
                name: normalize_ws(node_text(node, source)),
            },
            false,
        )),
    }
}

fn rust_use_key(node: Node<'_>, source: &str) -> Option<String> {
    let arg = node.child_by_field_name("argument")?;
    if arg.kind() == "scoped_use_list" {
        if let Some(path) = arg.child_by_field_name("path") {
            let p = normalize_ws(node_text(path, source));
            return Some(format!("{p}::{{}}"));
        }
        return Some("{}".to_string());
    }
    let norm = normalize_ws(node_text(arg, source));
    if norm.is_empty() { None } else { Some(norm) }
}

fn extract_ts_js_item_key(node: Node<'_>, source: &str) -> Option<(ItemKey, bool)> {
    match node.kind() {
        "import_statement" => {
            let is_type_import = has_keyword_token(node, source, "type");
            let kind = if is_type_import {
                "import_type"
            } else {
                "import"
            };
            let name = if let Some(src_node) = node.child_by_field_name("source") {
                unquote_string(node_text(src_node, source))
            } else {
                normalize_ws(node_text(node, source))
            };
            Some((
                ItemKey {
                    kind: kind.to_string(),
                    name,
                },
                true,
            ))
        }
        "export_statement" => {
            if let Some(decl) = node.child_by_field_name("declaration") {
                return extract_ts_js_item_key(decl, source);
            }
            if has_keyword_token(node, source, "default") {
                return Some((
                    ItemKey {
                        kind: "export_default".to_string(),
                        name: "default".to_string(),
                    },
                    true,
                ));
            }
            Some((
                ItemKey {
                    kind: "export".to_string(),
                    name: normalize_ws(node_text(node, source)),
                },
                true,
            ))
        }
        "ambient_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named()
                    && let Some(key) = extract_ts_js_item_key(child, source)
                {
                    return Some(key);
                }
            }
            Some((
                ItemKey {
                    kind: "declare".to_string(),
                    name: normalize_ws(node_text(node, source)),
                },
                true,
            ))
        }
        "function_declaration" | "generator_function_declaration" | "function_signature" => {
            if let Some(res) = named_key(node, source, "function", true) {
                Some(res)
            } else {
                Some((
                    ItemKey {
                        kind: "export_default".to_string(),
                        name: "default".to_string(),
                    },
                    true,
                ))
            }
        }
        "class_declaration" | "abstract_class_declaration" => {
            if let Some(res) = named_key(node, source, "class", true) {
                Some(res)
            } else {
                Some((
                    ItemKey {
                        kind: "export_default".to_string(),
                        name: "default".to_string(),
                    },
                    true,
                ))
            }
        }
        "interface_declaration" => named_key(node, source, "interface", true),
        "type_alias_declaration" => named_key(node, source, "type", true),
        "enum_declaration" => named_key(node, source, "enum", true),
        "internal_module" | "module" => named_key(node, source, "namespace", true),
        "lexical_declaration" | "variable_declaration" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator"
                    && let Some(name_node) = child.child_by_field_name("name")
                {
                    names.push(normalize_ws(node_text(name_node, source)));
                }
            }
            if names.is_empty() {
                return None;
            }
            Some((
                ItemKey {
                    kind: "variable".to_string(),
                    name: names.join(", "),
                },
                true,
            ))
        }
        other => Some((
            ItemKey {
                kind: format!("stmt:{other}"),
                name: normalize_ws(node_text(node, source)),
            },
            false,
        )),
    }
}

fn named_key(
    node: Node<'_>,
    source: &str,
    kind: &str,
    is_declaration: bool,
) -> Option<(ItemKey, bool)> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    Some((
        ItemKey {
            kind: kind.to_string(),
            name: name.to_string(),
        },
        is_declaration,
    ))
}

fn has_keyword_token(node: Node<'_>, source: &str, keyword: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() && node_text(child, source).trim() == keyword {
            return true;
        }
    }
    false
}

fn unquote_string(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('`') && trimmed.ends_with('`')))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Document-level 3-way merge
// ---------------------------------------------------------------------------

struct MergedPiece {
    key: ItemKey,
    leading_ws: String,
    text: String,
    ends_with_conflict_marker: bool,
}

fn merge_documents(
    base: &ParsedDocument,
    ours: &ParsedDocument,
    theirs: &ParsedDocument,
) -> Option<MergeOutcome> {
    let base_index: HashMap<&ItemKey, usize> = base
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| (&item.key, i))
        .collect();
    let ours_map: HashMap<&ItemKey, &TopLevelItem> =
        ours.items.iter().map(|item| (&item.key, item)).collect();
    let theirs_map: HashMap<&ItemKey, &TopLevelItem> =
        theirs.items.iter().map(|item| (&item.key, item)).collect();

    // Ensure surviving base items preserve relative order on both sides.
    if !preserves_base_order(&base_index, &ours.items)
        || !preserves_base_order(&base_index, &theirs.items)
    {
        return None;
    }

    let slot_count = base.items.len() + 1;
    let ours_slots = partition_additions(&base_index, &ours.items, slot_count);
    let theirs_slots = partition_additions(&base_index, &theirs.items, slot_count);

    // Track cross-slot duplicate additions (same key added by both sides at different slots).
    let mut ours_added_slot: HashMap<&ItemKey, (usize, &TopLevelItem)> = HashMap::new();
    for (slot_idx, items) in ours_slots.iter().enumerate() {
        for item in items {
            ours_added_slot.insert(&item.key, (slot_idx, item));
        }
    }
    let mut theirs_added_slot: HashMap<&ItemKey, (usize, &TopLevelItem)> = HashMap::new();
    for (slot_idx, items) in theirs_slots.iter().enumerate() {
        for item in items {
            theirs_added_slot.insert(&item.key, (slot_idx, item));
        }
    }

    let mut dedup_skip_in_theirs: HashSet<&ItemKey> = HashSet::new();
    for (key, &(o_slot, o_item)) in &ours_added_slot {
        if let Some(&(t_slot, t_item)) = theirs_added_slot.get(key)
            && o_slot != t_slot
        {
            if o_item.text == t_item.text {
                dedup_skip_in_theirs.insert(*key);
            } else {
                // Same new item added with conflicting bodies at different positions -> ambiguous
                return None;
            }
        }
    }

    let mut conflict_hunks = 0usize;
    let mut pieces: Vec<MergedPiece> = Vec::new();

    // Merge preamble
    let (merged_preamble, preamble_hunks) =
        merge_text_segment(&base.preamble, &ours.preamble, &theirs.preamble);
    conflict_hunks += preamble_hunks;

    for slot_idx in 0..slot_count {
        let o_adds = &ours_slots[slot_idx];
        let t_adds = &theirs_slots[slot_idx];

        // Avoid reordering concurrent non-declaration imperative statements at the same slot.
        if !o_adds.is_empty()
            && !t_adds.is_empty()
            && (o_adds.iter().any(|i| !i.is_declaration)
                || t_adds.iter().any(|i| !i.is_declaration))
        {
            return None;
        }

        let t_slot_map: HashMap<&ItemKey, &TopLevelItem> =
            t_adds.iter().map(|item| (&item.key, *item)).collect();
        let mut emitted_in_slot: HashSet<&ItemKey> = HashSet::new();

        for &o_item in o_adds {
            if let Some(&t_item) = t_slot_map.get(&o_item.key) {
                emitted_in_slot.insert(&o_item.key);
                if o_item.text == t_item.text {
                    pieces.push(MergedPiece {
                        key: o_item.key.clone(),
                        leading_ws: preferred_ws(&o_item.leading_ws, &t_item.leading_ws, ""),
                        text: o_item.text.clone(),
                        ends_with_conflict_marker: false,
                    });
                } else {
                    let (merged_text, hunks, ends_marker) =
                        merge_item_text("", &o_item.text, &t_item.text);
                    conflict_hunks += hunks;
                    pieces.push(MergedPiece {
                        key: o_item.key.clone(),
                        leading_ws: preferred_ws(&o_item.leading_ws, &t_item.leading_ws, ""),
                        text: merged_text,
                        ends_with_conflict_marker: ends_marker,
                    });
                }
            } else {
                emitted_in_slot.insert(&o_item.key);
                pieces.push(MergedPiece {
                    key: o_item.key.clone(),
                    leading_ws: o_item.leading_ws.clone(),
                    text: o_item.text.clone(),
                    ends_with_conflict_marker: false,
                });
            }
        }

        for &t_item in t_adds {
            if emitted_in_slot.contains(&t_item.key) || dedup_skip_in_theirs.contains(&t_item.key) {
                continue;
            }
            pieces.push(MergedPiece {
                key: t_item.key.clone(),
                leading_ws: t_item.leading_ws.clone(),
                text: t_item.text.clone(),
                ends_with_conflict_marker: false,
            });
        }

        // Process base item at slot_idx (if any)
        if let Some(b_item) = base.items.get(slot_idx) {
            let o_opt = ours_map.get(&b_item.key).copied();
            let t_opt = theirs_map.get(&b_item.key).copied();

            match (o_opt, t_opt) {
                (Some(o), Some(t)) => {
                    if o.text == t.text {
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(
                                &o.leading_ws,
                                &t.leading_ws,
                                &b_item.leading_ws,
                            ),
                            text: o.text.clone(),
                            ends_with_conflict_marker: false,
                        });
                    } else if o.text == b_item.text {
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(
                                &t.leading_ws,
                                &o.leading_ws,
                                &b_item.leading_ws,
                            ),
                            text: t.text.clone(),
                            ends_with_conflict_marker: false,
                        });
                    } else if t.text == b_item.text {
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(
                                &o.leading_ws,
                                &t.leading_ws,
                                &b_item.leading_ws,
                            ),
                            text: o.text.clone(),
                            ends_with_conflict_marker: false,
                        });
                    } else {
                        let (merged_text, hunks, ends_marker) =
                            merge_item_text(&b_item.text, &o.text, &t.text);
                        conflict_hunks += hunks;
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(
                                &o.leading_ws,
                                &t.leading_ws,
                                &b_item.leading_ws,
                            ),
                            text: merged_text,
                            ends_with_conflict_marker: ends_marker,
                        });
                    }
                }
                (None, Some(t)) => {
                    if t.text != b_item.text {
                        // Delete/modify conflict
                        let (merged_text, hunks, ends_marker) =
                            merge_item_text(&b_item.text, "", &t.text);
                        conflict_hunks += hunks;
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(&t.leading_ws, &b_item.leading_ws, ""),
                            text: merged_text,
                            ends_with_conflict_marker: ends_marker,
                        });
                    }
                }
                (Some(o), None) => {
                    if o.text != b_item.text {
                        // Modify/delete conflict
                        let (merged_text, hunks, ends_marker) =
                            merge_item_text(&b_item.text, &o.text, "");
                        conflict_hunks += hunks;
                        pieces.push(MergedPiece {
                            key: b_item.key.clone(),
                            leading_ws: preferred_ws(&o.leading_ws, &b_item.leading_ws, ""),
                            text: merged_text,
                            ends_with_conflict_marker: ends_marker,
                        });
                    }
                }
                (None, None) => {
                    // Both sides deleted this item cleanly
                }
            }
        }
    }

    // Merge epilogue
    let (merged_epilogue, epilogue_hunks) =
        merge_text_segment(&base.epilogue, &ours.epilogue, &theirs.epilogue);
    conflict_hunks += epilogue_hunks;

    // Assemble final output
    let mut out = String::new();
    out.push_str(&merged_preamble);

    let total_pieces = pieces.len();
    let mut prev_key: Option<ItemKey> = None;
    for (idx, piece) in pieces.into_iter().enumerate() {
        if idx == 0 {
            if merged_preamble.is_empty() {
                // Avoid accidental leading blank lines when original first item was deleted.
                let trimmed = piece.leading_ws.trim_start_matches(['\r', '\n']);
                out.push_str(trimmed);
            } else if piece.leading_ws.is_empty() {
                if !merged_preamble.ends_with('\n') {
                    out.push('\n');
                }
                out.push('\n');
            } else {
                out.push_str(&piece.leading_ws);
            }
        } else if piece.leading_ws.contains('\n') {
            out.push_str(&piece.leading_ws);
        } else {
            let same_import_group = prev_key.as_ref().is_some_and(ItemKey::is_import_like)
                && piece.key.is_import_like();
            if same_import_group {
                out.push('\n');
            } else {
                out.push_str("\n\n");
            }
            out.push_str(&piece.leading_ws);
        }
        out.push_str(&piece.text);
        if idx + 1 == total_pieces && piece.ends_with_conflict_marker && merged_epilogue.is_empty()
        {
            out.push('\n');
        }
        prev_key = Some(piece.key);
    }

    out.push_str(&merged_epilogue);

    if conflict_hunks == 0 {
        Some(MergeOutcome::Clean(out.into_bytes()))
    } else {
        Some(MergeOutcome::Conflict {
            materialized: out.into_bytes(),
            hunks: conflict_hunks,
        })
    }
}

fn preserves_base_order(base_index: &HashMap<&ItemKey, usize>, items: &[TopLevelItem]) -> bool {
    let mut last_idx: Option<usize> = None;
    for item in items {
        if let Some(&idx) = base_index.get(&item.key) {
            if let Some(prev) = last_idx
                && idx < prev
            {
                return false;
            }
            last_idx = Some(idx);
        }
    }
    true
}

fn partition_additions<'a>(
    base_index: &HashMap<&ItemKey, usize>,
    items: &'a [TopLevelItem],
    slot_count: usize,
) -> Vec<Vec<&'a TopLevelItem>> {
    let mut slots = vec![Vec::new(); slot_count];
    let mut current_slot = 0usize;
    for item in items {
        if let Some(&idx) = base_index.get(&item.key) {
            current_slot = idx + 1;
        } else {
            slots[current_slot].push(item);
        }
    }
    slots
}

fn preferred_ws(primary: &str, secondary: &str, tertiary: &str) -> String {
    if !primary.is_empty() {
        primary.to_string()
    } else if !secondary.is_empty() {
        secondary.to_string()
    } else {
        tertiary.to_string()
    }
}

fn merge_text_segment(base: &str, ours: &str, theirs: &str) -> (String, usize) {
    if ours == theirs {
        return (ours.to_string(), 0);
    }
    if ours == base {
        return (theirs.to_string(), 0);
    }
    if theirs == base {
        return (ours.to_string(), 0);
    }
    match merge_lines(base, ours, theirs) {
        MergeOutcome::Clean(bytes) => (String::from_utf8(bytes).unwrap_or_default(), 0),
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => (String::from_utf8(materialized).unwrap_or_default(), hunks),
    }
}

fn merge_item_text(base: &str, ours: &str, theirs: &str) -> (String, usize, bool) {
    let with_nl = |s: &str| {
        if s.is_empty() {
            String::new()
        } else {
            format!("{s}\n")
        }
    };
    let b = with_nl(base);
    let o = with_nl(ours);
    let t = with_nl(theirs);

    match merge_lines(&b, &o, &t) {
        MergeOutcome::Clean(bytes) => {
            let mut s = String::from_utf8(bytes).unwrap_or_default();
            if s.ends_with('\n') {
                s.pop();
            }
            (s, 0, false)
        }
        MergeOutcome::Conflict {
            materialized,
            hunks,
        } => {
            let mut s = String::from_utf8(materialized).unwrap_or_default();
            if s.ends_with('\n') {
                s.pop();
            }
            let ends_marker = s.ends_with(">>>>>>> THEIRS");
            (s, hunks, ends_marker)
        }
    }
}
