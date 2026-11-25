use crate::record::CodeAnchor;
use gitx_core::ObjectHash;
use similar::TextDiff;
use std::collections::HashSet;

/// Minimum `similar` line-similarity ratio required for fuzzy anchor relocation.
const FUZZY_SIMILARITY_THRESHOLD: f32 = 0.6;

/// Compute a whitespace-normalized BLAKE3 fingerprint for a slice of source lines.
pub fn compute_hunk_fingerprint(lines: &[&str]) -> ObjectHash {
    let mut payload = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            payload.push('\n');
        }
        payload.push_str(line.trim());
    }
    ObjectHash::of_typed("gitx:hunk:v1", payload.as_bytes())
}

/// Relocate a `CodeAnchor` in `new_file_content`, returning the 1-based inclusive `(start, end)`
/// line range if found.
///
/// Relocation proceeds in three tiers:
/// 1. Exact line / fingerprint match at the original `(line_start, line_end)` position.
/// 2. Exact normalized snippet match anywhere in the file (survives arbitrary rebase line shifts
///    and re-indentation).
/// 3. Fuzzy line-similarity match using `similar` with ratio >= 0.6.
pub fn relocate_anchor(anchor: &CodeAnchor, new_file_content: &str) -> Option<(u32, u32)> {
    let new_lines: Vec<&str> = new_file_content.lines().collect();
    if new_lines.is_empty() {
        return None;
    }

    let snippet_lines: Vec<&str> = anchor.snippet.lines().collect();
    let expected_fp = if anchor.hunk_fingerprint != ObjectHash::ZERO {
        anchor.hunk_fingerprint
    } else if !snippet_lines.is_empty() {
        compute_hunk_fingerprint(&snippet_lines)
    } else {
        return None;
    };

    // Tier 1: Exact match at original line range.
    if anchor.line_start >= 1 && anchor.line_end >= anchor.line_start {
        let start_idx = (anchor.line_start - 1) as usize;
        let end_idx = anchor.line_end as usize;
        if end_idx <= new_lines.len() {
            let window = &new_lines[start_idx..end_idx];
            let exact_lines = !snippet_lines.is_empty() && window == snippet_lines.as_slice();
            let exact_fp = compute_hunk_fingerprint(window) == expected_fp
                && (!snippet_lines.is_empty() || anchor.hunk_fingerprint != ObjectHash::ZERO);
            let symbol_ok = anchor.symbol.is_none()
                || symbol_matches(anchor, new_file_content, anchor.line_start);
            if (exact_lines || exact_fp) && symbol_ok {
                return Some((anchor.line_start, anchor.line_end));
            }
        }
    }

    let norm_new: Vec<&str> = new_lines.iter().map(|l| l.trim()).collect();

    // Tier 2: Exact normalized snippet match anywhere in the file.
    if !snippet_lines.is_empty() {
        let norm_snip: Vec<&str> = snippet_lines.iter().map(|l| l.trim()).collect();
        let win_len = norm_snip.len();
        if win_len <= norm_new.len() {
            let mut best: Option<(bool, usize, u32, u32)> = None;
            for start_idx in 0..=(norm_new.len() - win_len) {
                if &norm_new[start_idx..start_idx + win_len] == norm_snip.as_slice() {
                    let start_1 = (start_idx + 1) as u32;
                    let end_1 = (start_idx + win_len) as u32;
                    let sym_match = symbol_matches(anchor, new_file_content, start_1);
                    let dist = start_1.abs_diff(anchor.line_start) as usize;
                    let is_better = match best {
                        None => true,
                        Some((best_sym, best_dist, _, _)) => {
                            (sym_match && !best_sym) || (sym_match == best_sym && dist < best_dist)
                        }
                    };
                    if is_better {
                        best = Some((sym_match, dist, start_1, end_1));
                    }
                }
            }
            if let Some((_, _, s, e)) = best {
                return Some((s, e));
            }
        }
    } else if anchor.hunk_fingerprint != ObjectHash::ZERO {
        // Fallback fingerprint scan if caller provided only hunk_fingerprint + line range.
        let win_len = anchor
            .line_end
            .saturating_sub(anchor.line_start)
            .saturating_add(1) as usize;
        if win_len > 0 && win_len <= new_lines.len() {
            let mut best: Option<(bool, usize, u32, u32)> = None;
            for start_idx in 0..=(new_lines.len() - win_len) {
                if compute_hunk_fingerprint(&new_lines[start_idx..start_idx + win_len])
                    == expected_fp
                {
                    let start_1 = (start_idx + 1) as u32;
                    let end_1 = (start_idx + win_len) as u32;
                    let sym_match = symbol_matches(anchor, new_file_content, start_1);
                    let dist = start_1.abs_diff(anchor.line_start) as usize;
                    let is_better = match best {
                        None => true,
                        Some((best_sym, best_dist, _, _)) => {
                            (sym_match && !best_sym) || (sym_match == best_sym && dist < best_dist)
                        }
                    };
                    if is_better {
                        best = Some((sym_match, dist, start_1, end_1));
                    }
                }
            }
            if let Some((_, _, s, e)) = best {
                return Some((s, e));
            }
        }
        return None;
    }

    // Tier 3: Fuzzy `similar` line-similarity match (>= 0.6 ratio).
    let norm_snip: Vec<&str> = snippet_lines.iter().map(|l| l.trim()).collect();
    if norm_snip.is_empty() {
        return None;
    }

    let non_empty_snip: HashSet<&str> = norm_snip
        .iter()
        .copied()
        .filter(|l| !l.is_empty())
        .collect();
    if non_empty_snip.is_empty() {
        return None;
    }

    let snip_len = norm_snip.len();
    let min_win = snip_len.saturating_sub(2).max(1);
    let max_win = (snip_len + 2).min(norm_new.len());

    // Pre-mark lines that match any non-empty line in the snippet so we skip irrelevant windows.
    let line_hits: Vec<bool> = norm_new
        .iter()
        .map(|l| !l.is_empty() && non_empty_snip.contains(l))
        .collect();
    // Prefix sums of hits for O(1) window hit check.
    let mut hit_prefix = Vec::with_capacity(line_hits.len() + 1);
    hit_prefix.push(0usize);
    for &hit in &line_hits {
        let prev = *hit_prefix.last().unwrap();
        hit_prefix.push(prev + usize::from(hit));
    }

    let mut best_fuzzy: Option<(f32, bool, usize, usize, u32, u32)> = None;

    for win_len in min_win..=max_win {
        let len_diff = win_len.abs_diff(snip_len);
        for start_idx in 0..=(norm_new.len() - win_len) {
            let end_idx = start_idx + win_len;
            // Require at least one non-empty line match to prevent blank-line false positives.
            if hit_prefix[end_idx] - hit_prefix[start_idx] == 0 {
                continue;
            }

            let window = &norm_new[start_idx..end_idx];
            let ratio = TextDiff::from_slices(&norm_snip, window).ratio();
            if ratio < FUZZY_SIMILARITY_THRESHOLD {
                continue;
            }

            let start_1 = (start_idx + 1) as u32;
            let end_1 = end_idx as u32;
            let sym_match = symbol_matches(anchor, new_file_content, start_1);
            let dist = start_1.abs_diff(anchor.line_start) as usize;

            let is_better = match best_fuzzy {
                None => true,
                Some((best_ratio, best_sym, best_len_diff, best_dist, _, _)) => {
                    if (ratio - best_ratio).abs() > 1e-6 {
                        ratio > best_ratio
                    } else if sym_match != best_sym {
                        sym_match
                    } else if len_diff != best_len_diff {
                        len_diff < best_len_diff
                    } else {
                        dist < best_dist
                    }
                }
            };

            if is_better {
                best_fuzzy = Some((ratio, sym_match, len_diff, dist, start_1, end_1));
            }
        }
    }

    best_fuzzy.map(|(_, _, _, _, s, e)| (s, e))
}

fn symbol_matches(anchor: &CodeAnchor, new_file_content: &str, line_1based: u32) -> bool {
    match &anchor.symbol {
        Some(expected) => {
            extract_symbol_hint_for_path(&anchor.path, new_file_content, line_1based).as_deref()
                == Some(expected.as_str())
        }
        None => false,
    }
}

/// Extract the enclosing symbol for `path` at `line_1based`, preferring Tree-sitter AST
/// extraction (Rust/TS/TSX/JS/Python) when the `ast` feature is enabled and falling back to
/// [`extract_symbol_hint`] for unsupported file types or pure-WASM builds.
pub fn extract_symbol_hint_for_path(
    path: &str,
    file_content: &str,
    line_1based: u32,
) -> Option<String> {
    #[cfg(feature = "ast")]
    {
        if let Some(sym) = gitx_merge::symbol_at_line(path, file_content, line_1based) {
            return Some(sym.name);
        }
    }
    let _ = path;
    extract_symbol_hint(file_content, line_1based)
}

/// Scan upward from `line_1based` to find the nearest enclosing symbol declaration.
///
/// Recognizes `fn `, `struct `, `impl `, `function `, `class `, `def `, and `export const `.
pub fn extract_symbol_hint(file_content: &str, line_1based: u32) -> Option<String> {
    let lines: Vec<&str> = file_content.lines().collect();
    if lines.is_empty() || line_1based == 0 {
        return None;
    }

    let start_idx = ((line_1based - 1) as usize).min(lines.len() - 1);

    for idx in (0..=start_idx).rev() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        if let Some(sym) = parse_symbol_from_line(trimmed) {
            return Some(sym);
        }
    }

    None
}

fn parse_symbol_from_line(trimmed: &str) -> Option<String> {
    if let Some(rest) = find_decl_keyword(trimmed, "export const ") {
        return extract_ident(rest);
    }
    if let Some(rest) = find_decl_keyword(trimmed, "fn ") {
        return extract_ident(rest);
    }
    if let Some(rest) = find_decl_keyword(trimmed, "struct ") {
        return extract_ident(rest);
    }
    if let Some(rest) = find_decl_keyword(trimmed, "function ") {
        return extract_ident(rest);
    }
    if let Some(rest) = find_decl_keyword(trimmed, "class ") {
        return extract_ident(rest);
    }
    if let Some(rest) = find_decl_keyword(trimmed, "def ") {
        return extract_ident(rest);
    }
    if let Some(header) = parse_impl_header(trimmed) {
        return Some(header);
    }
    None
}

/// Find `keyword` in `trimmed` only when preceded by declaration-compatible tokens
/// (no assignment `=`, quotes, or parentheses before it) and on a whitespace/start boundary.
fn find_decl_keyword<'a>(trimmed: &'a str, keyword: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(pos) = trimmed[offset..].find(keyword) {
        let abs = offset + pos;
        let prefix = &trimmed[..abs];
        let boundary_ok = abs == 0
            || prefix
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_whitespace());
        let prefix_clean = !prefix.contains('=')
            && !prefix.contains('"')
            && !prefix.contains('\'')
            && !prefix.contains(';');
        if boundary_ok && prefix_clean {
            return Some(&trimmed[abs + keyword.len()..]);
        }
        offset = abs + 1;
    }
    None
}

fn parse_impl_header(trimmed: &str) -> Option<String> {
    let after_impl = find_decl_keyword(trimmed, "impl ")
        .map(|rest| ("impl ", rest))
        .or_else(|| find_decl_keyword(trimmed, "impl<").map(|rest| ("impl<", rest)))?;

    let full = format!("{}{}", after_impl.0, after_impl.1);
    let cut = full
        .find('{')
        .or_else(|| full.find(" where "))
        .unwrap_or(full.len());
    let header = full[..cut].trim();
    if header.is_empty() {
        None
    } else {
        Some(header.to_string())
    }
}

fn extract_ident(rest: &str) -> Option<String> {
    let trimmed = rest.trim_start();
    let ident: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_leading_and_trailing_whitespace() {
        let a = compute_hunk_fingerprint(&["  let x = 1;  ", "    let y = 2;"]);
        let b = compute_hunk_fingerprint(&["let x = 1;", "let y = 2;"]);
        assert_eq!(a, b);
    }

    #[test]
    fn symbol_hints_across_languages() {
        let rust = "pub struct Foo {\n    x: u32,\n}\n\nimpl Foo {\n    pub async fn compute(&self) -> u32 {\n        self.x + 1\n    }\n}\n";
        assert_eq!(extract_symbol_hint(rust, 2).as_deref(), Some("Foo"));
        assert_eq!(extract_symbol_hint(rust, 5).as_deref(), Some("impl Foo"));
        assert_eq!(extract_symbol_hint(rust, 7).as_deref(), Some("compute"));

        let ts = "export const fetchUser = async (id: string) => {\n  return id;\n};\n\nexport class UserService {\n  async function helper() {}\n}\n";
        assert_eq!(extract_symbol_hint(ts, 2).as_deref(), Some("fetchUser"));
        assert_eq!(extract_symbol_hint(ts, 5).as_deref(), Some("UserService"));

        let py = "class Worker:\n    def run_job(self, x):\n        return x * 2\n";
        assert_eq!(extract_symbol_hint(py, 3).as_deref(), Some("run_job"));
        assert_eq!(extract_symbol_hint(py, 1).as_deref(), Some("Worker"));
    }
}
