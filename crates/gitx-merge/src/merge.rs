use gitx_core::ObjectHash;
use serde::{Deserialize, Serialize};
use similar::{DiffOp, TextDiff};
use std::collections::BTreeSet;
use std::path::Path;

/// Result of a 3-way merge of byte content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeOutcome {
    /// Merged cleanly with no conflicts.
    Clean(Vec<u8>),
    /// Merge produced one or more conflicts, materialized with diff3 markers.
    Conflict { materialized: Vec<u8>, hunks: usize },
}

impl MergeOutcome {
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean(_))
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }

    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Clean(bytes) => bytes,
            Self::Conflict { materialized, .. } => materialized,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Clean(bytes) => bytes,
            Self::Conflict { materialized, .. } => materialized,
        }
    }
}

/// 3-way merge of file bytes with structured key-aware semantic merging for JSON and TOML,
/// 3-way line merging for UTF-8 text, and binary conflict fallback for non-UTF-8 content.
pub fn merge_bytes(path: &str, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeOutcome {
    // Fast paths
    if ours == theirs {
        return MergeOutcome::Clean(ours.to_vec());
    }
    if ours == base {
        return MergeOutcome::Clean(theirs.to_vec());
    }
    if theirs == base {
        return MergeOutcome::Clean(ours.to_vec());
    }

    // Binary fallback if any side is non-UTF-8
    let (Ok(base_str), Ok(ours_str), Ok(theirs_str)) = (
        std::str::from_utf8(base),
        std::str::from_utf8(ours),
        std::str::from_utf8(theirs),
    ) else {
        return MergeOutcome::Conflict {
            materialized: materialize_binary_conflict(path, base, ours, theirs),
            hunks: 1,
        };
    };

    // Structured semantic merge for JSON
    if has_extension_ci(path, "json")
        && let Some(outcome) = try_merge_json(base_str, ours_str, theirs_str)
    {
        return outcome;
    }

    // Structured semantic merge for TOML
    if has_extension_ci(path, "toml")
        && let Some(outcome) = try_merge_toml(base_str, ours_str, theirs_str)
    {
        return outcome;
    }

    // Structured semantic merge for YAML
    if (has_extension_ci(path, "yaml") || has_extension_ci(path, "yml"))
        && let Some(outcome) = try_merge_yaml(base_str, ours_str, theirs_str)
    {
        return outcome;
    }

    // Standard 3-way line merge first (guarantees zero formatting churn on clean line merges)
    let line_outcome = merge_lines(base_str, ours_str, theirs_str);
    #[cfg(feature = "ast")]
    {
        let needs_ast_merge = match &line_outcome {
            MergeOutcome::Conflict { .. } => true,
            MergeOutcome::Clean(bytes) => std::str::from_utf8(bytes)
                .is_ok_and(|merged| crate::ast_merge::has_duplicate_top_level_keys(path, merged)),
        };
        if needs_ast_merge
            && let Some(ast_outcome) =
                crate::ast_merge::try_ast_merge(path, base_str, ours_str, theirs_str)
        {
            return ast_outcome;
        }
    }
    line_outcome
}

fn has_extension_ci(path: &str, expected: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(expected))
}

fn materialize_binary_conflict(path: &str, base: &[u8], ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    let base_hash = ObjectHash::of_bytes(base).short();
    let ours_hash = ObjectHash::of_bytes(ours).short();
    let theirs_hash = ObjectHash::of_bytes(theirs).short();
    format!(
        "<<<<<<< OURS\n\
         [binary file {path}: {} bytes, blake3:{ours_hash}]\n\
         ||||||| BASE\n\
         [binary file {path}: {} bytes, blake3:{base_hash}]\n\
         =======\n\
         [binary file {path}: {} bytes, blake3:{theirs_hash}]\n\
         >>>>>>> THEIRS\n",
        ours.len(),
        base.len(),
        theirs.len(),
    )
    .into_bytes()
}

fn whole_file_conflict(base: &str, ours: &str, theirs: &str) -> MergeOutcome {
    let mut out = String::new();
    push_conflict_block(&mut out, &[base], &[ours], &[theirs]);
    MergeOutcome::Conflict {
        materialized: out.into_bytes(),
        hunks: 1,
    }
}

// ---------------------------------------------------------------------------
// Key-aware JSON merge
// ---------------------------------------------------------------------------

fn try_merge_json(base_str: &str, ours_str: &str, theirs_str: &str) -> Option<MergeOutcome> {
    let ours_val: serde_json::Value = serde_json::from_str(ours_str).ok()?;
    let theirs_val: serde_json::Value = serde_json::from_str(theirs_str).ok()?;
    let base_val: serde_json::Value = if base_str.trim().is_empty() {
        if ours_val.is_object() && theirs_val.is_object() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            return None;
        }
    } else {
        serde_json::from_str(base_str).ok()?
    };

    match merge_json_value(&base_val, &ours_val, &theirs_val) {
        Ok(merged) => {
            let mut rendered = serde_json::to_string_pretty(&merged).ok()?;
            if base_str.ends_with('\n') || ours_str.ends_with('\n') || theirs_str.ends_with('\n') {
                rendered.push('\n');
            }
            Some(MergeOutcome::Clean(rendered.into_bytes()))
        }
        Err(()) => {
            // Semantic conflict on a shared key: produce line-level conflict markers,
            // guaranteeing we never report a false clean merge.
            let line_outcome = merge_lines(base_str, ours_str, theirs_str);
            if line_outcome.is_conflict() {
                Some(line_outcome)
            } else {
                Some(whole_file_conflict(base_str, ours_str, theirs_str))
            }
        }
    }
}

fn merge_json_value(
    base: &serde_json::Value,
    ours: &serde_json::Value,
    theirs: &serde_json::Value,
) -> std::result::Result<serde_json::Value, ()> {
    if ours == theirs {
        return Ok(ours.clone());
    }
    if ours == base {
        return Ok(theirs.clone());
    }
    if theirs == base {
        return Ok(ours.clone());
    }

    if let (
        serde_json::Value::Object(bm),
        serde_json::Value::Object(om),
        serde_json::Value::Object(tm),
    ) = (base, ours, theirs)
    {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        keys.extend(bm.keys().map(String::as_str));
        keys.extend(om.keys().map(String::as_str));
        keys.extend(tm.keys().map(String::as_str));

        let mut merged = serde_json::Map::new();
        for key in keys {
            let bv = bm.get(key);
            let ov = om.get(key);
            let tv = tm.get(key);

            if ov == tv {
                if let Some(v) = ov {
                    merged.insert(key.to_string(), v.clone());
                }
            } else if ov == bv {
                if let Some(v) = tv {
                    merged.insert(key.to_string(), v.clone());
                }
            } else if tv == bv {
                if let Some(v) = ov {
                    merged.insert(key.to_string(), v.clone());
                }
            } else {
                match (bv, ov, tv) {
                    (Some(b_val), Some(o_val), Some(t_val)) => {
                        let sub = merge_json_value(b_val, o_val, t_val)?;
                        merged.insert(key.to_string(), sub);
                    }
                    (
                        None,
                        Some(o_val @ serde_json::Value::Object(_)),
                        Some(t_val @ serde_json::Value::Object(_)),
                    ) => {
                        let empty = serde_json::Value::Object(serde_json::Map::new());
                        let sub = merge_json_value(&empty, o_val, t_val)?;
                        merged.insert(key.to_string(), sub);
                    }
                    _ => return Err(()),
                }
            }
        }
        Ok(serde_json::Value::Object(merged))
    } else {
        Err(())
    }
}

// ---------------------------------------------------------------------------
// Key-aware YAML merge
// ---------------------------------------------------------------------------

fn try_merge_yaml(base_str: &str, ours_str: &str, theirs_str: &str) -> Option<MergeOutcome> {
    let ours_val: serde_yaml_ng::Value = serde_yaml_ng::from_str(ours_str).ok()?;
    let theirs_val: serde_yaml_ng::Value = serde_yaml_ng::from_str(theirs_str).ok()?;
    let base_val: serde_yaml_ng::Value = if base_str.trim().is_empty() {
        if ours_val.is_mapping() && theirs_val.is_mapping() {
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new())
        } else {
            return None;
        }
    } else {
        serde_yaml_ng::from_str(base_str).ok()?
    };

    match merge_yaml_value(&base_val, &ours_val, &theirs_val) {
        Ok(merged) => {
            let rendered = serde_yaml_ng::to_string(&merged).ok()?;
            Some(MergeOutcome::Clean(rendered.into_bytes()))
        }
        Err(()) => {
            let line_outcome = merge_lines(base_str, ours_str, theirs_str);
            if line_outcome.is_conflict() {
                Some(line_outcome)
            } else {
                Some(whole_file_conflict(base_str, ours_str, theirs_str))
            }
        }
    }
}

fn merge_yaml_value(
    base: &serde_yaml_ng::Value,
    ours: &serde_yaml_ng::Value,
    theirs: &serde_yaml_ng::Value,
) -> std::result::Result<serde_yaml_ng::Value, ()> {
    if ours == theirs {
        return Ok(ours.clone());
    }
    if ours == base {
        return Ok(theirs.clone());
    }
    if theirs == base {
        return Ok(ours.clone());
    }

    if let (
        serde_yaml_ng::Value::Mapping(bm),
        serde_yaml_ng::Value::Mapping(om),
        serde_yaml_ng::Value::Mapping(tm),
    ) = (base, ours, theirs)
    {
        let mut keys: Vec<serde_yaml_ng::Value> = Vec::new();
        for k in bm.keys().chain(om.keys()).chain(tm.keys()) {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }

        let mut merged = serde_yaml_ng::Mapping::new();
        for key in keys {
            let bv = bm.get(&key);
            let ov = om.get(&key);
            let tv = tm.get(&key);

            if ov == tv {
                if let Some(v) = ov {
                    merged.insert(key, v.clone());
                }
            } else if ov == bv {
                if let Some(v) = tv {
                    merged.insert(key, v.clone());
                }
            } else if tv == bv {
                if let Some(v) = ov {
                    merged.insert(key, v.clone());
                }
            } else {
                match (bv, ov, tv) {
                    (Some(b_val), Some(o_val), Some(t_val)) => {
                        let sub = merge_yaml_value(b_val, o_val, t_val)?;
                        merged.insert(key, sub);
                    }
                    (
                        None,
                        Some(o_val @ serde_yaml_ng::Value::Mapping(_)),
                        Some(t_val @ serde_yaml_ng::Value::Mapping(_)),
                    ) => {
                        let empty = serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new());
                        let sub = merge_yaml_value(&empty, o_val, t_val)?;
                        merged.insert(key, sub);
                    }
                    _ => return Err(()),
                }
            }
        }
        Ok(serde_yaml_ng::Value::Mapping(merged))
    } else {
        Err(())
    }
}

// ---------------------------------------------------------------------------
// Key-aware TOML merge
// ---------------------------------------------------------------------------

fn try_merge_toml(base_str: &str, ours_str: &str, theirs_str: &str) -> Option<MergeOutcome> {
    let ours_table: toml::Table = ours_str.parse().ok()?;
    let theirs_table: toml::Table = theirs_str.parse().ok()?;
    let base_table: toml::Table = if base_str.trim().is_empty() {
        toml::Table::new()
    } else {
        base_str.parse().ok()?
    };

    let base_val = toml::Value::Table(base_table);
    let ours_val = toml::Value::Table(ours_table);
    let theirs_val = toml::Value::Table(theirs_table);

    match merge_toml_value(&base_val, &ours_val, &theirs_val) {
        Ok(toml::Value::Table(merged_table)) => {
            let rendered = toml::to_string_pretty(&merged_table).ok()?;
            Some(MergeOutcome::Clean(rendered.into_bytes()))
        }
        Ok(_) => None,
        Err(()) => {
            let line_outcome = merge_lines(base_str, ours_str, theirs_str);
            if line_outcome.is_conflict() {
                Some(line_outcome)
            } else {
                Some(whole_file_conflict(base_str, ours_str, theirs_str))
            }
        }
    }
}

fn merge_toml_value(
    base: &toml::Value,
    ours: &toml::Value,
    theirs: &toml::Value,
) -> std::result::Result<toml::Value, ()> {
    if ours == theirs {
        return Ok(ours.clone());
    }
    if ours == base {
        return Ok(theirs.clone());
    }
    if theirs == base {
        return Ok(ours.clone());
    }

    if let (toml::Value::Table(bt), toml::Value::Table(ot), toml::Value::Table(tt)) =
        (base, ours, theirs)
    {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        keys.extend(bt.keys().map(String::as_str));
        keys.extend(ot.keys().map(String::as_str));
        keys.extend(tt.keys().map(String::as_str));

        let mut merged = toml::map::Map::new();
        for key in keys {
            let bv = bt.get(key);
            let ov = ot.get(key);
            let tv = tt.get(key);

            if ov == tv {
                if let Some(v) = ov {
                    merged.insert(key.to_string(), v.clone());
                }
            } else if ov == bv {
                if let Some(v) = tv {
                    merged.insert(key.to_string(), v.clone());
                }
            } else if tv == bv {
                if let Some(v) = ov {
                    merged.insert(key.to_string(), v.clone());
                }
            } else {
                match (bv, ov, tv) {
                    (Some(b_val), Some(o_val), Some(t_val)) => {
                        let sub = merge_toml_value(b_val, o_val, t_val)?;
                        merged.insert(key.to_string(), sub);
                    }
                    (
                        None,
                        Some(o_val @ toml::Value::Table(_)),
                        Some(t_val @ toml::Value::Table(_)),
                    ) => {
                        let empty = toml::Value::Table(toml::map::Map::new());
                        let sub = merge_toml_value(&empty, o_val, t_val)?;
                        merged.insert(key.to_string(), sub);
                    }
                    _ => return Err(()),
                }
            }
        }
        Ok(toml::Value::Table(merged))
    } else {
        Err(())
    }
}

// ---------------------------------------------------------------------------
// 3-way line merge (similar diff hunks against base)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Edit {
    base_start: usize,
    base_end: usize,
    side_start: usize,
    side_end: usize,
}

impl Edit {
    fn delta(&self) -> isize {
        (self.side_end - self.side_start) as isize - (self.base_end - self.base_start) as isize
    }
}

fn collect_edits(ops: &[DiffOp]) -> Vec<Edit> {
    let mut edits: Vec<Edit> = Vec::new();
    for op in ops {
        let (b_start, b_end, s_start, s_end) = match *op {
            DiffOp::Equal { .. } => continue,
            DiffOp::Delete {
                old_index,
                old_len,
                new_index,
            } => (old_index, old_index + old_len, new_index, new_index),
            DiffOp::Insert {
                old_index,
                new_index,
                new_len,
            } => (old_index, old_index, new_index, new_index + new_len),
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => (
                old_index,
                old_index + old_len,
                new_index,
                new_index + new_len,
            ),
        };

        if let Some(last) = edits.last_mut()
            && last.base_end == b_start
            && last.side_end == s_start
        {
            last.base_end = b_end;
            last.side_end = s_end;
        } else {
            edits.push(Edit {
                base_start: b_start,
                base_end: b_end,
                side_start: s_start,
                side_end: s_end,
            });
        }
    }
    edits
}

/// Returns true if two base ranges `[a0, a1)` and `[b0, b1)` cannot be cleanly ordered.
fn ranges_overlap(a0: usize, a1: usize, b0: usize, b1: usize) -> bool {
    if a0 == a1 && b0 == b1 {
        a0 == b0
    } else if a0 == a1 {
        b0 < a0 && a0 < b1
    } else if b0 == b1 {
        a0 < b0 && b0 < a1
    } else {
        a0 < b1 && b0 < a1
    }
}

fn edits_overlap(a: &Edit, b: &Edit) -> bool {
    ranges_overlap(a.base_start, a.base_end, b.base_start, b.base_end)
}

fn edit_precedes(a: &Edit, b: &Edit) -> bool {
    !edits_overlap(a, b)
        && (a.base_start < b.base_start
            || (a.base_start == b.base_start && a.base_end < b.base_end))
}

pub(crate) fn merge_lines(base: &str, ours: &str, theirs: &str) -> MergeOutcome {
    let diff_ours = TextDiff::from_lines(base, ours);
    let diff_theirs = TextDiff::from_lines(base, theirs);

    let base_lines = diff_ours.old_slices();
    let ours_lines = diff_ours.new_slices();
    let theirs_lines = diff_theirs.new_slices();

    let ours_edits = collect_edits(diff_ours.ops());
    let theirs_edits = collect_edits(diff_theirs.ops());

    let mut out = String::with_capacity(base.len().max(ours.len()).max(theirs.len()));
    let mut conflict_hunks = 0usize;

    let mut base_pos = 0usize;
    let mut oi = 0usize;
    let mut ti = 0usize;
    let mut ours_delta = 0isize;
    let mut theirs_delta = 0isize;

    while oi < ours_edits.len() || ti < theirs_edits.len() {
        match (ours_edits.get(oi), theirs_edits.get(ti)) {
            (Some(&o), None) => {
                push_slices(&mut out, &base_lines[base_pos..o.base_start]);
                push_slices(&mut out, &ours_lines[o.side_start..o.side_end]);
                base_pos = o.base_end;
                ours_delta += o.delta();
                oi += 1;
            }
            (None, Some(&t)) => {
                push_slices(&mut out, &base_lines[base_pos..t.base_start]);
                push_slices(&mut out, &theirs_lines[t.side_start..t.side_end]);
                base_pos = t.base_end;
                theirs_delta += t.delta();
                ti += 1;
            }
            (Some(&o), Some(&t)) if edit_precedes(&o, &t) => {
                push_slices(&mut out, &base_lines[base_pos..o.base_start]);
                push_slices(&mut out, &ours_lines[o.side_start..o.side_end]);
                base_pos = o.base_end;
                ours_delta += o.delta();
                oi += 1;
            }
            (Some(&o), Some(&t)) if edit_precedes(&t, &o) => {
                push_slices(&mut out, &base_lines[base_pos..t.base_start]);
                push_slices(&mut out, &theirs_lines[t.side_start..t.side_end]);
                base_pos = t.base_end;
                theirs_delta += t.delta();
                ti += 1;
            }
            (Some(&o), Some(&t)) => {
                // Overlapping cluster
                let span_start = o.base_start.min(t.base_start);
                let mut span_end = o.base_end.max(t.base_end);

                let ours_delta_start = ours_delta;
                let theirs_delta_start = theirs_delta;

                ours_delta += o.delta();
                oi += 1;
                theirs_delta += t.delta();
                ti += 1;

                // Transitively absorb any subsequent edits overlapping [span_start, span_end)
                loop {
                    let mut extended = false;
                    if let Some(&next_o) = ours_edits.get(oi)
                        && ranges_overlap(span_start, span_end, next_o.base_start, next_o.base_end)
                    {
                        span_end = span_end.max(next_o.base_end);
                        ours_delta += next_o.delta();
                        oi += 1;
                        extended = true;
                    }
                    if let Some(&next_t) = theirs_edits.get(ti)
                        && ranges_overlap(span_start, span_end, next_t.base_start, next_t.base_end)
                    {
                        span_end = span_end.max(next_t.base_end);
                        theirs_delta += next_t.delta();
                        ti += 1;
                        extended = true;
                    }
                    if !extended {
                        break;
                    }
                }

                push_slices(&mut out, &base_lines[base_pos..span_start]);

                let ours_start = (span_start as isize + ours_delta_start) as usize;
                let ours_end = (span_end as isize + ours_delta) as usize;
                let theirs_start = (span_start as isize + theirs_delta_start) as usize;
                let theirs_end = (span_end as isize + theirs_delta) as usize;

                let base_chunk = &base_lines[span_start..span_end];
                let ours_chunk = &ours_lines[ours_start..ours_end];
                let theirs_chunk = &theirs_lines[theirs_start..theirs_end];

                if ours_chunk == theirs_chunk {
                    // Convergent edit (false conflict): emit once cleanly
                    push_slices(&mut out, ours_chunk);
                } else {
                    conflict_hunks += 1;
                    push_conflict_block(&mut out, base_chunk, ours_chunk, theirs_chunk);
                }

                base_pos = span_end;
            }
            (None, None) => break,
        }
    }

    push_slices(&mut out, &base_lines[base_pos..]);

    if conflict_hunks == 0 {
        MergeOutcome::Clean(out.into_bytes())
    } else {
        MergeOutcome::Conflict {
            materialized: out.into_bytes(),
            hunks: conflict_hunks,
        }
    }
}

fn push_slices(out: &mut String, slices: &[&str]) {
    for s in slices {
        out.push_str(s);
    }
}

fn push_section_lines(out: &mut String, slices: &[&str]) {
    let start_len = out.len();
    push_slices(out, slices);
    if out.len() > start_len && !out.ends_with('\n') {
        out.push('\n');
    }
}

fn push_conflict_block(out: &mut String, base: &[&str], ours: &[&str], theirs: &[&str]) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("<<<<<<< OURS\n");
    push_section_lines(out, ours);
    out.push_str("||||||| BASE\n");
    push_section_lines(out, base);
    out.push_str("=======\n");
    push_section_lines(out, theirs);
    out.push_str(">>>>>>> THEIRS\n");
}
