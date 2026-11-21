use crate::merge::{MergeOutcome, merge_bytes};
use crate::tree_merge::{TreeMergeResult, merge_domain_trees};
use gitx_core::{DomainTree, ObjectHash, Result};

/// Undo an AI agent's edit (`before_agent -> after_agent`) on `path` while preserving
/// non-overlapping human edits made afterwards (`after_agent -> current_with_human_edits`).
///
/// Implemented as a 3-way inverse patch:
/// `merge_bytes(path, after_agent, before_agent, current_with_human_edits)`.
pub fn revert_agent_step(
    path: &str,
    before_agent: &[u8],
    after_agent: &[u8],
    current_with_human_edits: &[u8],
) -> MergeOutcome {
    merge_bytes(path, after_agent, before_agent, current_with_human_edits)
}

/// Tree-level inverse patch to undo an agent's checkpoint (`before_agent -> after_agent`)
/// while preserving subsequent human edits (`current_with_human_edits`).
pub fn revert_agent_tree_step<F, W>(
    before_agent: &DomainTree,
    after_agent: &DomainTree,
    current_with_human_edits: &DomainTree,
    read_blob: F,
    write_blob: W,
) -> Result<TreeMergeResult>
where
    F: Fn(ObjectHash) -> Result<Vec<u8>>,
    W: FnMut(&[u8]) -> Result<(ObjectHash, u64)>,
{
    merge_domain_trees(
        after_agent,
        before_agent,
        current_with_human_edits,
        read_blob,
        write_blob,
    )
}
