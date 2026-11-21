//! 3-way text and semantic merging, Jujutsu-style algebraic tree merging,
//! unified diffs, Graphite-style interdiffs, and inverse patches for agent checkpoint undo.

pub mod diff;
pub mod merge;
pub mod tree_merge;
pub mod undo_patch;

pub use diff::{DiffStatus, TreeDiffEntry, diff_trees, render_interdiff, unified_diff};
pub use merge::{MergeOutcome, merge_bytes};
pub use tree_merge::{
    TreeMergeResult, materialize_conflict, merge_domain_trees, resolve_conflict_by_deletion,
    resolve_conflict_in_tree,
};
pub use undo_patch::{revert_agent_step, revert_agent_tree_step};
