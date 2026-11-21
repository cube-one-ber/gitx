//! Hermetic deterministic simulator, adversarial ACL & secret-leak fuzzer,
//! concurrent AST/JSON merge-queue stress tester, and GitX-vs-Git benchmark harness.

pub mod bench;
pub mod sim;

pub use bench::{
    BenchConfig, BenchReport, MergeBenchResult, ServerQueryBenchResult, WorkspaceFanOutResult,
    format_markdown_report, run_benchmarks, run_benchmarks_with_config,
};
pub use sim::{
    AclFuzzReport, MergeQueueStressReport, OpLogSimReport, SimConfig, run_acl_secret_leak_fuzzer,
    run_concurrent_merge_queue_stress, run_oplog_crash_recovery_sim,
};
