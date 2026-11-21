use gitx_sim::{
    SimConfig, format_markdown_report, run_acl_secret_leak_fuzzer, run_benchmarks,
    run_concurrent_merge_queue_stress, run_oplog_crash_recovery_sim,
};

#[test]
fn oplog_and_crash_recovery_simulator_200_ops() {
    let cfg = SimConfig::default();
    let report_a =
        run_oplog_crash_recovery_sim(&cfg).expect("oplog crash-recovery sim run 1 succeeded");
    let report_b =
        run_oplog_crash_recovery_sim(&cfg).expect("oplog crash-recovery sim run 2 succeeded");

    assert_eq!(report_a.total_ops_executed, 200);
    assert!(report_a.crash_recoveries >= 10);
    assert!(report_a.file_edits > 0);
    assert!(report_a.new_changesets > 0);
    assert!(report_a.lands > 0);
    assert!(report_a.reverts > 0);
    assert!(report_a.undos > 0);
    assert!(report_a.workspace_adds > 0);
    assert_eq!(report_a.final_oplog_len, 201); // Init + 200 ops
    assert!(report_a.final_land_seq >= (1 + report_a.lands + report_a.reverts) as u64);
    assert!(report_a.verified_blobs > 0);

    // Deterministic seeded execution yields identical operation breakdown!
    assert_eq!(report_a, report_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_acl_and_secret_leak_fuzzer() {
    let cfg = SimConfig::default();
    let report = run_acl_secret_leak_fuzzer(&cfg)
        .await
        .expect("ACL fuzzer found zero leaks and git fsck passed");

    assert_eq!(report.leaks_detected, 0);
    assert!(report.git_fsck_passed);
    assert_eq!(report.canaries_planted, 7);
    assert!(report.total_http_probes >= 80);
    assert!(report.cloned_git_objects_inspected > 0);
    assert!(report.cloned_files_inspected > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_32_agent_ast_and_json_merge_queue_stress() {
    let cfg = SimConfig::default();
    let report = run_concurrent_merge_queue_stress(&cfg)
        .await
        .expect("32-agent concurrent AST + JSON merge queue stress succeeded");

    assert_eq!(report.agent_count, 32);
    assert_eq!(report.batch_landed, 32);
    assert_eq!(report.conflicts, 0);
    assert_eq!(report.rejected, 0);
    assert_eq!(report.rust_functions_verified, 32);
    assert_eq!(report.json_keys_verified, 32);
    assert_eq!(report.land_seqs, vec![1, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benchmark_suite_smoke_test() {
    let report = run_benchmarks()
        .await
        .expect("benchmark suite completed cleanly");

    assert_eq!(report.workspace_fanout.len(), 2);
    for row in &report.workspace_fanout {
        assert_eq!(row.repo_file_count, 250);
        assert_eq!(row.git_worktree_files_written, row.workspace_count * 250);
        assert_eq!(row.cow_workspace_files_written, row.workspace_count * 250);
        assert_eq!(row.lazy_workspace_files_written, 0);
        assert_eq!(row.mem_vfs_files_written, 0);
    }

    assert_eq!(report.same_file_merge.agent_count, 16);
    assert_eq!(report.same_file_merge.total_merges, 15);
    assert_eq!(report.same_file_merge.git_line_merge_conflicts, 15);
    assert_eq!(report.same_file_merge.gitx_ast_merge_conflicts, 0);

    assert_eq!(report.server_query.repo_file_count, 250);
    assert!(report.server_query.warm_trigram_cache_hits >= 10);

    let md = format_markdown_report(&report);
    assert!(md.contains("GitX vs Git Benchmark Report"));
    assert!(md.contains("Workspace Fan-Out"));
    assert!(md.contains("Multi-Agent Same-File Merge"));
    assert!(md.contains("Zero-Clone Server Grep & Diff"));
}
