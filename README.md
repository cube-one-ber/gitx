<img src="assets/icon.svg" width="64" height="64" alt="GitX">

# GitX

**A next-generation Git replacement written in Rust — built for modern teams, monorepos, and AI coding agents.**

Source control shouldn't be 100% or 0% access, lock branches inside clunky worktrees, force every CI job to clone gigabytes of history, or lose the *why* behind every change. **GitX** rethinks version control from first principles while keeping an incremental, lossless interoperability bridge with Git.

> **Status:** Working Rust workspace (9 crates, 76 passing unit/integration/E2E tests, zero clippy warnings). See [PLAN.md](PLAN.md) for the full technical design and roadmap.

## Quickstart

```bash
# Build & test the full workspace
cargo test --workspace

# Run the CLI
cargo run --bin gitx -- --help

# Initialize a repo (or --colocate inside an existing Git repo)
gitx init
gitx status
gitx describe -m "Initial feature"
gitx land --target master

# Native encrypted .env secrets & ACL-filtered Git export
gitx secret set .env --domain secret:dev
gitx git-export /tmp/public-mirror --domains public

# Start the always-online zero-clone + ACL-filtered Git Smart HTTP server
gitx serve --addr 127.0.0.1:7878
```

---

## Core Capabilities

- **Granular Access Control & Native Secrets (`.env`):** File-, directory-, branch/stack-, and change-level permissions via **Visibility Domains** and **Domain-Partitioned Merkle Trees**. Commit `.env` and private sub-packages directly inside public monorepos using envelope encryption with key epochs, audit logs, and true revocation—without ever leaking private hashes into public history.
- **Delayed Disclosure / Embargoed Merges:** Merge, build, and distribute security patches privately to maintainers and distros before promoting the diff into the public timeline.
- **Snapshots, Native Stacks & First-Class Conflicts:** Always-live working-copy snapshots (`@`), stable `ChangeId`s, an immutable operation log (`gitx undo`), Graphite/Meta-style stacked diffs with revision interdiffs (`v1..v2`), and algebraic conflicts stored *inside* changes so partial merges (by humans or agents) never block progress.
- **Instant, Lock-Free Workspaces (No Git Worktrees):** Multiple workspaces can share `main` without holding branches hostage. Three pluggable backends:
  - `mem://` — Zero-disk, zero-OS in-memory VFS for AI agents (`just-bash`-compatible) and fast CI.
  - `cow://` — Copy-on-write / reflink (`FICLONE` / `clonefile`) local checkouts that eliminate APFS/disk bloat.
  - `vfs://` — Lazy FUSE3 / NFSv3 virtualized mounts for instant checkouts on huge monorepos.
- **Always-Online Server & Zero-Clone APIs:** BLAKE3 + FastCDC chunked blob storage (zero packfiles, zero Git LFS hacks), push-to-create repos, server-side RPCs (`diff`, `blame`, `grep`, `rebase`, `land`) so CI and agents never need full clones, derived server indices, ACID transactional landings, and O(1) atomic reverts.
- **Agent Provenance & Durable "Why" Context:** First-class `author` (human) vs. `committer` (agent/model/harness) metadata, sub-commit checkpoints that undo agent turns without clobbering human edits, and a durable context store (`gitx why <file>:<line>`) anchored across rebases and squashes.
- **Cross-Machine Fleet Sync ("Dropbox for Devs"):** Encrypted delta sync of `.env` files, configured gitignored overlays, and WIP snapshots across laptops, Linux agent boxes, and cloud sandboxes.
- **Lossless Git Interoperability:** Colocated `.git` mode (`gitx init --colocate`) powered by `gitoxide`, plus an ACL-filtered Git Smart HTTP/SSH bridge so standard `git clone` clients work seamlessly while seeing *only* authorized domains.

---

## Planned Workspace Structure

```text
gitx/
├── crates/
│   ├── gitx-core/         # ChangeSet, ChangeId, BLAKE3, FastCDC, VisibilityDomain, ConflictSet, OpLog
│   ├── gitx-crypto/       # Envelope encryption (age/X25519 + ChaCha20), key epochs, ACLs, secret scanner
│   ├── gitx-store/        # CAS & metadata backends (SQLite/FS locally; Postgres/S3/R2 + RAM cache on server)
│   ├── gitx-merge/        # 3-way merge, JSON/TOML/YAML key merge, Tree-sitter AST merge, algebraic conflicts
│   ├── gitx-vfs/          # mem://, cow://, vfs:// (FUSE3/NFSv3), cross-machine fleet sync
│   ├── gitx-context/      # Sub-commit checkpoints & durable "why" store with AST/hunk anchoring
│   ├── gitx-git-bridge/   # gitoxide colocated bridge + ACL-filtered Git Smart HTTP/SSH adapter
│   ├── gitx-proto/        # gRPC / HTTP / JSON-RPC schemas
│   ├── gitx-server/       # Axum + Tonic server, IAM/embargo engine, derived indices, transactional landing queue
│   ├── gitx-cli/          # Single static `gitx` binary
│   └── gitx-sdk/          # MCP server, JSON-RPC daemon, TypeScript/N-API & WASM bindings
└── tests/
    ├── sim/               # Deterministic hermetic simulation & crash/concurrency fuzzing
    └── bench/             # Workspace fan-out, large-repo status/diff, 16-agent concurrent landing benchmarks
```

---

## Roadmap Summary

| Phase | Milestone |
| --- | --- |
| **Phase 0** | Core BLAKE3+FastCDC storage, snapshots (`@`), OpLog (`undo`), `mem://` & `cow://` workspaces, core CLI |
| **Phase 1** | First-class conflicts inside ChangeSets, semantic/AST merge, native stacked diffs + interdiffs, colocated `.git` bridge |
| **Phase 2** | `.gitxacl` Visibility Domains, stable public Merkle projections, envelope-encrypted `.env` secrets, private branches & embargoes |
| **Phase 3** | Always-online `gitx-server`, push-to-create, zero-clone RPCs, derived data workers, ACID landing/revert, ACL-filtered Git HTTP |
| **Phase 4** | `vfs://` lazy virtualized mounts (FUSE3 / NFSv3), in-memory Agent/MCP/TS SDK, encrypted multi-machine fleet sync |
| **Phase 5** | Sub-commit agent checkpoints, durable `gitx why` context store, batched agentic merge queue, hermetic simulation & fuzzing |

Read the complete specification and verification plan in **[PLAN.md](PLAN.md)**.
