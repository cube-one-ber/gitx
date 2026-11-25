<img src="assets/icon.svg" width="64" height="64" alt="GitX">

# GitX

**A next-generation Git replacement written in Rust — built for modern teams, monorepos, and AI coding agents.**

Source control shouldn't be 100% or 0% access, lock branches inside clunky worktrees, force every CI job to clone gigabytes of history, or lose the *why* behind every change. **GitX** rethinks version control from first principles while keeping an incremental, lossless interoperability bridge with Git.

> **Status:** 13-crate Rust workspace + `@gitx/sdk` TypeScript/WASM package (Phases 0–5 implemented; full Rust workspace and TS/WASM test suites passing with 0 clippy warnings). See [PLAN.md](PLAN.md) for the full technical architecture and [Current Scope & Production Hardening](#current-scope--production-hardening) below.

## Quickstart

```bash
# Build & test all 13 Rust crates (including hermetic simulation & ACL fuzzing)
cargo test --workspace

# Build the WASM bindings & run the @gitx/sdk TypeScript test suite
cargo build -p gitx-wasm --target wasm32-wasip1
cargo build -p gitx-cli
node --test packages/gitx-ts/tests/*.test.ts

# Run GitX vs. Git benchmarks
cargo run --release --bin gitx-bench

# Run the CLI (26 top-level commands)
cargo run --bin gitx -- --help
```

### Local Workflow, Secrets & Workspaces

```bash
# Initialize a repo (or --colocate inside an existing Git repo)
gitx init
gitx status
gitx describe -m "Initial feature"
gitx land --target master

# Native encrypted .env secrets, encrypted fleet sync & ACL-filtered Git export
gitx secret set .env --domain secret:dev
gitx fleet export /tmp/fleet.bundle.json --encrypted --machine workstation-1
gitx git-export /tmp/public-mirror --domains public

# Lock-free workspaces (in-memory, CoW reflink, demand-paged lazy, or OS virtual mount)
gitx ws add agent-1 --lazy
gitx ws mount agent-1 /tmp/agent-1-mnt --backend fuse      # or --backend loopback
gitx ws unmount /tmp/agent-1-mnt

# Tree-sitter AST symbol inspection (Rust, TypeScript, TSX, JavaScript)
gitx symbols src/lib.rs --json
```

### Always-Online Server, Zero-Clone RPCs, Merge Queue & MCP

```bash
# Start the always-online HTTP/JSON + ACL-filtered Git Smart HTTP server
gitx serve --addr 127.0.0.1:7878

# Configure a remote, push-to-create, pull, and run zero-clone server queries
gitx remote add origin http://127.0.0.1:7878/acme/app --token "user=alice;teams=core"
gitx push origin -m "Ship feature"
gitx pull origin
gitx remote grep "fn main"
gitx remote diff master~1 master
gitx remote blame src/lib.rs
gitx remote log --limit 10
gitx remote stats

# Submit and drain the batched agentic merge queue
gitx queue enqueue -m "Agent PR #42"
gitx queue list
gitx queue drain

# Start the zero-disk MCP server (JSON-RPC 2.0 stdio, 13 tools) for AI agents
gitx mcp --in-memory
```

---

## Benchmarks (`cargo run --bin gitx-bench`)

Measured on Linux (250-file repo, debug build):

| Benchmark | Baseline Git | GitX | Improvement |
| --- | --- | --- | --- |
| **32x Parallel Workspaces** | `git worktree add`: 757 ms (8,000 files written) | `LazyWorkspace`: **2.91 ms** (0 files written) / `MemVfs`: **<0.01 ms** | **260x+ faster** |
| **16 Agents Appending to `src/lib.rs`** | `git merge-file`: **15/15 conflicts (100%)** | Tree-sitter AST Merge: **0/15 conflicts (0%)**, 4.86 ms | **100% → 0% conflicts** |
| **Zero-Clone Server `/grep`** | `git clone` + `git grep`: 465.4 ms | Warm `TrigramIndex`: **1.35 ms** (zero clone) | **344x faster** |
| **Zero-Clone Server `/diff`** | `git clone` + `git diff`: 468.0 ms | Server `/diff`: **18.0 ms** (zero clone) | **25.9x faster** |

---

## Core Capabilities

- **Granular Access Control & Native Secrets (`.env`):** File-, directory-, branch/stack-, and change-level permissions via **Visibility Domains** and **Domain-Partitioned Merkle Trees**. Commit `.env` and private sub-packages directly inside public monorepos using envelope encryption (X25519 + ChaCha20-Poly1305) with key epochs, audit logs, and deterministic revocation/rotation—without ever leaking private hashes into public history.
- **Delayed Disclosure / Embargoed Merges:** Merge, build, and distribute security patches privately to maintainers and distros before promoting the diff into the public timeline (`gitx embargo create` / `publish`).
- **Snapshots, Native Stacks & First-Class Conflicts:** Always-live working-copy snapshots (`@`), stable `ChangeId`s, an immutable operation log (`gitx undo`), native stacked diffs with revision interdiffs (`v1..v2`), semantic JSON/TOML + Tree-sitter AST merge (Rust/TS/TSX/JS), and algebraic conflicts stored *inside* changes so partial merges never block progress.
- **Instant, Lock-Free Workspaces (No Git Worktrees):** Multiple workspaces can share `master` without holding branches hostage. Pluggable backends:
  - `mem://` — Zero-disk, zero-OS in-memory VFS for AI agents and fast CI.
  - `cow://` — Copy-on-write / reflink (`FICLONE` / `clonefile`) local checkouts that eliminate disk bloat.
  - `vfs://` — Demand-paged lazy workspaces with Linux FUSE3 (`fuser`) mounts and a cross-platform TCP loopback NFSv3-style virtual mount backend (`gitx ws mount`).
- **Always-Online Server, gRPC & Zero-Clone APIs:** BLAKE3 + FastCDC chunked blob storage (zero packfiles, zero Git LFS), tiered `object_store` backend (InMemory / FS / S3 / R2 / GCS + bounded LRU cache), push-to-create repos, HTTP/JSON and Tonic gRPC (`gitx-proto`) zero-clone RPCs (`diff`, `blame`, `grep`, `log`, `land`, `revert`), derived server indices, batched agentic merge queue, ACID transactional landings, and O(1) atomic reverts.
- **Agent Provenance, Durable "Why" Context & SDKs:** First-class `author` (human) vs. `committer` (agent/model/harness) metadata, sub-commit checkpoints with 3-way human-edit-preserving undo, a durable context store (`gitx why <file>:<line>`) anchored across rebases and squashes, a 13-tool JSON-RPC 2.0 MCP server, pure-Rust WASM bindings (`gitx-wasm`), and the zero-dependency `@gitx/sdk` TypeScript package (`packages/gitx-ts`).
- **Cross-Machine Fleet Sync ("Dropbox for Devs"):** End-to-end encrypted delta sync of `.env` files, configured gitignored overlays, and WIP snapshots across laptops, Linux agent boxes, and cloud sandboxes.
- **Lossless Git Interoperability:** Colocated `.git` mode (`gitx init --colocate`), ACL-filtered Git export (`git fsck` verified), ACL-filtered Git Smart HTTP, and an ACL-filtered Git SSH transport adapter (`git-upload-pack` / `git-receive-pack`) so standard `git` clients see *only* authorized domains.

---

## Workspace Structure

```text
gitx/
├── crates/
│   ├── gitx-core/         # ChangeSet, ChangeId, BLAKE3, FastCDC, VisibilityDomain, ConflictSet, OpLog
│   ├── gitx-crypto/       # Envelope encryption (X25519 + ChaCha20), key epochs, .gitxacl, secret scanner
│   ├── gitx-store/        # SQLite WAL + LZ4 FastCDC CAS (`LocalStore`), `MemoryStore`, `TieredObjectStore` (`object_store`), SQL metadata + Postgres DDL
│   ├── gitx-merge/        # 3-way line merge, JSON/TOML key merge, Tree-sitter AST merge (RS/TS/TSX/JS), interdiffs
│   ├── gitx-vfs/          # `MemVfs`, reflink `CowWorkspace`, demand-paged `LazyWorkspace`, Linux FUSE3 & loopback VFS mounts, encrypted fleet sync
│   ├── gitx-context/      # Sub-commit agent checkpoints & durable `gitx why` store with fuzzy anchor relocation
│   ├── gitx-git-bridge/   # Pure-Rust Git objects, ACL-filtered projection (`git fsck` verified), colocated import, Smart HTTP & SSH transport adapter
│   ├── gitx-proto/        # Protobuf / Tonic gRPC definitions (`proto/gitx.proto`) for client-server & zero-clone RPCs
│   ├── gitx-server/       # Always-online Axum + Tonic gRPC server, zero-clone RPCs, Derived Data Engine, batched merge queue, Git HTTP
│   ├── gitx-sdk/          # Zero-disk `AgentRepo` SDK + 13-tool JSON-RPC 2.0 MCP server
│   ├── gitx-wasm/         # Pure-Rust `wasm32-wasip1` linear-memory ABI bindings over `AgentRepo`, `MemVfs`, merge, ACLs & MCP
│   ├── gitx-cli/          # Single static `gitx` binary (26 commands: local, remote, push/pull, queue, mount, serve, mcp) + E2E tests
│   └── gitx-sim/          # Hermetic crash/OpLog simulator, adversarial ACL fuzzer, 32-agent merge stress test & `gitx-bench`
└── packages/
    └── gitx-ts/           # Zero-dependency `@gitx/sdk` TypeScript SDK (`WasmAgentRepo`, `GitxServerClient`, `GitxMcpClient`)
```

See [packages/gitx-ts/README.md](packages/gitx-ts/README.md) for TypeScript and WASM usage examples.

---

## Roadmap & Implementation Status

| Phase | Milestone | Status |
| --- | --- | --- |
| **Phase 0** | Core BLAKE3+FastCDC storage, snapshots (`@`), OpLog (`undo`), `mem://` & `cow://` workspaces, core CLI | **Implemented** |
| **Phase 1** | First-class conflicts inside ChangeSets, semantic/AST merge, native stacked diffs + interdiffs, colocated `.git` bridge | **Implemented** |
| **Phase 2** | `.gitxacl` Visibility Domains, stable public Merkle projections, envelope-encrypted `.env` secrets, private branches & embargoes | **Implemented** |
| **Phase 3** | Always-online `gitx-server` (HTTP + Tonic gRPC), push-to-create, zero-clone RPCs, derived indices, ACID landing/revert, ACL-filtered Git HTTP & SSH adapter, CLI `remote`/`push`/`pull`/`queue` | **Implemented** |
| **Phase 4** | `vfs://` lazy virtualized mounts (Linux FUSE3 + TCP loopback VFS), in-memory Agent/MCP/WASM/TS SDK (`@gitx/sdk`), encrypted multi-machine fleet sync | **Implemented** |
| **Phase 5** | Sub-commit agent checkpoints, durable `gitx why` context store, batched agentic merge queue, hermetic simulation & fuzzing | **Implemented** |

### Current Scope & Production Hardening

GitX is currently an end-to-end functional implementation with the following remaining production-hardening items:

- **PostgreSQL Runtime Driver:** `gitx-store` includes validated `PostgresConfig` and versioned `POSTGRES_MIGRATIONS` DDL; runtime SQL execution currently runs on SQLite (`rusqlite`) alongside `TieredObjectStore` (`InMemory` / `FS` / S3 / R2 / GCS).
- **Kernel macOS Virtual Mount:** Linux supports kernel FUSE3 (`fuser`); cross-platform/macOS loopback uses a custom TCP NFSv3-style RPC mount rather than kernel RFC 1813 NFSv3/FSKit.
- **Git Interop Backend:** Colocated import and Git Smart HTTP/SSH projections use pure-Rust object writers paired with `git` transport subprocesses rather than `gitoxide` (`gix`).

Read the complete specification and verification plan in **[PLAN.md](PLAN.md)**.
