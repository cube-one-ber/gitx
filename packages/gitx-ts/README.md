# `@gitx/sdk` — GitX TypeScript SDK

Zero-dependency TypeScript SDK for **GitX** providing three composable transports:

1. **`WasmAgentRepo`** (`src/wasm.ts`) — Loads the pure-Rust `gitx_wasm.wasm` binary via Node's `node:wasi` (or a minimal browser WASI shim) for zero-disk, lock-free in-memory workspaces, 3-way semantic merges, ACL enforcement, secret scanning, durable "Why" context, surgical checkpoint undo, and direct MCP JSON-RPC dispatch.
2. **`GitxServerClient`** (`src/client.ts`) — Typed `fetch`-based HTTP client for `gitx-server` supporting bearer tokens, principal headers, zero-clone commits, server-side `rebase`, AST `symbols`, ACID transactional landing, O(1) revert, batched merge queues, derived index stats, grep, blame, diff, and `why`.
3. **`GitxMcpClient`** (`src/mcp.ts`) — Typed JSON-RPC 2.0 stdio client that spawns `gitx mcp --in-memory` (or wraps arbitrary readable/writable streams) and invokes GitX MCP tools.

## Quick Start

### In-Memory WASM Repository

```ts
import { WasmAgentRepo } from "@gitx/sdk";

const repo = await WasmAgentRepo.load({
  authorName: "Alice",
  authorEmail: "alice@example.com",
  principalId: "alice",
  teams: ["core"],
});

repo.writeFile("package.json", JSON.stringify({ name: "demo", dependencies: { a: "1.0.0" } }, null, 2) + "\n");
repo.commit("Seed package.json");
repo.land({ target: "master" });

repo.createWorkspace("agent-1", "master");
repo.createWorkspace("agent-2", "master");

repo.dispose();
```

### HTTP Server Client

```ts
import { GitxServerClient } from "@gitx/sdk";

const client = new GitxServerClient({
  baseUrl: "http://127.0.0.1:8080",
  user: "alice",
  teams: ["core"],
  bearerToken: process.env.GITX_TOKEN,
});

await client.createRepo("acme", "service");
await client.commit("acme", "service", {
  message: "Initial commit",
  files: { "README.md": "# Hello GitX\n" },
  context_prompt: "Bootstrap service repository",
});
```

### MCP Stdio Client

```ts
import { GitxMcpClient } from "@gitx/sdk";

const mcp = GitxMcpClient.spawn({ binPath: "gitx" });
await mcp.initialize();
const tools = await mcp.listTools();
await mcp.writeFile({ path: "hello.txt", content: "hi from mcp\n" });
await mcp.close();
```

## Running Tests

Build the WASM artifact and native `gitx` CLI binary, then run the Node.js test suite:

```bash
cargo build -p gitx-wasm --target wasm32-wasip1
cargo build -p gitx-cli
node --test packages/gitx-ts/tests/*.test.ts
```
