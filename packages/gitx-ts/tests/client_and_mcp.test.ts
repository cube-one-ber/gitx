import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { GitxHttpError, GitxMcpClient, GitxServerClient } from "../src/index.ts";

const GITX_BIN = fileURLToPath(new URL("../../../target/debug/gitx", import.meta.url));

async function getFreePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (!addr || typeof addr === "string") {
        srv.close(() => reject(new Error("failed to obtain ephemeral port")));
        return;
      }
      const port = addr.port;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

async function waitForServerHealth(client: GitxServerClient, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await client.health();
      if (res.status === "ok") {
        return;
      }
    } catch {
      // Server still booting.
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`gitx serve did not become healthy within ${timeoutMs}ms`);
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.killed) {
    return;
  }
  child.kill("SIGTERM");
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 3000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

describe("GitxServerClient (against live `gitx serve`)", () => {
  it("exercises repo lifecycle, zero-clone commits, blob reads, diff, grep, blame, land, revert, merge queue, derived stats, and why", async () => {
    const tmpDir = await mkdtemp(path.join(os.tmpdir(), "gitx-ts-server-"));
    const port = await getFreePort();
    const addr = `127.0.0.1:${port}`;
    const baseUrl = `http://${addr}`;

    const serverProc = spawn(GITX_BIN, ["serve", "--addr", addr, "--data-dir", tmpDir], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderrLog = "";
    serverProc.stderr?.on("data", (chunk: Buffer | string) => {
      stderrLog += chunk.toString();
    });

    const client = new GitxServerClient({
      baseUrl,
      bearerToken: "test-bearer-token-123",
      user: "alice",
      teams: ["core"],
      roles: ["maintainer"],
    });

    try {
      await waitForServerHealth(client);

      // 1. Health + Repo creation & listing
      const health = await client.health();
      assert.equal(health.status, "ok");

      const created = await client.createRepo("acme", "platform");
      assert.equal(created.repo.full_name, "acme/platform");

      const allRepos = await client.listRepos();
      assert.ok(allRepos.repos.some((r) => r.full_name === "acme/platform"));
      const ownerRepos = await client.listRepos("acme");
      assert.equal(ownerRepos.repos.length, 1);

      // 2. Zero-clone server-side commit with context_prompt
      const c1 = await client.commit("acme", "platform", {
        message: "Initial platform scaffold",
        author_name: "Alice",
        author_email: "alice@acme.dev",
        actor_agent: { harness: "ts-sdk", model: "test-model", session_id: "sess-1" },
        files: {
          "package.json": `${JSON.stringify({ name: "platform", dependencies: { core: "1.0.0" } }, null, 2)}\n`,
          "src/service.ts": "export function greet(name: string): string {\n  return `Hello, ${name}`;\n}\n",
        },
        context_prompt: "Scaffold the ACME platform greeting service",
      });
      assert.ok(c1.changeset_id.length >= 64);

      // 3. Tree + readBlob + missing blob 404
      const tree = await client.getTree("acme", "platform");
      assert.equal(tree.files.length, 2);

      const blob = await client.readBlob("acme", "platform", "src/service.ts");
      assert.match(blob.content ?? "", /Hello, \$\{name\}/);

      await assert.rejects(
        () => client.readBlob("acme", "platform", "does-not-exist.ts"),
        (err: unknown) => err instanceof GitxHttpError && err.status === 404,
      );

      // 4. Second commit + diff + grep + blame + log
      const c2 = await client.commit("acme", "platform", {
        message: "Add farewell helper",
        author_name: "Alice",
        author_email: "alice@acme.dev",
        files: {
          "src/service.ts":
            "export function greet(name: string): string {\n  return `Hello, ${name}`;\n}\nexport function farewell(name: string): string {\n  return `Bye, ${name}`;\n}\n",
        },
      });

      const diffRes = await client.diff("acme", "platform", {
        from: c1.changeset_id,
        to: c2.changeset_id,
      });
      assert.match(diffRes.unified_diff, /\+export function farewell/);

      const grepRes = await client.grep("acme", "platform", { q: "farewell" });
      assert.equal(grepRes.matches.length, 1);
      assert.equal(grepRes.matches[0]!.path, "src/service.ts");

      const blameRes = await client.blame("acme", "platform", { path: "src/service.ts" });
      assert.equal(blameRes.lines.length, 6);
      assert.equal(blameRes.lines[0]!.changeset_id, c1.changeset_id);
      assert.equal(blameRes.lines[3]!.changeset_id, c2.changeset_id);

      const logRes = await client.log("acme", "platform", { limit: 10 });
      assert.equal(logRes.commits.length, 2);

      // 4b. Derived AST SymbolIndex query via client.symbols()
      const symRes = await client.symbols("acme", "platform");
      assert.ok(symRes.symbols.some((s) => s.name === "greet"));
      assert.ok(symRes.symbols.some((s) => s.name === "farewell"));

      // 4c. Server-side zero-clone Rebase via client.rebase()
      const featureOnC1 = await client.commit("acme", "platform", {
        message: "Add helper on c1",
        author_name: "Alice",
        author_email: "alice@acme.dev",
        parent: c1.changeset_id,
        update_target: false,
        files: { "src/extra.ts": "export const EXTRA = 42;\n" },
      });
      const rebaseRes = await client.rebase("acme", "platform", {
        changeset_id: featureOnC1.changeset_id,
        onto: "master",
        update_bookmark: "feat-rebased",
      });
      assert.equal(rebaseRes.has_conflicts, false);
      assert.equal(rebaseRes.onto, c2.changeset_id);
      assert.equal(rebaseRes.updated_bookmark, "feat-rebased");

      // 5. Derived stats reflect trigram + path_history + symbol indexing
      const stats = await client.derivedStats("acme", "platform");
      assert.ok(stats.trigram_indexed_trees >= 1);
      assert.ok(stats.path_history_entries >= 1);
      assert.ok(stats.symbol_indexed_trees >= 1);

      // 6. Durable recordContext + why query
      await client.recordContext("acme", "platform", {
        path: "src/service.ts",
        prompt: "Keep greet and farewell side-effect free for edge workers",
      });
      const whyRes = await client.why("acme", "platform", { path: "src/service.ts", line: 1 });
      assert.ok(whyRes.matches.length >= 1);

      // 7. Land + O(1) atomic revert
      const headBeforeLand = (await client.getTree("acme", "platform")).rev!;
      const draftCommit = await client.commit("acme", "platform", {
        message: "Draft feature to land then revert",
        update_target: false,
        parent: headBeforeLand,
        files: { "src/temp.ts": "export const TEMP = true;\n" },
      });
      const landRes = await client.land("acme", "platform", {
        changeset_id: draftCommit.changeset_id,
        target: "master",
      });
      assert.equal(landRes.new_head, draftCommit.changeset_id);

      const revertRes = await client.revert("acme", "platform", landRes.land_seq);
      assert.equal(revertRes.reverted_land_seq, landRes.land_seq);
      assert.equal(revertRes.restored_head, headBeforeLand);

      // 8. Batched lock-free agentic merge queue (enqueueMerge -> listMergeQueue -> drainMergeQueue)
      const qBase = (await client.getTree("acme", "platform")).rev!;
      const q1 = await client.commit("acme", "platform", {
        message: "Agent 1 adds dep-a",
        update_target: false,
        parent: qBase,
        files: {
          "package.json": `${JSON.stringify({ name: "platform", dependencies: { core: "1.0.0", "dep-a": "^1.0.0" } }, null, 2)}\n`,
          "src/a.ts": "export const A = 1;\n",
        },
      });
      const q2 = await client.commit("acme", "platform", {
        message: "Agent 2 adds dep-b",
        update_target: false,
        parent: qBase,
        files: {
          "package.json": `${JSON.stringify({ name: "platform", dependencies: { core: "1.0.0", "dep-b": "^2.0.0" } }, null, 2)}\n`,
          "src/b.ts": "export const B = 2;\n",
        },
      });

      const enq1 = await client.enqueueMerge("acme", "platform", {
        changeset_id: q1.changeset_id,
        target: "master",
      });
      assert.equal(enq1.queue_depth, 1);

      const enq2 = await client.enqueueMerge("acme", "platform", {
        changeset_id: q2.changeset_id,
        target: "master",
      });
      assert.equal(enq2.queue_depth, 2);

      const qList = await client.listMergeQueue("acme", "platform", {
        target: "master",
        pending_only: true,
      });
      assert.equal(qList.pending_count, 2);

      const drained = await client.drainMergeQueue("acme", "platform", { target: "master" });
      assert.equal(drained.landed.length, 2);
      assert.equal(drained.conflicted.length, 0);
      assert.ok(drained.land_seq !== null);

      const mergedPkgBlob = await client.readBlob("acme", "platform", "package.json");
      const mergedPkg = JSON.parse(mergedPkgBlob.content!) as {
        dependencies: Record<string, string>;
      };
      assert.equal(mergedPkg.dependencies["dep-a"], "^1.0.0");
      assert.equal(mergedPkg.dependencies["dep-b"], "^2.0.0");

      // 9. Zero-trust secret rejection returns structured GitxHttpError
      const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
      await assert.rejects(
        () =>
          client.commit("acme", "platform", {
            message: "Accidental secret",
            files: { "src/leak.ts": `export const KEY = "${fakeAwsKey}";\n` },
          }),
        (err: unknown) =>
          err instanceof GitxHttpError &&
          err.status === 400 &&
          err.code === "secret_detected" &&
          (err.findings?.length ?? 0) >= 1,
      );
    } catch (err) {
      throw new Error(
        `GitxServerClient test failed: ${err instanceof Error ? err.message : String(err)}\nServer stderr:\n${stderrLog}`,
        { cause: err },
      );
    } finally {
      await stopChild(serverProc);
      await rm(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("GitxMcpClient (against live `gitx mcp --in-memory` and custom streams)", () => {
  it("spawns `gitx mcp --in-memory` and runs full tool workflow over JSON-RPC 2.0 stdio", async () => {
    const mcp = GitxMcpClient.spawn({
      binPath: GITX_BIN,
      args: ["mcp", "--in-memory"],
    });

    try {
      const init = await mcp.initialize({ name: "gitx-ts-test", version: "0.1.0" });
      assert.equal(init.serverInfo.name, "gitx-mcp");
      assert.equal(init.protocolVersion, "2024-11-05");

      const pong = await mcp.ping();
      assert.deepEqual(pong, {});

      const tools = await mcp.listTools();
      assert.ok(tools.length >= 13);
      assert.ok(tools.some((t) => t.name === "gitx_write_file"));
      assert.ok(tools.some((t) => t.name === "gitx_checkpoint_undo"));

      // Write, grep, diff, commit, land
      const writeRes = await mcp.writeFile({
        path: "src/lib.ts",
        content: "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
      });
      assert.equal(writeRes.secret_warnings.length, 0);

      const filesRes = await mcp.listFiles();
      assert.deepEqual(filesRes.files, ["src/lib.ts"]);

      const grepRes = await mcp.grep({ query: "return a + b" });
      assert.equal(grepRes.matches.length, 1);

      const diffRes = await mcp.diff();
      assert.match(diffRes.diff, /\+export function add/);

      const commitRes = await mcp.commit({
        message: "Add addition helper",
        prompt: "Provide deterministic arithmetic helper",
      });
      assert.ok(commitRes.changeset_id.length >= 64);
      assert.ok(commitRes.context_record_id !== null);

      const landRes = await mcp.land({ target: "master" });
      assert.equal(landRes.land_seq, 1);

      // Why query
      const whyRes = await mcp.why({ workspace: "master", path: "src/lib.ts", line: 2 });
      assert.equal(whyRes.matches.length, 1);

      // Create workspace, save checkpoint, make human edit, surgically undo agent checkpoint
      await mcp.createWorkspace({ name: "agent-ws", base_ref: "master" });
      await mcp.writeFile({
        workspace: "agent-ws",
        path: "src/lib.ts",
        content:
          "export function add(a: number, b: number): number {\n  return a * b; // wrong op\n}\n\nexport function sub(a: number, b: number): number {\n  return a - b;\n}\n",
      });
      const savedCp = await mcp.checkpointSave({
        workspace: "agent-ws",
        prompt_summary: "Broken add + added sub",
      });
      assert.ok(savedCp.checkpoint.id.length > 0);

      // Secret scan inline
      const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
      const scanRes = await mcp.secretScan({ content: `AWS_KEY=${fakeAwsKey}\n`, path: ".env" });
      assert.equal(scanRes.has_secrets, true);

      // Undo checkpoint restores original add()
      const undoRes = await mcp.checkpointUndo({
        workspace: "agent-ws",
        checkpoint_id: savedCp.checkpoint.id,
      });
      assert.deepEqual(undoRes.conflict_paths, []);

      const readBack = await mcp.readFile({ workspace: "agent-ws", path: "src/lib.ts" });
      assert.match(readBack.content, /return a \+ b;/);

      // Delete file
      const delRes = await mcp.deleteFile({ workspace: "agent-ws", path: "src/lib.ts" });
      assert.equal(delRes.deleted, true);
    } finally {
      await mcp.close();
    }
  });

  it("supports wrapping arbitrary Node streams via GitxMcpClient.fromStreams", async () => {
    const serverToClient = new PassThrough();
    const clientToServer = new PassThrough();

    clientToServer.on("data", (chunk: Buffer | string) => {
      const lines = chunk.toString().split("\n").filter(Boolean);
      for (const line of lines) {
        const req = JSON.parse(line) as { id?: number; method: string };
        if (req.id !== undefined && req.method === "ping") {
          serverToClient.write(`${JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { pong: true } })}\n`);
        }
      }
    });

    const mcp = GitxMcpClient.fromStreams(serverToClient, clientToServer);
    try {
      const res = await mcp.ping();
      assert.deepEqual(res, { pong: true });
    } finally {
      await mcp.close();
    }
  });
});
