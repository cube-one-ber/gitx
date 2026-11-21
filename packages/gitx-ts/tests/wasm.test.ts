import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { GitxWasmError, WasmAgentRepo, WasmGitxModule } from "../src/index.ts";

const WASM_PATH = fileURLToPath(
  new URL("../../../target/wasm32-wasip1/debug/gitx_wasm.wasm", import.meta.url),
);

describe("WasmAgentRepo (real gitx_wasm.wasm)", () => {
  it("runs parallel in-memory workspaces, semantic JSON merge, diff, grep, log, context/why, and checkpoint undo", async () => {
    const repo = await WasmAgentRepo.load({
      wasm: WASM_PATH,
      authorName: "Alice Dev",
      authorEmail: "alice@example.com",
      principalId: "alice",
      teams: ["core"],
    });

    try {
      // Seed shared package.json + source file + binary file on default workspace and land onto master
      const basePkg = `${JSON.stringify(
        {
          name: "wasm-sdk-demo",
          version: "1.0.0",
          dependencies: { "core-lib": "^1.0.0" },
        },
        null,
        2,
      )}\n`;
      const w1 = repo.writeFile("package.json", basePkg);
      assert.equal(w1.secretWarnings.length, 0);

      const baseSrc = [
        "export function alpha(): number {",
        "  return 1;",
        "}",
        "",
        "export function beta(): number {",
        "  return 2;",
        "}",
        "",
      ].join("\n");
      repo.writeFile("src/app.ts", baseSrc);

      const binaryBytes = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff]);
      repo.writeFile("assets/logo.bin", binaryBytes);

      const seedCommit = repo.commit("Seed repository", {
        agent: { harness: "ts-test", model: "seed-v1", sessionId: "sess-seed" },
      });
      assert.ok(seedCommit.changesetId.length >= 64);

      const seedLand = repo.land({ target: "master" });
      assert.equal(seedLand.landSeq, 1);
      assert.equal(seedLand.autoMerged, false);

      // Verify binary round-trip
      const roundTrippedBytes = repo.readFileBytes("assets/logo.bin", { rev: "master" });
      assert.deepEqual(roundTrippedBytes, binaryBytes);

      // Fork 3 concurrent in-memory workspaces off master
      const specs = [
        { ws: "agent-auth", file: "src/auth.ts", dep: "oauth-kit", ver: "^2.1.0", prompt: "Add OAuth2 session middleware" },
        { ws: "agent-billing", file: "src/billing.ts", dep: "stripe-lite", ver: "^3.0.0", prompt: "Implement invoice billing handler" },
        { ws: "agent-metrics", file: "src/metrics.ts", dep: "otel-wasm", ver: "^0.9.0", prompt: "Emit OpenTelemetry request counters" },
      ];

      for (const spec of specs) {
        const wsRef = repo.createWorkspace(spec.ws, "master");
        assert.equal(wsRef.name, spec.ws);
      }

      const workspaces = repo.listWorkspaces();
      assert.equal(workspaces.length, 4); // default + 3 agents

      for (const spec of specs) {
        const code = `export const MODULE = "${spec.dep}";\nexport function run(): string {\n  return MODULE;\n}\n`;
        repo.writeFile(spec.file, code, { workspace: spec.ws });

        const pkg = JSON.parse(repo.readFile("package.json", { workspace: spec.ws })) as {
          dependencies: Record<string, string>;
        };
        pkg.dependencies[spec.dep] = spec.ver;
        repo.writeFile("package.json", `${JSON.stringify(pkg, null, 2)}\n`, { workspace: spec.ws });

        const diffRes = repo.diff({ workspace: spec.ws });
        assert.match(diffRes.diff, new RegExp(spec.dep));
        assert.ok(diffRes.entries.length >= 2);

        const grepHits = repo.grep(spec.dep, { workspace: spec.ws });
        assert.ok(grepHits.length >= 2);

        const commitRes = repo.commit(`Implement ${spec.dep}`, {
          workspace: spec.ws,
          prompt: spec.prompt,
          agent: { harness: "ts-test", model: "agent-v1", sessionId: `sess-${spec.ws}` },
        });
        assert.ok(commitRes.contextRecord !== null);
      }

      // Land all 3 concurrent agent workspaces onto master (2nd and 3rd semantically auto-merge package.json!)
      let lastSeq = seedLand.landSeq;
      for (let i = 0; i < specs.length; i += 1) {
        const landRes = repo.land({ workspace: specs[i]!.ws, target: "master" });
        assert.equal(landRes.landSeq, lastSeq + 1);
        if (i > 0) {
          assert.equal(landRes.autoMerged, true);
        }
        assert.deepEqual(landRes.conflictPaths, []);
        lastSeq = landRes.landSeq;
      }

      // Verify all 3 dependencies + files exist on master
      const mergedPkg = JSON.parse(repo.readFile("package.json", { rev: "master" })) as {
        dependencies: Record<string, string>;
      };
      assert.equal(mergedPkg.dependencies["core-lib"], "^1.0.0");
      assert.equal(mergedPkg.dependencies["oauth-kit"], "^2.1.0");
      assert.equal(mergedPkg.dependencies["stripe-lite"], "^3.0.0");
      assert.equal(mergedPkg.dependencies["otel-wasm"], "^0.9.0");

      const masterFiles = repo.listFiles({ rev: "master" });
      assert.ok(masterFiles.includes("src/auth.ts"));
      assert.ok(masterFiles.includes("src/billing.ts"));
      assert.ok(masterFiles.includes("src/metrics.ts"));

      // Verify log returns full ancestry
      const logRes = repo.log({ rev: "master", limit: 20 });
      assert.ok(logRes.commits.length >= 4);

      // Query commit-attached "why" context
      const whyAuth = repo.why("src/auth.ts", 2, { rev: "master" });
      assert.ok(whyAuth.length >= 1);
      assert.ok("Prompt" in whyAuth[0]!.record.kind);
      assert.equal(whyAuth[0]!.record.kind.Prompt.prompt, "Add OAuth2 session middleware");

      // Record an explicit design-decision context record and query via why
      const explicitCtx = repo.recordContext({
        rev: "master",
        path: "src/app.ts",
        lineStart: 1,
        lineEnd: 3,
        kind: "design_decision",
        title: "Pure alpha function",
        rationale: "Keeps WASM cold-start deterministic",
      });
      assert.ok(explicitCtx.id.length > 0);
      const whyApp = repo.why("src/app.ts", 2, { rev: "master" });
      assert.ok(whyApp.length >= 1);
      assert.ok("DesignDecision" in whyApp[0]!.record.kind);
      assert.equal(whyApp[0]!.record.kind.DesignDecision.title, "Pure alpha function");

      // Test deleteFile in a scratch workspace
      repo.createWorkspace("ws-delete", "master");
      repo.deleteFile("assets/logo.bin", { workspace: "ws-delete" });
      assert.ok(!repo.listFiles({ workspace: "ws-delete" }).includes("assets/logo.bin"));

      // Test surgical checkpoint undo preserving concurrent non-overlapping human edits
      repo.createWorkspace("ws-undo", "master");
      const afterAgentEdit = [
        "export function alpha(): number {",
        "  return 999; // bad agent change",
        "}",
        "",
        "export function beta(): number {",
        "  return 2;",
        "}",
        "",
      ].join("\n");
      repo.writeFile("src/app.ts", afterAgentEdit, { workspace: "ws-undo" });
      const cp = repo.checkpoint("Agent changed alpha return value", { workspace: "ws-undo" });
      assert.ok(cp.id.length > 0);
      assert.equal(repo.listCheckpoints({ workspace: "ws-undo" }).length, 1);

      // Human concurrently modifies beta() without touching alpha()
      const afterHumanEdit = [
        "export function alpha(): number {",
        "  return 999; // bad agent change",
        "}",
        "",
        "export function beta(): number {",
        "  return 42; // human fix",
        "}",
        "",
      ].join("\n");
      repo.writeFile("src/app.ts", afterHumanEdit, { workspace: "ws-undo" });

      const undoRes = repo.undoCheckpoint({ workspace: "ws-undo", checkpointId: cp.id });
      assert.deepEqual(undoRes.conflictPaths, []);
      assert.ok(undoRes.cleanPaths.includes("src/app.ts"));

      const finalApp = repo.readFile("src/app.ts", { workspace: "ws-undo" });
      assert.match(finalApp, /return 1;/);
      assert.match(finalApp, /return 42; \/\/ human fix/);
      assert.doesNotMatch(finalApp, /return 999/);
    } finally {
      repo.dispose();
    }
  });

  it("enforces secret scanning, ACL isolation, and direct MCP JSON-RPC dispatch", async () => {
    const aclPolicy = "secrets/** -> team:security allow=team:security\n";

    const repo = await WasmAgentRepo.load({
      wasm: WASM_PATH,
      authorName: "Sec Admin",
      authorEmail: "sec@example.com",
      principalId: "sec-admin",
      teams: ["security"],
      acl: aclPolicy,
    });

    try {
      // Zero-trust secret scanning catches leaked credentials immediately on writeFile + scanSecrets
      const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
      const writeRes = repo.writeFile("src/config.ts", `export const KEY = "${fakeAwsKey}";\n`);
      assert.ok(writeRes.secretWarnings.length >= 1);

      const scanRes = repo.scanSecrets({ path: "src/config.ts" });
      assert.equal(scanRes.hasSecrets, true);
      assert.ok(scanRes.findings.length >= 1);

      // Write clean public file + restricted team:security file and land to master
      repo.writeFile("src/config.ts", 'export const KEY = process.env.API_KEY ?? "";\n');
      repo.writeFile("secrets/prod.env", "DB_PASS=classified-value\n");
      repo.commit("Add public config and security secret");
      repo.land({ target: "master" });

      assert.equal(repo.readFile("secrets/prod.env", { rev: "master" }), "DB_PASS=classified-value\n");

      // Direct MCP JSON-RPC 2.0 dispatch inside WASM
      const initResp = repo.mcpCall<{ protocolVersion: string; serverInfo: { name: string } }>({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      });
      assert.equal(initResp?.result?.serverInfo.name, "gitx-mcp");

      const listResp = repo.mcpCall<{ tools: Array<{ name: string }> }>({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      });
      assert.ok((listResp?.result?.tools.length ?? 0) >= 13);

      // Switch principal to an external user without team:security membership -> ACL must block
      repo.setPrincipal({ id: "guest", teams: [] });
      assert.throws(
        () => repo.readFile("secrets/prod.env", { rev: "master" }),
        (err: unknown) => err instanceof GitxWasmError && err.code === "access_denied",
      );
      assert.throws(
        () => repo.writeFile("secrets/prod.env", "tampered\n"),
        (err: unknown) => err instanceof GitxWasmError && err.code === "access_denied",
      );

      // Public files remain readable to guest
      assert.match(repo.readFile("src/config.ts", { rev: "master" }), /process\.env\.API_KEY/);
    } finally {
      repo.dispose();
    }
  });

  it("works identically using the browser-compatible minimal WASI shim", async () => {
    const mod = await WasmGitxModule.load({
      wasm: WASM_PATH,
      useMinimalWasiShim: true,
    });
    const repo = mod.createRepo({
      authorName: "Browser Agent",
      authorEmail: "browser@gitx.local",
      principalId: "browser-agent",
    });

    try {
      repo.writeFile("hello.txt", "hello from minimal WASI shim\n");
      const commit = repo.commit("Browser commit", { prompt: "Test minimal WASI shim" });
      assert.ok(commit.changesetId.length >= 64);
      const land = repo.land({ target: "master" });
      assert.equal(land.landSeq, 1);
      assert.equal(repo.readFile("hello.txt", { rev: "master" }), "hello from minimal WASI shim\n");
      const whyMatches = repo.why("hello.txt", 1, { rev: "master" });
      assert.equal(whyMatches.length, 1);
    } finally {
      repo.dispose();
    }
  });
});
