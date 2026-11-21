import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import type { Interface as ReadlineInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type {
  Checkpoint,
  GrepMatch,
  JsonRpcError,
  JsonRpcRequest,
  JsonRpcResponse,
  McpInitializeResult,
  McpRawToolResult,
  McpToolCallResult,
  McpToolDefinition,
  SecretFinding,
  WhyMatch,
  WorkspaceRef,
} from "./types.ts";

export interface McpSpawnOptions {
  /** Path to the `gitx` executable (defaults to `"gitx"`). */
  binPath?: string;
  /** Arguments passed to the executable (defaults to `["mcp", "--in-memory"]`). */
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export class GitxMcpError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "GitxMcpError";
    this.code = code;
    this.data = data;
  }
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

/**
 * Typed JSON-RPC 2.0 stdio client for `gitx mcp --in-memory` (or any compatible MCP stream pair).
 */
export class GitxMcpClient {
  private readonly input: Readable;
  private readonly output: Writable;
  private readonly child?: ChildProcess;
  private readonly rl: ReadlineInterface;
  private readonly pending: Map<number, PendingRequest>;
  private nextId: number;
  private closed: boolean;
  private stderrOutput: string;

  private constructor(input: Readable, output: Writable, child?: ChildProcess) {
    this.input = input;
    this.output = output;
    this.child = child;
    this.pending = new Map();
    this.nextId = 1;
    this.closed = false;
    this.stderrOutput = "";

    this.rl = createInterface({
      input: this.input,
      crlfDelay: Infinity,
    });

    this.rl.on("line", (line: string) => {
      this.handleLine(line);
    });

    this.rl.on("close", () => {
      this.rejectAll(
        new GitxMcpError(
          -32000,
          this.stderrOutput
            ? `MCP stream closed unexpectedly: ${this.stderrOutput.trim()}`
            : "MCP stream closed",
        ),
      );
    });

    if (this.child) {
      this.child.stderr?.on("data", (chunk: Buffer | string) => {
        this.stderrOutput += chunk.toString();
      });
      this.child.on("error", (err: Error) => {
        this.rejectAll(new GitxMcpError(-32000, `MCP process error: ${err.message}`));
      });
      this.child.on("exit", (code: number | null, signal: NodeJS.Signals | null) => {
        if (this.pending.size > 0) {
          this.rejectAll(
            new GitxMcpError(
              -32000,
              `MCP process exited (code=${String(code)}, signal=${String(signal)}): ${this.stderrOutput.trim()}`,
            ),
          );
        }
      });
    }
  }

  /**
   * Spawn a `gitx mcp --in-memory` child process and connect over stdio.
   */
  static spawn(options?: McpSpawnOptions): GitxMcpClient {
    const binPath = options?.binPath ?? "gitx";
    const args = options?.args ?? ["mcp", "--in-memory"];
    const child = spawn(binPath, args, {
      cwd: options?.cwd,
      env: options?.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (!child.stdout || !child.stdin) {
      child.kill();
      throw new GitxMcpError(-32000, "Failed to open stdio pipes for gitx mcp process");
    }
    return new GitxMcpClient(child.stdout, child.stdin, child);
  }

  /**
   * Wrap an existing readable/writable stream pair speaking newline-delimited JSON-RPC 2.0.
   */
  static fromStreams(input: Readable, output: Writable): GitxMcpClient {
    return new GitxMcpClient(input, output);
  }

  private handleLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }

    let msg: JsonRpcResponse;
    try {
      msg = JSON.parse(trimmed) as JsonRpcResponse;
    } catch {
      return;
    }

    if (typeof msg.id !== "number") {
      return;
    }

    const waiter = this.pending.get(msg.id);
    if (!waiter) {
      return;
    }
    this.pending.delete(msg.id);

    if (msg.error) {
      const rpcErr: JsonRpcError = msg.error;
      waiter.reject(new GitxMcpError(rpcErr.code, rpcErr.message, rpcErr.data));
    } else {
      waiter.resolve(msg.result);
    }
  }

  private rejectAll(err: Error): void {
    for (const waiter of this.pending.values()) {
      waiter.reject(err);
    }
    this.pending.clear();
  }

  request<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    if (this.closed) {
      return Promise.reject(new GitxMcpError(-32000, "MCP client is closed"));
    }
    const id = this.nextId++;
    const payload: JsonRpcRequest = {
      jsonrpc: "2.0",
      id,
      method,
      params,
    };

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      this.output.write(`${JSON.stringify(payload)}\n`, (err?: Error | null) => {
        if (err) {
          this.pending.delete(id);
          reject(new GitxMcpError(-32000, `Failed to write JSON-RPC request: ${err.message}`));
        }
      });
    });
  }

  notify(method: string, params: Record<string, unknown> = {}): void {
    if (this.closed) {
      throw new GitxMcpError(-32000, "MCP client is closed");
    }
    const payload: JsonRpcRequest = {
      jsonrpc: "2.0",
      method,
      params,
    };
    this.output.write(`${JSON.stringify(payload)}\n`);
  }

  async initialize(clientInfo?: { name: string; version: string }): Promise<McpInitializeResult> {
    const result = await this.request<McpInitializeResult>("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: clientInfo ?? { name: "@gitx/sdk", version: "0.1.0" },
    });
    this.notify("notifications/initialized", {});
    return result;
  }

  async ping(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("ping", {});
  }

  async listTools(): Promise<McpToolDefinition[]> {
    const res = await this.request<{ tools: McpToolDefinition[] }>("tools/list", {});
    return res.tools;
  }

  async callTool<T = unknown>(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<McpToolCallResult<T>> {
    const raw = await this.request<McpRawToolResult>("tools/call", {
      name,
      arguments: args,
    });
    const text = raw.content
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("\n");

    let data: unknown = text;
    if (!raw.isError && text.length > 0) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    return {
      raw,
      isError: raw.isError,
      text,
      data: data as T,
    };
  }

  // -------------------------------------------------------------------------
  // Typed Wrappers for Built-In GitX MCP Tools
  // -------------------------------------------------------------------------

  async listFiles(args?: { workspace?: string }): Promise<{ workspace: string; files: string[] }> {
    return this.unwrapTool(await this.callTool("gitx_list_files", args));
  }

  async readFile(args: {
    path: string;
    workspace?: string;
  }): Promise<{ workspace: string; path: string; size: number; content: string }> {
    return this.unwrapTool(await this.callTool("gitx_read_file", args));
  }

  async writeFile(args: {
    path: string;
    content: string;
    workspace?: string;
  }): Promise<{
    workspace: string;
    path: string;
    bytes_written: number;
    secret_warnings: SecretFinding[];
  }> {
    return this.unwrapTool(await this.callTool("gitx_write_file", args));
  }

  async deleteFile(args: {
    path: string;
    workspace?: string;
  }): Promise<{ workspace: string; path: string; deleted: boolean }> {
    return this.unwrapTool(await this.callTool("gitx_delete_file", args));
  }

  async diff(args?: {
    workspace?: string;
    base_ref?: string;
  }): Promise<{ workspace: string; diff: string }> {
    return this.unwrapTool(await this.callTool("gitx_diff", args));
  }

  async grep(args: {
    query: string;
    workspace?: string;
  }): Promise<{ workspace: string; query: string; matches: GrepMatch[] }> {
    return this.unwrapTool(await this.callTool("gitx_grep", args));
  }

  async createWorkspace(args: {
    name: string;
    base_ref?: string;
  }): Promise<{ workspace: WorkspaceRef }> {
    return this.unwrapTool(await this.callTool("gitx_create_workspace", args));
  }

  async commit(args: {
    message: string;
    workspace?: string;
    prompt?: string;
    visibility?: string;
    harness?: string;
    model?: string;
    session_id?: string;
  }): Promise<{
    workspace: string;
    changeset_id: string;
    change_id: string;
    context_record_id: string | null;
    secret_warnings: SecretFinding[];
  }> {
    return this.unwrapTool(await this.callTool("gitx_commit", args));
  }

  async land(args?: {
    workspace?: string;
    target?: string;
  }): Promise<{
    workspace: string;
    target: string;
    land_seq: number;
    new_head: string;
    auto_merged: boolean;
    landed_changes: string[];
    conflict_paths: string[];
  }> {
    return this.unwrapTool(await this.callTool("gitx_land", args));
  }

  async checkpointSave(args?: {
    workspace?: string;
    prompt_summary?: string;
    harness?: string;
    model?: string;
    session_id?: string;
  }): Promise<{ checkpoint: Checkpoint }> {
    return this.unwrapTool(await this.callTool("gitx_checkpoint_save", args));
  }

  async checkpointUndo(args?: {
    workspace?: string;
    checkpoint_id?: string;
  }): Promise<{
    workspace: string;
    reverted_checkpoint_id: string;
    restored_to_checkpoint: string | null;
    clean_paths: string[];
    conflict_paths: string[];
  }> {
    return this.unwrapTool(await this.callTool("gitx_checkpoint_undo", args));
  }

  async why(args: {
    path: string;
    line: number;
    workspace?: string;
  }): Promise<{ workspace: string; path: string; line: number; matches: WhyMatch[] }> {
    return this.unwrapTool(await this.callTool("gitx_why", args));
  }

  async secretScan(args?: {
    workspace?: string;
    path?: string;
    content?: string;
  }): Promise<{ has_secrets: boolean; findings: SecretFinding[] }> {
    return this.unwrapTool(await this.callTool("gitx_secret_scan", args));
  }

  private unwrapTool<T>(res: McpToolCallResult<T>): T {
    if (res.isError) {
      throw new GitxMcpError(-32001, res.text);
    }
    return res.data;
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.rl.close();
    this.output.end();

    if (this.child && this.child.exitCode === null && !this.child.killed) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          this.child?.kill("SIGKILL");
          resolve();
        }, 2000);
        this.child?.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }
}
