import type {
  AgentIdentity,
  Checkpoint,
  ContextRecord,
  DeleteFileResult,
  GrepMatch,
  JsonRpcRequest,
  JsonRpcResponse,
  PrincipalConfig,
  ReadFileResult,
  RecordContextInput,
  SecretScanResult,
  UndoCheckpointResult,
  WasmCommitOptions,
  WasmCommitResult,
  WasmDiffResult,
  WasmLandResult,
  WasmLoadOptions,
  WasmLogResult,
  WasmRepoConfig,
  WhyMatch,
  WorkspaceRef,
  WriteFileResult,
} from "./types.ts";

interface GitxWasmExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  _initialize?: () => void;
  gitx_alloc: (len: number) => number;
  gitx_dealloc: (ptr: number, len: number) => void;
  gitx_create_repo: (configPtr: number, configLen: number) => number;
  gitx_drop_repo: (handle: number) => number;
  gitx_invoke: (handle: number, reqPtr: number, reqLen: number) => bigint;
}

interface InvokeEnvelope<T = unknown> {
  ok: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
}

export class GitxWasmError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "GitxWasmError";
    this.code = code;
  }
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: false });

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions === "object" &&
    typeof process.versions.node === "string"
  );
}

async function resolveWasmBytes(
  source?: Uint8Array | ArrayBuffer | URL | string,
): Promise<Uint8Array> {
  if (source instanceof Uint8Array) {
    return source;
  }
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source);
  }

  if (source instanceof URL) {
    if (source.protocol === "file:" && isNodeRuntime()) {
      const fs = await import("node:fs/promises");
      return new Uint8Array(await fs.readFile(source));
    }
    const resp = await fetch(source);
    if (!resp.ok) {
      throw new GitxWasmError(
        "load_error",
        `Failed to fetch WASM module from ${source.toString()}: HTTP ${resp.status}`,
      );
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  if (typeof source === "string") {
    if (source.startsWith("http://") || source.startsWith("https://")) {
      const resp = await fetch(source);
      if (!resp.ok) {
        throw new GitxWasmError(
          "load_error",
          `Failed to fetch WASM module from ${source}: HTTP ${resp.status}`,
        );
      }
      return new Uint8Array(await resp.arrayBuffer());
    }
    if (isNodeRuntime()) {
      const fs = await import("node:fs/promises");
      const target = source.startsWith("file://") ? new URL(source) : source;
      return new Uint8Array(await fs.readFile(target));
    }
    const resp = await fetch(source);
    if (!resp.ok) {
      throw new GitxWasmError(
        "load_error",
        `Failed to fetch WASM module from ${source}: HTTP ${resp.status}`,
      );
    }
    return new Uint8Array(await resp.arrayBuffer());
  }

  if (isNodeRuntime()) {
    const fs = await import("node:fs/promises");
    const candidates = [
      new URL("../../../target/wasm32-wasip1/release/gitx_wasm.wasm", import.meta.url),
      new URL("../../../target/wasm32-wasip1/debug/gitx_wasm.wasm", import.meta.url),
    ];
    for (const candidate of candidates) {
      try {
        return new Uint8Array(await fs.readFile(candidate));
      } catch {
        // Try next candidate path.
      }
    }
    throw new GitxWasmError(
      "load_error",
      "Could not locate gitx_wasm.wasm. Build it with `cargo build -p gitx-wasm --target wasm32-wasip1` or pass `{ wasm: pathOrBytes }`.",
    );
  }

  throw new GitxWasmError(
    "load_error",
    "Browser environments must pass `{ wasm: urlOrBytes }` to WasmAgentRepo.load().",
  );
}

/**
 * Minimal browser-compatible `wasi_snapshot_preview1` import shim supporting
 * Rust std + chrono + getrandom + panic stderr output inside `WebAssembly.instantiate`.
 */
export function createMinimalWasiImports(memoryRef: {
  memory: WebAssembly.Memory | null;
}): WebAssembly.Imports {
  const ERRNO_SUCCESS = 0;
  const ERRNO_BADF = 8;
  const ERRNO_NOSYS = 52;

  const getView = (): DataView => {
    if (!memoryRef.memory) {
      throw new Error("WASM memory not yet bound to WASI shim");
    }
    return new DataView(memoryRef.memory.buffer);
  };

  const getBytes = (): Uint8Array => {
    if (!memoryRef.memory) {
      throw new Error("WASM memory not yet bound to WASI shim");
    }
    return new Uint8Array(memoryRef.memory.buffer);
  };

  return {
    wasi_snapshot_preview1: {
      args_sizes_get(argcPtr: number, argvBufSizePtr: number): number {
        const view = getView();
        view.setUint32(argcPtr, 0, true);
        view.setUint32(argvBufSizePtr, 0, true);
        return ERRNO_SUCCESS;
      },
      args_get(_argvPtr: number, _argvBufPtr: number): number {
        return ERRNO_SUCCESS;
      },
      environ_sizes_get(countPtr: number, bufSizePtr: number): number {
        const view = getView();
        view.setUint32(countPtr, 0, true);
        view.setUint32(bufSizePtr, 0, true);
        return ERRNO_SUCCESS;
      },
      environ_get(_environPtr: number, _environBufPtr: number): number {
        return ERRNO_SUCCESS;
      },
      clock_res_get(_clockId: number, outPtr: number): number {
        const view = getView();
        view.setBigUint64(outPtr, 1_000_000n, true);
        return ERRNO_SUCCESS;
      },
      clock_time_get(_clockId: number, _precision: bigint, outPtr: number): number {
        const view = getView();
        const nowNs = BigInt(Date.now()) * 1_000_000n;
        view.setBigUint64(outPtr, nowNs, true);
        return ERRNO_SUCCESS;
      },
      random_get(bufPtr: number, bufLen: number): number {
        const bytes = getBytes().subarray(bufPtr, bufPtr + bufLen);
        const maxChunk = 65_536;
        for (let offset = 0; offset < bufLen; offset += maxChunk) {
          const end = Math.min(offset + maxChunk, bufLen);
          globalThis.crypto.getRandomValues(bytes.subarray(offset, end));
        }
        return ERRNO_SUCCESS;
      },
      fd_write(fd: number, iovsPtr: number, iovsLen: number, nwrittenPtr: number): number {
        const view = getView();
        const mem = getBytes();
        let total = 0;
        let stderrChunk = "";
        for (let i = 0; i < iovsLen; i += 1) {
          const ptr = view.getUint32(iovsPtr + i * 8, true);
          const len = view.getUint32(iovsPtr + i * 8 + 4, true);
          total += len;
          if (fd === 2 && len > 0) {
            stderrChunk += textDecoder.decode(mem.subarray(ptr, ptr + len));
          }
        }
        if (stderrChunk.length > 0 && typeof console !== "undefined") {
          console.error(stderrChunk);
        }
        view.setUint32(nwrittenPtr, total, true);
        return ERRNO_SUCCESS;
      },
      fd_read(): number {
        return ERRNO_BADF;
      },
      fd_close(): number {
        return ERRNO_SUCCESS;
      },
      fd_seek(): number {
        return ERRNO_BADF;
      },
      fd_fdstat_get(): number {
        return ERRNO_BADF;
      },
      fd_filestat_get(): number {
        return ERRNO_BADF;
      },
      fd_prestat_get(): number {
        return ERRNO_BADF;
      },
      fd_prestat_dir_name(): number {
        return ERRNO_BADF;
      },
      path_open(): number {
        return ERRNO_NOSYS;
      },
      poll_oneoff(): number {
        return ERRNO_NOSYS;
      },
      sched_yield(): number {
        return ERRNO_SUCCESS;
      },
      proc_exit(code: number): never {
        throw new GitxWasmError("wasi_exit", `WASM module exited with code ${code}`);
      },
    },
  };
}

/**
 * Loaded WebAssembly instance of `gitx_wasm.wasm`.
 * Can host any number of isolated in-memory [`WasmAgentRepo`] instances.
 */
export class WasmGitxModule {
  readonly exports: GitxWasmExports;

  private constructor(exports: GitxWasmExports) {
    this.exports = exports;
  }

  static async load(options?: {
    wasm?: Uint8Array | ArrayBuffer | URL | string;
    useMinimalWasiShim?: boolean;
  }): Promise<WasmGitxModule> {
    const bytes = await resolveWasmBytes(options?.wasm);
    const compiled = await WebAssembly.compile(bytes);

    if (!options?.useMinimalWasiShim && isNodeRuntime()) {
      const { WASI } = await import("node:wasi");
      const wasi = new WASI({
        version: "preview1",
        args: [],
        env: {},
      });
      const instance = await WebAssembly.instantiate(
        compiled,
        wasi.getImportObject() as WebAssembly.Imports,
      );
      if (typeof instance.exports._initialize === "function") {
        wasi.initialize(instance);
      }
      return new WasmGitxModule(instance.exports as GitxWasmExports);
    }

    const memoryRef: { memory: WebAssembly.Memory | null } = { memory: null };
    const imports = createMinimalWasiImports(memoryRef);
    const instance = await WebAssembly.instantiate(compiled, imports);
    const exports = instance.exports as GitxWasmExports;
    memoryRef.memory = exports.memory;
    if (typeof exports._initialize === "function") {
      exports._initialize();
    }
    return new WasmGitxModule(exports);
  }

  createRepo(config?: WasmRepoConfig): WasmAgentRepo {
    const cfgBytes = config ? textEncoder.encode(JSON.stringify(config)) : new Uint8Array(0);
    let ptr = 0;
    try {
      if (cfgBytes.length > 0) {
        ptr = this.exports.gitx_alloc(cfgBytes.length);
        new Uint8Array(this.exports.memory.buffer, ptr, cfgBytes.length).set(cfgBytes);
      }
      const handle = this.exports.gitx_create_repo(ptr, cfgBytes.length);
      if (handle === 0) {
        throw new GitxWasmError("init_error", "gitx_create_repo failed to initialize repository");
      }
      return new WasmAgentRepo(this, handle);
    } finally {
      if (ptr !== 0 && cfgBytes.length > 0) {
        this.exports.gitx_dealloc(ptr, cfgBytes.length);
      }
    }
  }

  invokeRaw<T>(handle: number, request: Record<string, unknown>): T {
    const reqBytes = textEncoder.encode(JSON.stringify(request));
    let reqPtr = 0;
    try {
      reqPtr = this.exports.gitx_alloc(reqBytes.length);
      new Uint8Array(this.exports.memory.buffer, reqPtr, reqBytes.length).set(reqBytes);

      const packed = this.exports.gitx_invoke(handle, reqPtr, reqBytes.length);
      const respPtr = Number((packed >> 32n) & 0xffff_ffffn);
      const respLen = Number(packed & 0xffff_ffffn);
      if (respPtr === 0 || respLen === 0) {
        throw new GitxWasmError("abi_error", "gitx_invoke returned an empty buffer");
      }

      let rawJson: string;
      try {
        const slice = new Uint8Array(this.exports.memory.buffer, respPtr, respLen);
        rawJson = textDecoder.decode(slice);
      } finally {
        this.exports.gitx_dealloc(respPtr, respLen);
      }

      const envelope = JSON.parse(rawJson) as InvokeEnvelope<T>;
      if (!envelope.ok) {
        throw new GitxWasmError(
          envelope.error?.code ?? "unknown_error",
          envelope.error?.message ?? "Unknown WASM invocation error",
        );
      }
      return envelope.data as T;
    } finally {
      if (reqPtr !== 0 && reqBytes.length > 0) {
        this.exports.gitx_dealloc(reqPtr, reqBytes.length);
      }
    }
  }

  dropRepo(handle: number): boolean {
    return this.exports.gitx_drop_repo(handle) === 1;
  }
}

/**
 * Zero-disk in-memory GitX repository executing inside WebAssembly (`gitx_wasm.wasm`).
 */
export class WasmAgentRepo {
  readonly module: WasmGitxModule;
  readonly handle: number;
  private disposed: boolean;

  constructor(module: WasmGitxModule, handle: number) {
    this.module = module;
    this.handle = handle;
    this.disposed = false;
  }

  /**
   * Load `gitx_wasm.wasm` and create a fresh in-memory [`WasmAgentRepo`] in one call.
   */
  static async load(options?: WasmLoadOptions): Promise<WasmAgentRepo> {
    const mod = await WasmGitxModule.load({
      wasm: options?.wasm,
      useMinimalWasiShim: options?.useMinimalWasiShim,
    });
    return mod.createRepo(options);
  }

  private ensureActive(): void {
    if (this.disposed) {
      throw new GitxWasmError("disposed", "WasmAgentRepo has already been disposed");
    }
  }

  private invoke<T>(payload: Record<string, unknown>): T {
    this.ensureActive();
    return this.module.invokeRaw<T>(this.handle, payload);
  }

  createWorkspace(name: string, baseRef = "master"): WorkspaceRef {
    const res = this.invoke<{ workspace: WorkspaceRef }>({
      op: "createWorkspace",
      name,
      baseRef,
    });
    return res.workspace;
  }

  listWorkspaces(): WorkspaceRef[] {
    const res = this.invoke<{ workspaces: WorkspaceRef[] }>({
      op: "listWorkspaces",
    });
    return res.workspaces;
  }

  writeFile(
    path: string,
    content: string | Uint8Array,
    options?: { workspace?: string },
  ): WriteFileResult {
    const isBinary = content instanceof Uint8Array;
    return this.invoke<WriteFileResult>({
      op: "writeFile",
      workspace: options?.workspace,
      path,
      content: isBinary ? bytesToBase64(content) : content,
      encoding: isBinary ? "base64" : "utf8",
    });
  }

  readFile(path: string, options?: { workspace?: string; rev?: string }): string {
    const res = this.invoke<ReadFileResult>({
      op: "readFile",
      workspace: options?.workspace,
      rev: options?.rev,
      path,
      encoding: "utf8",
    });
    if (res.encoding === "base64") {
      return textDecoder.decode(base64ToBytes(res.content));
    }
    return res.content;
  }

  readFileBytes(path: string, options?: { workspace?: string; rev?: string }): Uint8Array {
    const res = this.invoke<ReadFileResult>({
      op: "readFile",
      workspace: options?.workspace,
      rev: options?.rev,
      path,
      encoding: "base64",
    });
    return base64ToBytes(res.content);
  }

  deleteFile(path: string, options?: { workspace?: string }): DeleteFileResult {
    return this.invoke<DeleteFileResult>({
      op: "deleteFile",
      workspace: options?.workspace,
      path,
    });
  }

  listFiles(options?: { workspace?: string; rev?: string }): string[] {
    const res = this.invoke<{ files: string[] }>({
      op: "listFiles",
      workspace: options?.workspace,
      rev: options?.rev,
    });
    return res.files;
  }

  commit(message: string, options?: WasmCommitOptions): WasmCommitResult {
    return this.invoke<WasmCommitResult>({
      op: "commit",
      workspace: options?.workspace,
      message,
      agent: options?.agent,
      prompt: options?.prompt,
      visibility: options?.visibility,
    });
  }

  land(options?: { workspace?: string; target?: string }): WasmLandResult {
    return this.invoke<WasmLandResult>({
      op: "land",
      workspace: options?.workspace,
      target: options?.target,
    });
  }

  diff(options?: { workspace?: string; baseRef?: string }): WasmDiffResult {
    return this.invoke<WasmDiffResult>({
      op: "diff",
      workspace: options?.workspace,
      baseRef: options?.baseRef,
    });
  }

  grep(query: string, options?: { workspace?: string }): GrepMatch[] {
    const res = this.invoke<{ matches: GrepMatch[] }>({
      op: "grep",
      workspace: options?.workspace,
      query,
    });
    return res.matches;
  }

  log(options?: { workspace?: string; rev?: string; limit?: number }): WasmLogResult {
    return this.invoke<WasmLogResult>({
      op: "log",
      workspace: options?.workspace,
      rev: options?.rev,
      limit: options?.limit,
    });
  }

  recordContext(input: RecordContextInput): ContextRecord {
    const res = this.invoke<{ record: ContextRecord }>({
      op: "recordContext",
      ...input,
    });
    return res.record;
  }

  why(path: string, line: number, options?: { workspace?: string; rev?: string }): WhyMatch[] {
    const res = this.invoke<{ matches: WhyMatch[] }>({
      op: "why",
      workspace: options?.workspace,
      rev: options?.rev,
      path,
      line,
    });
    return res.matches;
  }

  checkpoint(
    promptSummary = "",
    options?: { workspace?: string; agent?: AgentIdentity },
  ): Checkpoint {
    const res = this.invoke<{ checkpoint: Checkpoint }>({
      op: "checkpoint",
      workspace: options?.workspace,
      promptSummary,
      agent: options?.agent,
    });
    return res.checkpoint;
  }

  listCheckpoints(options?: { workspace?: string; limit?: number }): Checkpoint[] {
    const res = this.invoke<{ checkpoints: Checkpoint[] }>({
      op: "listCheckpoints",
      workspace: options?.workspace,
      limit: options?.limit,
    });
    return res.checkpoints;
  }

  undoCheckpoint(options?: { workspace?: string; checkpointId?: string }): UndoCheckpointResult {
    return this.invoke<UndoCheckpointResult>({
      op: "undoCheckpoint",
      workspace: options?.workspace,
      checkpointId: options?.checkpointId,
    });
  }

  scanSecrets(options?: { workspace?: string; path?: string; content?: string }): SecretScanResult {
    return this.invoke<SecretScanResult>({
      op: "scanSecrets",
      workspace: options?.workspace,
      path: options?.path,
      content: options?.content,
    });
  }

  setAcl(policy: string): void {
    this.invoke({ op: "setAcl", policy });
  }

  setPrincipal(principal: PrincipalConfig): void {
    this.invoke({ op: "setPrincipal", ...principal });
  }

  mcpCall<T = unknown>(request: JsonRpcRequest | string): JsonRpcResponse<T> | null {
    const res = this.invoke<{ response: JsonRpcResponse<T> | null }>({
      op: "mcpCall",
      request,
    });
    return res.response;
  }

  dispose(): void {
    if (!this.disposed) {
      this.module.dropRepo(this.handle);
      this.disposed = true;
    }
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}
