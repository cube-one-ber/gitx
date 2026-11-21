// ---------------------------------------------------------------------------
// Shared Core / Provenance / Security Types
// ---------------------------------------------------------------------------

export interface Identity {
  name: string;
  email: string;
  key_fingerprint?: string | null;
}

export type Actor =
  | { Human: Identity }
  | {
      Agent: {
        harness: string;
        model: string;
        session_id: string;
        initiated_by: Identity;
      };
    };

export interface AgentIdentity {
  harness: string;
  model: string;
  sessionId: string;
}

export interface SecretFinding {
  path: string;
  line: number;
  kind: string;
  snippet: string;
}

export interface WorkspaceRef {
  name: string;
  root_path: string | null;
  backend: string;
  head_changeset: string;
  head_change_id: string;
}

export interface GrepMatch {
  path: string;
  line_number: number;
  line: string;
}

export interface TreeDiffEntry {
  path: string;
  status: string;
  old_hash?: string | null;
  new_hash?: string | null;
}

export interface CodeAnchor {
  path: string;
  line_start: number;
  line_end: number;
  symbol: string | null;
  hunk_fingerprint: string;
  snippet: string;
}

export type ContextKind =
  | {
      Prompt: {
        prompt: string;
        model: string;
        harness: string;
        session_id: string;
      };
    }
  | {
      AgentTrace: {
        summary: string;
        tool_calls: string[];
        session_id: string;
      };
    }
  | {
      ReviewThread: {
        reviewer: Identity;
        body: string;
        resolved: boolean;
      };
    }
  | {
      DesignDecision: {
        title: string;
        rationale: string;
      };
    }
  | {
      IssueLink: {
        tracker: string;
        key: string;
        url: string | null;
      };
    };

export interface ContextRecord {
  id: string;
  change_id: string;
  revision: string;
  visibility: string;
  author: Actor;
  kind: ContextKind;
  anchors: CodeAnchor[];
  created_at: string;
}

export interface WhyMatch {
  record: ContextRecord;
  matched_anchor: CodeAnchor;
  relocated_lines: [number, number];
}

export interface Checkpoint {
  id: string;
  workspace: string;
  session_id: string;
  actor: Actor;
  prompt_summary: string;
  tree_hash: string;
  parent_checkpoint: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// WASM AgentRepo Types
// ---------------------------------------------------------------------------

export interface WasmRepoConfig {
  authorName?: string;
  authorEmail?: string;
  principalId?: string;
  teams?: string[];
  roles?: string[];
  fingerprint?: string;
  anonymous?: boolean;
  acl?: string;
  defaultWorkspace?: string;
  agent?: AgentIdentity;
}

export interface WasmLoadOptions extends WasmRepoConfig {
  /**
   * Path, URL, or raw WASM binary bytes for `gitx_wasm.wasm`.
   * When omitted in Node.js, automatically searches `target/wasm32-wasip1/{debug,release}/gitx_wasm.wasm`.
   */
  wasm?: Uint8Array | ArrayBuffer | URL | string;
  /**
   * Force the minimal browser-compatible WASI preview1 shim instead of `node:wasi`.
   */
  useMinimalWasiShim?: boolean;
}

export interface PrincipalConfig {
  id?: string;
  teams?: string[];
  roles?: string[];
  fingerprint?: string;
  anonymous?: boolean;
}

export interface WriteFileResult {
  workspace: string;
  path: string;
  bytesWritten: number;
  secretWarnings: SecretFinding[];
}

export interface ReadFileResult {
  workspace: string;
  path: string;
  size: number;
  encoding: "utf8" | "base64";
  content: string;
}

export interface DeleteFileResult {
  workspace: string;
  path: string;
  deleted: boolean;
}

export interface WasmCommitOptions {
  workspace?: string;
  agent?: AgentIdentity;
  prompt?: string;
  visibility?: string;
}

export interface WasmCommitResult {
  workspace: string;
  changesetId: string;
  changeId: string;
  committer: Actor;
  description: string;
  createdAt: string;
  contextRecord: ContextRecord | null;
  secretWarnings: SecretFinding[];
}

export interface WasmLandResult {
  workspace: string;
  target: string;
  landSeq: number;
  previousHead: string | null;
  newHead: string;
  changesetId: string;
  changeId: string;
  autoMerged: boolean;
  landedChanges: string[];
  conflictPaths: string[];
}

export interface WasmDiffResult {
  workspace: string;
  diff: string;
  entries: TreeDiffEntry[];
}

export interface WasmLogEntry {
  changesetId: string;
  changeId: string;
  publicProjectionHash: string;
  parents: string[];
  author: Identity;
  committer: Actor;
  description: string;
  createdAt: string;
  visibilityDomain: string;
  domains: string[];
  hasConflicts: boolean;
}

export interface WasmLogResult {
  rev: string | null;
  commits: WasmLogEntry[];
}

export interface RecordContextInput {
  workspace?: string;
  rev?: string;
  path?: string;
  lineStart?: number;
  lineEnd?: number;
  kind?: "prompt" | "design_decision" | "agent_trace";
  prompt?: string;
  title?: string;
  rationale?: string;
  summary?: string;
  toolCalls?: string[];
  visibility?: string;
  agent?: AgentIdentity;
}

export interface UndoCheckpointResult {
  workspace: string;
  revertedCheckpoint: Checkpoint;
  restoredToCheckpoint: string | null;
  cleanPaths: string[];
  conflictPaths: string[];
}

export interface SecretScanResult {
  workspace?: string;
  path?: string | null;
  hasSecrets: boolean;
  findings: SecretFinding[];
}

// ---------------------------------------------------------------------------
// GitX HTTP Server Client Types
// ---------------------------------------------------------------------------

export interface GitxServerClientOptions {
  baseUrl: string;
  bearerToken?: string;
  user?: string;
  teams?: string[];
  roles?: string[];
  fingerprint?: string;
  fetch?: typeof globalThis.fetch;
}

export interface HealthResponse {
  status: string;
}

export interface RepoInfo {
  owner: string;
  name: string;
  full_name: string;
  default_branch: string;
  bookmarks: Record<string, string>;
}

export interface CreateRepoResponse {
  repo: RepoInfo;
}

export interface ListReposResponse {
  repos: RepoInfo[];
}

export interface ActorAgentInput {
  harness: string;
  model: string;
  session_id: string;
}

export interface ServerCommitRequest {
  files?: Record<string, string>;
  delete_files?: string[];
  encoding?: "utf8" | "base64";
  message: string;
  author_name?: string;
  author_email?: string;
  actor_agent?: ActorAgentInput;
  target?: string;
  parent?: string;
  update_target?: boolean;
  visibility_domain?: string;
  embargo_advisory?: string;
  embargo_allowed_teams?: string[];
  context_prompt?: string;
}

export interface ServerCommitResponse {
  changeset_id: string;
  change_id: string;
  public_projection_hash: string;
  domains_written: string[];
  target: string | null;
}

export interface TreeFileEntry {
  path: string;
  domain: string;
  size: number;
  blob_hash: string;
  content?: string;
  content_base64?: string;
}

export interface TreeResponse {
  rev: string | null;
  domains: string[];
  files: TreeFileEntry[];
}

export interface BlobResponse {
  path: string;
  domain: string;
  size: number;
  blobHash: string;
  rev: string | null;
  content: string | null;
  contentBytes: Uint8Array;
}

export interface DiffFileEntry {
  path: string;
  domain: string;
  status: string;
  patch: string;
}

export interface ServerDiffResponse {
  from: string | null;
  to: string | null;
  files: DiffFileEntry[];
  unified_diff: string;
}

export interface ServerGrepMatch {
  path: string;
  domain: string;
  line_number: number;
  line: string;
}

export interface ServerGrepResponse {
  query: string;
  rev: string | null;
  matches: ServerGrepMatch[];
}

export interface BlameLine {
  line_number: number;
  content: string;
  changeset_id: string;
  change_id: string;
  author_name: string;
  author_email: string;
  timestamp: string;
  message: string;
}

export interface BlameResponse {
  path: string;
  rev: string;
  lines: BlameLine[];
}

export interface ServerLogEntry {
  changeset_id: string;
  change_id: string;
  public_projection_hash: string;
  parents: string[];
  author_name: string;
  author_email: string;
  message: string;
  created_at: string;
  visibility_domain: string;
  domains: string[];
  has_conflicts: boolean;
}

export interface ServerLogResponse {
  rev: string | null;
  commits: ServerLogEntry[];
}

export interface ServerLandRequest {
  changeset_id: string;
  target?: string;
  expected_head?: string;
}

export interface ServerLandResponse {
  land_seq: number;
  target: string;
  previous_head: string | null;
  new_head: string;
  conflicts: string[];
}

export interface RevertResponse {
  reverted_land_seq: number;
  revert_land_seq: number;
  target: string;
  restored_head: string;
}

export type QueueStatus =
  | { state: "pending" }
  | { state: "landed"; land_seq: number }
  | { state: "conflicted"; conflict_paths: string[] }
  | { state: "rejected"; reason: string };

export interface QueueEntry {
  id: number;
  changeset_id: string;
  change_id: string;
  target: string;
  submitted_by: string;
  enqueued_at: string;
  status: QueueStatus;
}

export interface EnqueueMergeRequest {
  changeset_id: string;
  target?: string;
}

export interface EnqueueMergeResponse {
  entry: QueueEntry;
  queue_depth: number;
}

export interface QueueListResponse {
  target: string;
  pending_count: number;
  entries: QueueEntry[];
}

export interface DrainMergeQueueRequest {
  target?: string;
  max_batch_size?: number;
}

export interface DrainMergeQueueResponse {
  target: string;
  land_seq: number | null;
  previous_head: string | null;
  new_head: string | null;
  landed: QueueEntry[];
  conflicted: QueueEntry[];
  rejected: QueueEntry[];
  resolved_conflicts: string[];
}

export interface DerivedStats {
  trigram_indexed_trees: number;
  trigram_domains: string[];
  trigram_total_postings: number;
  trigram_cache_hits: number;
  trigram_cache_misses: number;
  commit_graph_nodes: number;
  commit_graph_cache_hits: number;
  commit_graph_cache_misses: number;
  path_history_entries: number;
  path_history_cache_hits: number;
  path_history_cache_misses: number;
}

export interface ServerWhyResponse {
  path: string;
  line: number;
  rev: string | null;
  matches: WhyMatch[];
}

export interface ServerRecordContextRequest {
  prompt: string;
  path?: string;
  files?: Record<string, string>;
  message?: string;
  target?: string;
  rev?: string;
  visibility_domain?: string;
  author_name?: string;
  author_email?: string;
  actor_agent?: ActorAgentInput;
}

export interface PublishEmbargoResponse {
  advisory: string;
  target: string;
  changeset_id: string;
  land_seq: number;
  promoted_paths: string[];
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC 2.0 Types
// ---------------------------------------------------------------------------

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: T;
  error?: JsonRpcError;
}

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: {
    tools?: {
      listChanged?: boolean;
    };
  };
  serverInfo: {
    name: string;
    version: string;
  };
}

export interface McpToolContentBlock {
  type: "text";
  text: string;
}

export interface McpRawToolResult {
  content: McpToolContentBlock[];
  isError: boolean;
}

export interface McpToolCallResult<T = unknown> {
  raw: McpRawToolResult;
  isError: boolean;
  text: string;
  data: T;
}
