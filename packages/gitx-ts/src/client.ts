import type {
  BlameResponse,
  BlobResponse,
  CreateRepoResponse,
  DerivedStats,
  DrainMergeQueueRequest,
  DrainMergeQueueResponse,
  EnqueueMergeRequest,
  EnqueueMergeResponse,
  GitxServerClientOptions,
  HealthResponse,
  ListReposResponse,
  PublishEmbargoResponse,
  QueueListResponse,
  RevertResponse,
  SecretFinding,
  ServerCommitRequest,
  ServerCommitResponse,
  ServerDiffResponse,
  ServerGrepResponse,
  ServerLandRequest,
  ServerLandResponse,
  ServerLogResponse,
  ServerRecordContextRequest,
  ServerWhyResponse,
  TreeResponse,
} from "./types.ts";

interface ServerErrorPayload {
  error?: string;
  code?: string;
  findings?: SecretFinding[];
}

export class GitxHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly findings?: SecretFinding[];

  constructor(status: number, code: string, message: string, findings?: SecretFinding[]) {
    super(message);
    this.name = "GitxHttpError";
    this.status = status;
    this.code = code;
    this.findings = findings;
  }
}

const textEncoder = new TextEncoder();

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

function encodeSegment(segment: string): string {
  return encodeURIComponent(segment);
}

/**
 * Typed `fetch`-based HTTP client for `gitx-server`.
 */
export class GitxServerClient {
  readonly baseUrl: string;
  readonly bearerToken?: string;
  readonly user?: string;
  readonly teams?: string[];
  readonly roles?: string[];
  readonly fingerprint?: string;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: GitxServerClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.bearerToken = options.bearerToken;
    this.user = options.user;
    this.teams = options.teams;
    this.roles = options.roles;
    this.fingerprint = options.fingerprint;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  /**
   * Return a cloned client targeting the same server with updated principal/auth headers.
   */
  asPrincipal(
    overrides: Partial<Omit<GitxServerClientOptions, "baseUrl" | "fetch">>,
  ): GitxServerClient {
    return new GitxServerClient({
      baseUrl: this.baseUrl,
      bearerToken: overrides.bearerToken !== undefined ? overrides.bearerToken : this.bearerToken,
      user: overrides.user !== undefined ? overrides.user : this.user,
      teams: overrides.teams !== undefined ? overrides.teams : this.teams,
      roles: overrides.roles !== undefined ? overrides.roles : this.roles,
      fingerprint: overrides.fingerprint !== undefined ? overrides.fingerprint : this.fingerprint,
      fetch: this.fetchImpl,
    });
  }

  private buildHeaders(hasBody: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      accept: "application/json",
    };
    if (hasBody) {
      headers["content-type"] = "application/json";
    }
    if (this.bearerToken) {
      headers["authorization"] = `Bearer ${this.bearerToken}`;
    }
    if (this.user) {
      headers["x-gitx-user"] = this.user;
    }
    if (this.teams && this.teams.length > 0) {
      headers["x-gitx-teams"] = this.teams.join(",");
    }
    if (this.roles && this.roles.length > 0) {
      headers["x-gitx-roles"] = this.roles.join(",");
    }
    if (this.fingerprint) {
      headers["x-gitx-fingerprint"] = this.fingerprint;
    }
    return headers;
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    options?: {
      query?: Record<string, string | number | boolean | undefined>;
      body?: unknown;
    },
  ): Promise<T> {
    const url = new URL(`${this.baseUrl}${path}`);
    if (options?.query) {
      for (const [k, v] of Object.entries(options.query)) {
        if (v !== undefined) {
          url.searchParams.set(k, String(v));
        }
      }
    }

    const hasBody = options?.body !== undefined;
    const response = await this.fetchImpl(url, {
      method,
      headers: this.buildHeaders(hasBody),
      body: hasBody ? JSON.stringify(options.body) : undefined,
    });

    const text = await response.text();
    let parsed: unknown = null;
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }

    if (!response.ok) {
      const errObj = (typeof parsed === "object" && parsed !== null
        ? parsed
        : {}) as ServerErrorPayload;
      throw new GitxHttpError(
        response.status,
        errObj.code ?? `http_${response.status}`,
        errObj.error ?? (typeof parsed === "string" && parsed ? parsed : response.statusText),
        errObj.findings,
      );
    }

    return parsed as T;
  }

  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/health");
  }

  async createRepo(
    owner: string,
    name: string,
    options?: { acl?: string },
  ): Promise<CreateRepoResponse> {
    return this.request<CreateRepoResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}`,
      options?.acl !== undefined ? { body: { acl: options.acl } } : undefined,
    );
  }

  async listRepos(owner?: string): Promise<ListReposResponse> {
    const path = owner ? `/v1/repos/${encodeSegment(owner)}/repos` : "/v1/repos";
    return this.request<ListReposResponse>("GET", path);
  }

  async commit(
    owner: string,
    name: string,
    req: ServerCommitRequest,
  ): Promise<ServerCommitResponse> {
    return this.request<ServerCommitResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/commit`,
      { body: req },
    );
  }

  async getTree(
    owner: string,
    name: string,
    query?: { rev?: string; domain?: string },
  ): Promise<TreeResponse> {
    return this.request<TreeResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/tree`,
      { query },
    );
  }

  /**
   * Read a single file blob at `path` from the ACL-filtered server tree.
   */
  async readBlob(
    owner: string,
    name: string,
    path: string,
    options?: { rev?: string; domain?: string },
  ): Promise<BlobResponse> {
    const normTarget = path.replace(/^\/+/, "").replace(/^\.\//, "");
    const tree = await this.getTree(owner, name, options);
    const entry = tree.files.find((f) => f.path === normTarget);
    if (!entry) {
      throw new GitxHttpError(
        404,
        "not_found",
        `blob '${normTarget}' not found in '${owner}/${name}'`,
      );
    }
    const contentBytes =
      entry.content_base64 !== undefined
        ? base64ToBytes(entry.content_base64)
        : textEncoder.encode(entry.content ?? "");
    return {
      path: entry.path,
      domain: entry.domain,
      size: entry.size,
      blobHash: entry.blob_hash,
      rev: tree.rev,
      content: entry.content ?? null,
      contentBytes,
    };
  }

  async diff(
    owner: string,
    name: string,
    query?: { from?: string; to?: string },
  ): Promise<ServerDiffResponse> {
    return this.request<ServerDiffResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/diff`,
      { query },
    );
  }

  async grep(
    owner: string,
    name: string,
    query: { q: string; rev?: string; case_insensitive?: boolean },
  ): Promise<ServerGrepResponse> {
    return this.request<ServerGrepResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/grep`,
      { query },
    );
  }

  async blame(
    owner: string,
    name: string,
    query: { path: string; rev?: string },
  ): Promise<BlameResponse> {
    return this.request<BlameResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/blame`,
      { query },
    );
  }

  async log(
    owner: string,
    name: string,
    query?: { rev?: string; limit?: number },
  ): Promise<ServerLogResponse> {
    return this.request<ServerLogResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/log`,
      { query },
    );
  }

  async land(owner: string, name: string, req: ServerLandRequest): Promise<ServerLandResponse> {
    return this.request<ServerLandResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/land`,
      { body: req },
    );
  }

  async revert(owner: string, name: string, landSeq: number): Promise<RevertResponse> {
    return this.request<RevertResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/revert/${encodeSegment(String(landSeq))}`,
    );
  }

  async enqueueMerge(
    owner: string,
    name: string,
    req: EnqueueMergeRequest,
  ): Promise<EnqueueMergeResponse> {
    return this.request<EnqueueMergeResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/queue/enqueue`,
      { body: req },
    );
  }

  async listMergeQueue(
    owner: string,
    name: string,
    query?: { target?: string; pending_only?: boolean },
  ): Promise<QueueListResponse> {
    return this.request<QueueListResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/queue`,
      { query },
    );
  }

  async drainMergeQueue(
    owner: string,
    name: string,
    req?: DrainMergeQueueRequest,
  ): Promise<DrainMergeQueueResponse> {
    return this.request<DrainMergeQueueResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/queue/drain`,
      req ? { body: req } : undefined,
    );
  }

  async derivedStats(owner: string, name: string): Promise<DerivedStats> {
    return this.request<DerivedStats>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/derived/stats`,
    );
  }

  /**
   * Record durable "Why" prompt context on the server.
   *
   * If `req.files` is provided, commits those files with `context_prompt`.
   * Otherwise, reads the existing file content at `req.path` and attaches the prompt context
   * cleanly as a commit anchored to that file.
   */
  async recordContext(
    owner: string,
    name: string,
    req: ServerRecordContextRequest,
  ): Promise<ServerCommitResponse> {
    let files = req.files;
    if (!files || Object.keys(files).length === 0) {
      if (!req.path) {
        throw new GitxHttpError(
          400,
          "bad_request",
          "recordContext requires either 'files' or 'path'",
        );
      }
      const blob = await this.readBlob(owner, name, req.path, { rev: req.rev ?? req.target });
      if (blob.content === null) {
        throw new GitxHttpError(
          400,
          "bad_request",
          `cannot attach UTF-8 context anchor to binary file '${req.path}'`,
        );
      }
      files = { [blob.path]: blob.content };
    }

    return this.commit(owner, name, {
      files,
      message: req.message ?? `Record context: ${req.prompt.slice(0, 72)}`,
      target: req.target,
      visibility_domain: req.visibility_domain,
      author_name: req.author_name,
      author_email: req.author_email,
      actor_agent: req.actor_agent,
      context_prompt: req.prompt,
    });
  }

  async why(
    owner: string,
    name: string,
    query: { path: string; line?: number; rev?: string },
  ): Promise<ServerWhyResponse> {
    return this.request<ServerWhyResponse>(
      "GET",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/why`,
      { query },
    );
  }

  async publishEmbargo(
    owner: string,
    name: string,
    advisory: string,
    req?: { target?: string; message?: string },
  ): Promise<PublishEmbargoResponse> {
    return this.request<PublishEmbargoResponse>(
      "POST",
      `/v1/repos/${encodeSegment(owner)}/${encodeSegment(name)}/embargo/${encodeSegment(advisory)}/publish`,
      req ? { body: req } : undefined,
    );
  }
}
