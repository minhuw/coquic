import "server-only";

import type { CloudReaderConfig } from "./cloud-config";

export type D1Scalar = string | number | boolean | null;
export type D1Row = Readonly<Record<string, unknown>>;
export type D1ResultMeta = Readonly<Record<string, unknown>>;

export interface D1ResultSet {
  readonly results: readonly D1Row[];
  readonly meta: D1ResultMeta;
}

export interface D1QueryResponse {
  readonly result: readonly D1ResultSet[];
}

export type D1ErrorCode =
  | "invalid-request"
  | "unauthorized"
  | "rate-limited"
  | "server-error"
  | "http-error"
  | "network-error"
  | "timeout"
  | "provider-error"
  | "malformed"
  | "response-too-large"
  | "result-set-limit"
  | "row-limit";

const ERROR_MESSAGES: Record<D1ErrorCode, string> = {
  "invalid-request": "invalid D1 request",
  unauthorized: "D1 authorization failed",
  "rate-limited": "D1 request was rate limited",
  "server-error": "D1 service is unavailable",
  "http-error": "D1 request failed",
  "network-error": "D1 network request failed",
  timeout: "D1 request timed out",
  "provider-error": "D1 provider rejected the query",
  malformed: "invalid D1 response",
  "response-too-large": "D1 response is too large",
  "result-set-limit": "D1 result-set limit exceeded",
  "row-limit": "D1 row limit exceeded",
};

export class CloudflareD1Error extends Error {
  readonly code: D1ErrorCode;
  readonly category: D1ErrorCode;

  constructor(code: D1ErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "CloudflareD1Error";
    this.code = code;
    this.category = code;
  }
}

export type D1Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
export type D1AbortController = new () => AbortController;
export type D1SetTimeout = (handler: () => void, timeout: number) => ReturnType<typeof setTimeout>;
export type D1ClearTimeout = (handle: ReturnType<typeof setTimeout>) => void;

export interface D1ClientOptions {
  readonly fetch?: D1Fetch;
  readonly AbortController?: D1AbortController;
  readonly setTimeout?: D1SetTimeout;
  readonly clearTimeout?: D1ClearTimeout;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly maxResultSets?: number;
  readonly maxRows?: number;
}

export const DEFAULT_D1_TIMEOUT_MS = 10_000;
export const DEFAULT_D1_MAX_RESPONSE_BYTES = 1_048_576;
export const DEFAULT_D1_MAX_RESULT_SETS = 16;
export const DEFAULT_D1_MAX_ROWS = 10_000;

const API_ORIGIN = "https://api.cloudflare.com/client/v4";
const NUMERIC_META = new Set(["duration", "rows_read", "rows_written", "last_row_id", "size_after", "changes"]);
const BOOLEAN_META = new Set(["changed_db", "served_by_primary"]);

function invalid(code: D1ErrorCode): never {
  throw new CloudflareD1Error(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedOption(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) invalid("invalid-request");
  return value;
}

function encodePathSegment(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function endpointFor(config: CloudReaderConfig): string {
  if (!isRecord(config) || typeof config.accountId !== "string" || typeof config.databaseId !== "string" || typeof config.d1ReadToken !== "string") {
    invalid("invalid-request");
  }
  return `${API_ORIGIN}/accounts/${encodePathSegment(config.accountId)}/d1/database/${encodePathSegment(config.databaseId)}/query`;
}

function scalar(value: unknown): value is D1Scalar {
  return value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

function requestBody(statement: string, params: readonly D1Scalar[]): string {
  if (typeof statement !== "string" || statement.trim() === "" || !Array.isArray(params) || !params.every(scalar)) invalid("invalid-request");
  try {
    return JSON.stringify({ sql: statement, params });
  } catch {
    invalid("invalid-request");
  }
}

function metadata(value: unknown): D1ResultMeta {
  if (!isRecord(value)) invalid("malformed");
  for (const [key, item] of Object.entries(value)) {
    if (NUMERIC_META.has(key) && (typeof item !== "number" || !Number.isFinite(item))) invalid("malformed");
    if (BOOLEAN_META.has(key) && typeof item !== "boolean") invalid("malformed");
  }
  return value;
}

function jsonContentType(response: Response): boolean {
  const value = response.headers?.get("content-type");
  return typeof value === "string" && value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function declaredLength(response: Response): number | null {
  const value = response.headers?.get("content-length")?.trim();
  if (!value || !/^\d+$/.test(value)) return null;
  const length = Number(value);
  return Number.isSafeInteger(length) ? length : Number.MAX_SAFE_INTEGER;
}

async function readBoundedBody(response: Response, maximum: number): Promise<string> {
  const length = declaredLength(response);
  if (length !== null && length > maximum) invalid("response-too-large");

  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        if (!(item.value instanceof Uint8Array)) invalid("malformed");
        total += item.value.byteLength;
        if (total > maximum) {
          await Promise.resolve(reader.cancel()).catch(() => undefined);
          invalid("response-too-large");
        }
        chunks.push(item.value);
      }
    } catch (error) {
      if (error instanceof CloudflareD1Error) throw error;
      invalid("malformed");
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      invalid("malformed");
    }
  }

  if (typeof response.text !== "function") invalid("malformed");
  try {
    const text = await response.text();
    if (typeof text !== "string" || new TextEncoder().encode(text).byteLength > maximum) invalid("response-too-large");
    return text;
  } catch (error) {
    if (error instanceof CloudflareD1Error) throw error;
    invalid("malformed");
  }
}

function parseResponse(source: string, maximumResultSets: number, maximumRows: number): D1QueryResponse {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    invalid("malformed");
  }
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.errors) || !Array.isArray(value.result)) {
    if (isRecord(value) && value.success === false) invalid("provider-error");
    invalid("malformed");
  }
  if (value.errors.length > 0) invalid("provider-error");
  if (value.messages !== undefined && !Array.isArray(value.messages)) invalid("malformed");
  if (value.result.length > maximumResultSets) invalid("result-set-limit");

  const result: D1ResultSet[] = [];
  let rowCount = 0;
  for (const entry of value.result) {
    if (!isRecord(entry) || entry.success !== true || !Array.isArray(entry.results) || !isRecord(entry.meta)) {
      if (isRecord(entry) && entry.success === false) invalid("provider-error");
      invalid("malformed");
    }
    const rows: D1Row[] = [];
    for (const row of entry.results) {
      if (!isRecord(row)) invalid("malformed");
      rowCount += 1;
      if (rowCount > maximumRows) invalid("row-limit");
      rows.push(row);
    }
    result.push({ results: rows, meta: metadata(entry.meta) });
  }
  return { result };
}

function isAbortError(error: unknown): boolean {
  return isRecord(error) && error.name === "AbortError";
}

export class CloudflareD1Client {
  private readonly config: CloudReaderConfig;
  private readonly options: Required<Pick<D1ClientOptions, "timeoutMs" | "maxResponseBytes" | "maxResultSets" | "maxRows">> & D1ClientOptions;

  constructor(config: CloudReaderConfig, options: D1ClientOptions = {}) {
    this.config = config;
    this.options = {
      ...options,
      timeoutMs: boundedOption(options.timeoutMs, DEFAULT_D1_TIMEOUT_MS),
      maxResponseBytes: boundedOption(options.maxResponseBytes, DEFAULT_D1_MAX_RESPONSE_BYTES),
      maxResultSets: boundedOption(options.maxResultSets, DEFAULT_D1_MAX_RESULT_SETS),
      maxRows: boundedOption(options.maxRows, DEFAULT_D1_MAX_ROWS),
    };
  }

  async query(statement: string, params: readonly D1Scalar[] = []): Promise<D1QueryResponse> {
    const endpoint = endpointFor(this.config);
    const body = requestBody(statement, params);
    const fetcher = this.options.fetch ?? globalThis.fetch;
    const AbortControllerImpl = this.options.AbortController ?? globalThis.AbortController;
    const setTimer = this.options.setTimeout ?? globalThis.setTimeout;
    const clearTimer = this.options.clearTimeout ?? globalThis.clearTimeout;
    if (typeof fetcher !== "function" || typeof AbortControllerImpl !== "function" || typeof setTimer !== "function" || typeof clearTimer !== "function") invalid("network-error");

    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortControllerImpl();
    const operation = (async () => {
      let response: Response;
      try {
        response = await fetcher(endpoint, {
          method: "POST",
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${this.config.d1ReadToken}`,
            "Content-Type": "application/json",
          },
          cache: "no-store",
          body,
          signal: controller.signal,
        });
      } catch (error) {
        if (timedOut || isAbortError(error)) invalid("timeout");
        invalid("network-error");
      }
      if (response.status === 401 || response.status === 403) invalid("unauthorized");
      if (response.status === 429) invalid("rate-limited");
      if (response.status >= 500 && response.status <= 599) invalid("server-error");
      if (response.status !== 200) invalid("http-error");
      if (!jsonContentType(response)) invalid("malformed");
      const source = await readBoundedBody(response, this.options.maxResponseBytes);
      return parseResponse(source, this.options.maxResultSets, this.options.maxRows);
    })();
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimer(() => {
        timedOut = true;
        try { controller.abort(); } finally { reject(new CloudflareD1Error("timeout")); }
      }, this.options.timeoutMs);
    });
    try {
      return await Promise.race([operation, timeout]);
    } catch (error) {
      if (error instanceof CloudflareD1Error) throw error;
      if (timedOut || isAbortError(error)) throw new CloudflareD1Error("timeout");
      throw new CloudflareD1Error("network-error");
    } finally {
      if (timer !== undefined) clearTimer(timer);
    }
  }
}

export { CloudflareD1Client as D1Client };

export function createCloudflareD1Client(config: CloudReaderConfig, options: D1ClientOptions = {}): CloudflareD1Client {
  return new CloudflareD1Client(config, options);
}

export function queryCloudflareD1(config: CloudReaderConfig, statement: string, params: readonly D1Scalar[] = [], options: D1ClientOptions = {}): Promise<D1QueryResponse> {
  return new CloudflareD1Client(config, options).query(statement, params);
}

export const queryD1 = queryCloudflareD1;
