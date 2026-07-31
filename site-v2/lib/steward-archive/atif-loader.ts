import "server-only";

import {
  validateAtifBytes,
  type AtifDocument,
  type AtifPublicationArtifactDescriptor,
} from "./atif";
import {
  validateCloudArtifact,
  validateCloudTrajectoryDescriptorData,
  type CloudArtifact,
  type CloudTaskDetail,
  type CloudTrajectoryDescriptor,
} from "./cloud-schema";
import { resolvePublicObjectUrl } from "./publication";

export const DEFAULT_ATIF_LOADER_MAX_BYTES = 16 * 1024 * 1024;
export const DEFAULT_ATIF_LOADER_TIMEOUT_MS = 10_000;

export type AtifLoaderFailureCategory = "missing" | "resource" | "integrity" | "transient";
export type AtifLoaderCategory = AtifLoaderFailureCategory;

export class AtifLoaderError extends Error {
  readonly category: AtifLoaderFailureCategory;
  readonly code: AtifLoaderFailureCategory;

  constructor(category: AtifLoaderFailureCategory) {
    super(category);
    this.name = "AtifLoaderError";
    this.category = category;
    this.code = category;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type AtifFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type AtifAbortController = new () => AbortController;
export type AtifSetTimeout = (handler: () => void, timeout: number) => unknown;
export type AtifClearTimeout = (handle: unknown) => void;

export interface AtifLoaderClock {
  readonly setTimeout?: AtifSetTimeout;
  readonly clearTimeout?: AtifClearTimeout;
}

export interface AtifTrajectoryRepository {
  readonly getTaskDetail?: (taskId: string) => Promise<CloudTaskDetail | null>;
  readonly getTrajectoryDescriptor?: (taskId: string, runId?: string) => Promise<CloudTrajectoryDescriptor | null>;
  readonly getTrajectory?: (taskId: string, runId?: string) => Promise<CloudTrajectoryDescriptor | null>;
}

export interface AtifLoaderConfig {
  readonly publicR2BaseUrl: string;
}

export interface AtifLoaderOptions {
  readonly repository?: AtifTrajectoryRepository;
  readonly config?: AtifLoaderConfig;
  readonly publicR2BaseUrl?: string;
  readonly fetch?: AtifFetch;
  readonly AbortController?: AtifAbortController;
  readonly setTimeout?: AtifSetTimeout;
  readonly clearTimeout?: AtifClearTimeout;
  readonly clock?: AtifLoaderClock;
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
}

export interface AtifLoadRequest {
  readonly taskId: string;
  readonly runId?: string;
  readonly options?: AtifLoaderOptions;
}

export type AtifLoadResult =
  | { readonly ok: true; readonly value: AtifDocument }
  | { readonly ok: false; readonly category: AtifLoaderFailureCategory };

interface ResolvedArguments {
  readonly taskId: string;
  readonly runId: string | undefined;
  readonly options: AtifLoaderOptions;
}

interface ResolvedSelection {
  readonly descriptor: CloudTrajectoryDescriptor;
  readonly artifacts: readonly CloudArtifact[];
  readonly source: "detail" | "descriptor";
}

interface DescriptorWithArtifacts extends CloudTrajectoryDescriptor {
  readonly artifacts?: readonly CloudArtifact[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeArguments(
  taskOrRequest: string | AtifLoadRequest,
  runOrOptions?: string | AtifLoaderOptions,
  suppliedOptions: AtifLoaderOptions = {},
): ResolvedArguments {
  if (typeof taskOrRequest === "object") {
    return {
      taskId: taskOrRequest.taskId,
      runId: taskOrRequest.runId,
      options: taskOrRequest.options ?? {},
    };
  }
  return {
    taskId: taskOrRequest,
    runId: typeof runOrOptions === "string" ? runOrOptions : undefined,
    options: typeof runOrOptions === "string" ? suppliedOptions : (runOrOptions ?? suppliedOptions),
  };
}

function loaderError(category: AtifLoaderFailureCategory): AtifLoaderError {
  return new AtifLoaderError(category);
}

function categoryFromUnknown(error: unknown): AtifLoaderFailureCategory {
  if (error instanceof AtifLoaderError) return error.category;
  if (isRecord(error)) {
    const code = error.code;
    if (code === "timeout" || code === "network-error" || code === "server-error" || code === "rate-limited" || code === "http-error") return "transient";
    if (code === "response-too-large" || code === "row-limit" || code === "result-set-limit") return "resource";
    if (code === "INVALID_PUBLIC_DATA" || code === "INVALID_PUBLICATION") return "integrity";
    if (error.name === "AbortError") return "transient";
  }
  return "integrity";
}

function validLimit(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) return fallback;
  return Math.min(value, DEFAULT_ATIF_LOADER_MAX_BYTES);
}

function validTimeout(value: number | undefined): number {
  if (value === undefined) return DEFAULT_ATIF_LOADER_TIMEOUT_MS;
  if (!Number.isSafeInteger(value) || value < 0) return DEFAULT_ATIF_LOADER_TIMEOUT_MS;
  return value;
}

function abortError(error: unknown): boolean {
  return isRecord(error) && error.name === "AbortError";
}

function redirectError(error: unknown): boolean {
  if (!isRecord(error) || error.name !== "TypeError" || error.message !== "fetch failed") return false;
  const cause = error.cause;
  return isRecord(cause) && cause.name === "Error" && cause.message === "unexpected redirect";
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    void Promise.resolve(reader.cancel()).catch(() => undefined);
  } catch {
    // A cancelled response is already unusable; its cancellation error is not
    // part of the bounded public failure contract.
  }
}

function contentLength(response: Response): number | null {
  let raw: string | null;
  try {
    raw = response.headers?.get("content-length") ?? null;
  } catch {
    throw loaderError("integrity");
  }
  if (raw === null) return null;
  const value = raw.trim();
  if (value === "") throw loaderError("integrity");
  if (!/^\d+$/.test(value)) throw loaderError("integrity");
  const length = Number(value);
  if (!Number.isSafeInteger(length)) throw loaderError("integrity");
  return length;
}

async function readBody(response: Response, expectedSize: number, maximum: number): Promise<Uint8Array> {
  const declared = contentLength(response);
  if (declared !== null) {
    if (declared > maximum) throw loaderError("resource");
    if (declared !== expectedSize) throw loaderError("integrity");
  }

  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        if (!(item.value instanceof Uint8Array)) {
          cancelReader(reader);
          throw loaderError("integrity");
        }
        total += item.value.byteLength;
        if (total > maximum) {
          cancelReader(reader);
          throw loaderError("resource");
        }
        if (total > expectedSize) {
          cancelReader(reader);
          throw loaderError("integrity");
        }
        chunks.push(item.value.slice());
      }
    } catch (error) {
      if (error instanceof AtifLoaderError) throw error;
      if (abortError(error)) throw loaderError("transient");
      throw loaderError("transient");
    }
    if (total !== expectedSize) throw loaderError("integrity");
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  }

  if (typeof response.arrayBuffer === "function") {
    let value: ArrayBuffer;
    try {
      value = await response.arrayBuffer();
    } catch (error) {
      if (abortError(error)) throw loaderError("transient");
      throw loaderError("transient");
    }
    if (!(value instanceof ArrayBuffer)) throw loaderError("integrity");
    if (value.byteLength > maximum) throw loaderError("resource");
    if (value.byteLength !== expectedSize) throw loaderError("integrity");
    return new Uint8Array(value);
  }

  throw loaderError("integrity");
}

async function fetchBody(
  url: string,
  expectedSize: number,
  maximum: number,
  options: AtifLoaderOptions,
): Promise<Uint8Array> {
  const fetcher = options.fetch ?? globalThis.fetch;
  const AbortControllerImpl = options.AbortController ?? globalThis.AbortController;
  const setTimer = options.clock?.setTimeout ?? options.setTimeout ?? ((handler: () => void, timeout: number) => globalThis.setTimeout(handler, timeout));
  const clearTimer = options.clock?.clearTimeout ?? options.clearTimeout ?? ((handle: unknown) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>));
  if (typeof fetcher !== "function" || typeof AbortControllerImpl !== "function" || typeof setTimer !== "function" || typeof clearTimer !== "function") {
    throw loaderError("transient");
  }

  let controller: AbortController;
  try {
    controller = new AbortControllerImpl();
  } catch {
    throw loaderError("transient");
  }

  let timedOut = false;
  let timer: unknown;
  let timerScheduled = false;
  const operation = (async () => {
    let response: Response;
    try {
      response = await fetcher(url, {
        headers: { Accept: "application/json" },
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: controller.signal,
      });
    } catch (error) {
      if (redirectError(error)) throw loaderError("integrity");
      if (timedOut || abortError(error)) throw loaderError("transient");
      throw loaderError("transient");
    }
    if (response.redirected === true) throw loaderError("integrity");
    if (response.status === 404) throw loaderError("missing");
    if (response.status === 408 || response.status === 425 || response.status === 429 || (response.status >= 500 && response.status <= 599)) throw loaderError("transient");
    if (response.status !== 200) throw loaderError("integrity");
    return readBody(response, expectedSize, maximum);
  })();

  const timeout = new Promise<Uint8Array>((_, reject) => {
    try {
      timer = setTimer(() => {
        timedOut = true;
        try { controller.abort(); } catch { /* the timeout category is stable even if abort is not */ }
        reject(loaderError("transient"));
      }, validTimeout(options.timeoutMs));
      timerScheduled = true;
    } catch {
      reject(loaderError("transient"));
    }
  });

  try {
    return await Promise.race([operation, timeout]);
  } catch (error) {
    if (error instanceof AtifLoaderError) throw error;
    if (timedOut || abortError(error)) throw loaderError("transient");
    throw loaderError("transient");
  } finally {
    if (timerScheduled) {
      try { clearTimer(timer); } catch { /* timer cleanup cannot change the category */ }
    }
  }
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) throw loaderError("integrity");
  let digest: ArrayBuffer;
  try {
    digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  } catch {
    throw loaderError("integrity");
  }
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function artifactsFromDescriptor(descriptor: CloudTrajectoryDescriptor): readonly CloudArtifact[] {
  const candidate = descriptor as DescriptorWithArtifacts;
  return candidate.artifacts ?? [];
}

function descriptorFromDetail(detail: CloudTaskDetail, runId: string | undefined): CloudTrajectoryDescriptor | null {
  if (runId === undefined) return detail.trajectory;
  const run = detail.runs.find((candidate) => candidate.runId === runId);
  if (!run || run.runState !== "completed") return null;
  const matches = detail.artifacts.filter((artifact) => artifact.runId === run.runId && artifact.sha256 === run.atifDigest && artifact.mediaType === "application/json");
  const available = matches.filter((artifact) => artifact.availability === "available");
  if (available.length === 0) return null;
  const artifact = available[0]!;
  return validateCloudTrajectoryDescriptorData({
    taskId: run.taskId,
    pipelineId: run.pipelineId,
    runId: run.runId,
    role: run.role,
    runState: run.runState,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    durationMs: run.durationMs,
    artifactId: matches.length === 1 ? artifact.artifactId : null,
    publicKey: artifact.publicKey,
    mediaType: "application/json",
    byteSize: artifact.byteSize,
    sha256: artifact.sha256,
    availability: "available",
    disclosure: artifact.disclosure,
  });
}

async function defaultRepository(): Promise<AtifTrajectoryRepository> {
  const module = await import("./cloud-repository");
  return module.getCloudRepository();
}

async function defaultConfig(): Promise<AtifLoaderConfig> {
  const module = await import("./cloud-config");
  return module.getCloudReaderConfig();
}

async function resolveSelection(
  taskId: string,
  runId: string | undefined,
  repository: AtifTrajectoryRepository,
): Promise<ResolvedSelection | null> {
  if (repository.getTaskDetail) {
    const detail = await repository.getTaskDetail(taskId);
    if (detail) {
      const descriptor = descriptorFromDetail(detail, runId);
      if (descriptor) return { descriptor, artifacts: detail.artifacts, source: "detail" };
      return null;
    }
    return null;
  }

  const resolver = repository.getTrajectoryDescriptor ?? repository.getTrajectory;
  if (!resolver) throw loaderError("integrity");
  const descriptor = await resolver(taskId, runId);
  if (!descriptor) return null;
  return { descriptor, artifacts: artifactsFromDescriptor(descriptor), source: "descriptor" };
}

function publicArtifactDescriptors(
  descriptor: CloudTrajectoryDescriptor,
  artifacts: readonly CloudArtifact[],
): readonly AtifPublicationArtifactDescriptor[] {
  const seen = new Set<string>();
  const result: AtifPublicationArtifactDescriptor[] = [];
  for (const artifact of artifacts) {
    try { validateCloudArtifact(artifact); } catch { throw loaderError("integrity"); }
    if (seen.has(artifact.artifactId)) throw loaderError("integrity");
    seen.add(artifact.artifactId);
    if (artifact.taskId !== descriptor.taskId || artifact.runId !== descriptor.runId) throw loaderError("integrity");
    result.push({
      artifactId: artifact.artifactId,
      taskId: artifact.taskId,
      runId: artifact.runId,
      mediaType: artifact.mediaType,
      sha256: artifact.sha256,
      byteSize: artifact.byteSize,
    });
  }
  if (result.length === 0) throw loaderError("integrity");
  if (descriptor.artifactId !== null && descriptor.artifactId !== undefined) {
    const artifact = artifacts.find((candidate) => candidate.artifactId === descriptor.artifactId);
    if (!artifact || artifact.publicKey !== descriptor.publicKey || artifact.sha256 !== descriptor.sha256 || artifact.byteSize !== descriptor.byteSize || artifact.mediaType !== descriptor.mediaType || artifact.availability !== "available") {
      throw loaderError("integrity");
    }
  }
  return result;
}

async function loadInternal(args: ResolvedArguments): Promise<AtifDocument> {
  if (typeof args.taskId !== "string" || args.taskId.length === 0) throw loaderError("missing");
  const options = args.options;
  const repository = options.repository ?? await defaultRepository();
  const selection = await resolveSelection(args.taskId, args.runId, repository);
  if (!selection) throw loaderError("missing");

  let descriptor: CloudTrajectoryDescriptor;
  try {
    const candidate = selection.descriptor as DescriptorWithArtifacts;
    const { artifacts: _artifacts, ...descriptorFields } = candidate;
    descriptor = validateCloudTrajectoryDescriptorData(descriptorFields);
  } catch {
    throw loaderError("integrity");
  }
  if (descriptor.taskId !== args.taskId || (args.runId !== undefined && descriptor.runId !== args.runId)) throw loaderError("integrity");
  if (descriptor.runState !== "completed" || descriptor.availability !== "available" || descriptor.mediaType !== "application/json") throw loaderError("integrity");

  const maximum = validLimit(options.maxBytes, DEFAULT_ATIF_LOADER_MAX_BYTES);
  if (descriptor.byteSize > maximum) throw loaderError("resource");
  if (!Number.isSafeInteger(descriptor.byteSize) || descriptor.byteSize < 0) throw loaderError("integrity");
  const selectedArtifacts = selection.source === "detail"
    ? selection.artifacts.filter((artifact) => artifact.runId === descriptor.runId)
    : selection.artifacts;
  const artifacts = publicArtifactDescriptors(descriptor, selectedArtifacts);
  const config = options.config ?? (options.publicR2BaseUrl ? { publicR2BaseUrl: options.publicR2BaseUrl } : await defaultConfig());
  let url: string;
  try {
    url = resolvePublicObjectUrl(config.publicR2BaseUrl, descriptor.publicKey);
  } catch {
    throw loaderError("integrity");
  }

  const bytes = await fetchBody(url, descriptor.byteSize, maximum, options);
  if (bytes.byteLength !== descriptor.byteSize) throw loaderError("integrity");
  if ((await digestHex(bytes)) !== descriptor.sha256) throw loaderError("integrity");
  try {
    return validateAtifBytes(bytes, {
      taskId: descriptor.taskId,
      pipelineId: descriptor.pipelineId,
      runId: descriptor.runId,
      role: descriptor.role,
      startedAt: descriptor.startedAt,
      completedAt: descriptor.completedAt,
      durationMs: descriptor.durationMs,
      disclosure: descriptor.disclosure,
      artifacts,
    });
  } catch {
    throw loaderError("integrity");
  }
}

export async function loadVerifiedAtif(
  taskOrRequest: string | AtifLoadRequest,
  runOrOptions?: string | AtifLoaderOptions,
  options?: AtifLoaderOptions,
): Promise<AtifDocument> {
  const args = normalizeArguments(taskOrRequest, runOrOptions, options ?? {});
  try {
    return await loadInternal(args);
  } catch (error) {
    const category = categoryFromUnknown(error);
    if (error instanceof AtifLoaderError && error.category === category) throw error;
    throw loaderError(category);
  }
}

export async function tryLoadVerifiedAtif(
  taskOrRequest: string | AtifLoadRequest,
  runOrOptions?: string | AtifLoaderOptions,
  options?: AtifLoaderOptions,
): Promise<AtifLoadResult> {
  try {
    return { ok: true, value: await loadVerifiedAtif(taskOrRequest, runOrOptions, options) };
  } catch (error) {
    return { ok: false, category: categoryFromUnknown(error) };
  }
}

export class VerifiedAtifLoader {
  constructor(readonly options: AtifLoaderOptions = {}) {}

  load(taskId: string, runId?: string): Promise<AtifDocument> {
    return loadVerifiedAtif(taskId, runId, this.options);
  }

  tryLoad(taskId: string, runId?: string): Promise<AtifLoadResult> {
    return tryLoadVerifiedAtif(taskId, runId, this.options);
  }
}

export const AtifLoader = VerifiedAtifLoader;
export const loadAtifTrajectory = loadVerifiedAtif;
export const fetchVerifiedAtif = loadVerifiedAtif;
export const loadVerifiedTrajectory = loadVerifiedAtif;
export const loadAtif = loadVerifiedAtif;
export const tryLoadAtif = tryLoadVerifiedAtif;
export const loadVerifiedAtifResult = tryLoadVerifiedAtif;
