import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import Module, { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { CloudReaderConfig } from "../lib/steward-archive/cloud-config";
import type { CloudD1QueryClient } from "../lib/steward-archive/cloud-repository";
import type { CloudArtifact } from "../lib/steward-archive/cloud-schema";

type RepositoryModule = typeof import("../lib/steward-archive/cloud-repository");
type CloudflareModule = typeof import("../lib/steward-archive/cloudflare");
type CloudSchemaModule = typeof import("../lib/steward-archive/cloud-schema");
type AtifLoaderModule = typeof import("../lib/steward-archive/atif-loader");
type AtifViewModelModule = typeof import("../lib/steward-archive/atif-view-model");

const rawCase = process.argv[2] ?? "";
const MAX_CASE_LENGTH = 256;
const GREENFIELD_TASK_ID = "task-greenfield";
const FAILURE_CASES = new Set(["dangling-head", "digest-mismatch", "private-field"]);
const REPLAY_CASES = new Set(["replay", "reopen/replay"]);
const SUPPORTED_CASES = new Set(["empty", "published", "replay", "reopen/replay", "hidden", "unavailable", "hidden/unavailable", "dangling-head", "digest-mismatch", "private-field", "protocol-negative", "child-boundary"]);
const requireForScript = createRequire(import.meta.url);
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };

function loadRuntimeModules(): { readonly repository: RepositoryModule; readonly cloudflare: CloudflareModule; readonly schema: CloudSchemaModule; readonly atifLoader: AtifLoaderModule; readonly atifViewModel: AtifViewModelModule } {
  const empty = resolve(dirname(requireForScript.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try {
    return {
      repository: requireForScript(resolve(dirname(fileURLToPath(import.meta.url)), "../lib/steward-archive/cloud-repository.ts")) as RepositoryModule,
      cloudflare: requireForScript(resolve(dirname(fileURLToPath(import.meta.url)), "../lib/steward-archive/cloudflare.ts")) as CloudflareModule,
      schema: requireForScript(resolve(dirname(fileURLToPath(import.meta.url)), "../lib/steward-archive/cloud-schema.ts")) as CloudSchemaModule,
      atifLoader: requireForScript(resolve(dirname(fileURLToPath(import.meta.url)), "../lib/steward-archive/atif-loader.ts")) as AtifLoaderModule,
      atifViewModel: requireForScript(resolve(dirname(fileURLToPath(import.meta.url)), "../lib/steward-archive/atif-view-model.ts")) as AtifViewModelModule,
    };
  } finally {
    runtimeModule._resolveFilename = previous;
  }
}

const runtime = loadRuntimeModules();
const { getCloudRepository, resetCloudRepository } = runtime.repository;
const { CloudflareD1Client } = runtime.cloudflare;
const { validateCloudStatusResponse, validateCloudTaskPageResponse, validateCloudTaskDetailResponse, validateCloudCompleteTrajectoryResponse, validateCloudProblemResponse, validateCloudTaskDetailData } = runtime.schema;
const { loadVerifiedAtif } = runtime.atifLoader;
const { buildAtifViewModel } = runtime.atifViewModel;

function assertLoopbackBase(value: unknown): URL {
  assert.equal(typeof value, "string", "provider URL is required");
  const raw = value as string;
  assert(raw.length > 0 && raw.length <= 2048 && raw === raw.trim(), "provider URL is malformed");
  const parsed = new URL(raw);
  assert.equal(parsed.protocol, "http:", "provider URL must use HTTP");
  assert.equal(parsed.hostname, "127.0.0.1", "provider URL must be loopback");
  assert.equal(parsed.username, "", "provider URL must not contain credentials");
  assert.equal(parsed.password, "", "provider URL must not contain credentials");
  assert(!raw.includes("?"), "provider URL must not contain a query");
  assert(!raw.includes("#"), "provider URL must not contain a fragment");
  assert.equal(parsed.search, "", "provider URL must not contain a query");
  assert.equal(parsed.hash, "", "provider URL must not contain a fragment");
  assert.equal(parsed.pathname, "/", "provider URL must not contain a path");
  return new URL(parsed.origin + "/");
}

function configFor(provider: URL): CloudReaderConfig {
  const config = {
    accountId: "a".repeat(32),
    databaseId: "12345678-1234-4abc-8def-1234567890ab",
    publicR2BaseUrl: `https://${provider.host}/r2/`,
  } as CloudReaderConfig;
  Object.defineProperty(config, "d1ReadToken", {
    configurable: false,
    enumerable: false,
    value: "greenfield-read-token",
    writable: false,
  });
  return Object.freeze(config);
}

function providerPath(provider: URL, path: string): string {
  assert(path.startsWith("/"), "provider path must be absolute");
  return new URL(path, provider).toString();
}

function installProviderFetch(provider: URL): () => void {
  const original = globalThis.fetch;
  assert.equal(typeof original, "function", "fetch is unavailable");
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const candidate = new URL(input instanceof Request ? input.url : String(input), provider);
    const secureOrigin = `https://${provider.host}`;
    assert(candidate.origin === provider.origin || candidate.origin === secureOrigin, "fetch escaped provider origin");
    assert.equal(candidate.username, "", "fetch URL contains credentials");
    assert.equal(candidate.password, "", "fetch URL contains credentials");
    assert.equal(candidate.search, "", "fetch URL contains a query on the provider base");
    assert.equal(candidate.hash, "", "fetch URL contains a fragment");
    if (candidate.origin === secureOrigin) candidate.protocol = "http:";
    return original(candidate, init);
  }) as typeof fetch;
  return () => { globalThis.fetch = original; };
}

function makeClient(provider: URL, config: CloudReaderConfig): CloudD1QueryClient {
  return new CloudflareD1Client(config, {
    fetch: async (_input, init) => globalThis.fetch(providerPath(provider, "/d1/query"), init),
    timeoutMs: 10_000,
    maxResponseBytes: 2 * 1024 * 1024,
  });
}

function allTaskIds(page: { readonly tasks: readonly { readonly taskId: string }[] }): string[] {
  return page.tasks.map((task) => task.taskId);
}

async function readEmpty(repository: ReturnType<typeof getCloudRepository>): Promise<void> {
  const status = await repository.getStatus();
  assert.deepEqual(status, { state: "empty", taskCount: 0, latestPublicationAt: null });
  const active = await repository.listTasks("active", { limit: 50 });
  const history = await repository.listTasks("history", { limit: 50 });
  assert.deepEqual(allTaskIds(active), []);
  assert.deepEqual(allTaskIds(history), []);
}

function artifactUrl(provider: URL, publicKey: string): string {
  const segments = publicKey.split("/");
  assert(segments.length >= 2 && segments.every((segment) => segment.length > 0), "invalid artifact key");
  return `${provider.origin}/r2/${segments.map((segment) => encodeURIComponent(segment)).join("/")}`;
}

async function checkArtifact(provider: URL, artifact: {
  readonly taskId: string;
  readonly publicKey: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly availability: string;
  readonly logicalPath: string;
}): Promise<string | null> {
  assert.match(artifact.publicKey, new RegExp(`^v1/tasks/${artifact.taskId}/objects/sha256/[0-9a-f]{2}/${artifact.sha256}$`));
  assert(!artifact.logicalPath.includes("..") && !artifact.logicalPath.includes("://"), "unsafe logical artifact path");
  if (artifact.availability !== "available") return null;
  const url = artifactUrl(provider, artifact.publicKey);
  const response = await globalThis.fetch(url, { cache: "no-store", credentials: "omit", redirect: "error" });
  assert.equal(response.status, 200, "published object is unavailable");
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(bytes.byteLength, artifact.byteSize, "published object size differs from descriptor");
  const digest = createHash("sha256").update(bytes).digest("hex");
  assert.equal(digest, artifact.sha256, "published object digest differs from descriptor");
  return `${artifact.publicKey}:${bytes.byteLength}:${digest}`;
}

function loaderBase(provider: URL): string {
  return `https://${provider.host}/r2/`;
}

async function loadDisplayModel(provider: URL, repository: ReturnType<typeof getCloudRepository>, taskId: string, runId: string, artifacts: readonly CloudArtifact[]) {
  const document = await loadVerifiedAtif(taskId, runId, {
    repository,
    config: { publicR2BaseUrl: loaderBase(provider) },
    fetch: async (input, init) => {
      const secure = new URL(String(input));
      assert.equal(secure.protocol, "https:", "loader escaped its bounded object URL");
      assert.equal(secure.hostname, provider.hostname, "loader escaped loopback host");
      secure.protocol = "http:";
      return globalThis.fetch(secure, init);
    },
  });
  const model = buildAtifViewModel(document, { artifacts, taskId, runId });
  assert.equal(model.kind, "atif-display");
  assert.equal(model.taskId, taskId);
  assert.equal(model.runId, runId);
  const serialized = JSON.stringify(model);
  assert(!serialized.includes("publicKey") && !serialized.includes("publicUrl"), "display model leaked an object locator");
  for (const artifact of model.artifacts) {
    if (artifact.action.kind === "unavailable") continue;
    assert.equal(artifact.action.taskId, taskId);
    assert.equal(artifact.action.runId, runId);
    assert.match(artifact.action.href, /^\/api\/steward\/tasks\/.+\/artifact\?path=/);
  }
  return model;
}

async function readRealRoutes(provider: URL, repository: ReturnType<typeof getCloudRepository>, taskId: string, logicalPath: string, runId: string): Promise<unknown> {
  const [statusRoute, tasksRoute, detailRoute, artifactRoute, transcriptRoute] = await Promise.all([
    import("../app/api/steward/status/route"),
    import("../app/api/steward/tasks/route"),
    import("../app/api/steward/tasks/[taskId]/route"),
    import("../app/api/steward/tasks/[taskId]/artifact/route"),
    import("../app/api/steward/tasks/[taskId]/transcript/route"),
  ]);
  const status = await statusRoute.GET();
  assert.equal(status.status, 200, "status route failed");
  const statusBody = await status.json() as unknown;
  const validatedStatus = validateCloudStatusResponse(statusBody);
  assert.equal(validatedStatus.schemaVersion, "4.0");
  assert(validatedStatus.data !== undefined, "status route omitted data");

  const tasks = await tasksRoute.GET(new Request(`${provider.origin}/api/steward/tasks?scope=history&limit=50`));
  assert.equal(tasks.status, 200, "tasks route failed");
  const tasksBody = await tasks.json() as unknown;
  const validatedTasks = validateCloudTaskPageResponse(tasksBody);
  assert.equal(validatedTasks.schemaVersion, "4.0");
  assert(validatedTasks.data.items.some((item) => item.taskId === taskId), "tasks route omitted task");

  const detail = await detailRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${encodeURIComponent(taskId)}`), { params: Promise.resolve({ taskId }) });
  assert.equal(detail.status, 200, "detail route failed");
  const detailBody = await detail.json() as unknown;
  const validatedDetail = validateCloudTaskDetailResponse(detailBody);
  assert.equal(validatedDetail.schemaVersion, "4.0");
  assert.equal(validatedDetail.data.task.taskId, taskId);

  const artifact = await artifactRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${encodeURIComponent(taskId)}/artifact?path=${encodeURIComponent(logicalPath)}`), { params: Promise.resolve({ taskId }) });
  assert.equal(artifact.status, 307, "artifact route failed");
  assert(new URL(artifact.headers.get("location") ?? "").hostname === provider.hostname, "artifact route escaped provider");

  const transcript = await transcriptRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${encodeURIComponent(taskId)}/transcript?run=${encodeURIComponent(runId)}`), { params: Promise.resolve({ taskId }) });
  assert.equal(transcript.status, 200, "transcript route failed");
  const transcriptBody = await transcript.json() as unknown;
  const validatedTranscript = validateCloudCompleteTrajectoryResponse(transcriptBody);
  assert.equal(validatedTranscript.schemaVersion, "4.0");
  assert(validatedTranscript.data !== undefined, "transcript route omitted data");
  return {
    status: { status: status.status, headers: selectedHeaders(status.headers), body: normalizeJson(statusBody) },
    tasks: { status: tasks.status, headers: selectedHeaders(tasks.headers), body: normalizeJson(tasksBody) },
    detail: { status: detail.status, headers: selectedHeaders(detail.headers), body: normalizeJson(detailBody) },
    artifact: { status: artifact.status, headers: selectedHeaders(artifact.headers), location: normalizeLocation(artifact.headers.get("location"), provider) },
    transcript: { status: transcript.status, headers: selectedHeaders(transcript.headers), body: normalizeJson(transcriptBody) },
  };
}

function normalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, key === "generatedAt" ? "<generated>" : normalizeJson(item)]));
  }
  return value;
}

function selectedHeaders(headers: Headers): Record<string, string> {
  const entries: Array<[string, string]> = [];
  headers.forEach((value, name) => entries.push([name, value]));
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeLocation(value: string | null, provider: URL): string | null {
  if (value === null) return null;
  const location = new URL(value);
  assert.equal(location.hostname, provider.hostname, "route redirect escaped provider");
  return `${location.pathname}${location.search}${location.hash}`;
}

async function readPublished(provider: URL, repository: ReturnType<typeof getCloudRepository>): Promise<string> {
  const status = await repository.getStatus();
  assert.equal(status.state, "available");
  assert(status.taskCount > 0, "published case has no visible task");
  const active = await repository.listTasks("active", { limit: 50 });
  const history = await repository.listTasks("history", { limit: 50 });
  const tasks = [...active.tasks, ...history.tasks];
  assert.equal(tasks.length, status.taskCount, "status and task pages disagree");
  assert.equal(new Set(tasks.map((task) => task.taskId)).size, tasks.length, "task page duplicated an identity");
  for (const task of tasks) {
    assert.equal(typeof task.disclosure.redactionApplied, "boolean", "task disclosure is malformed");
    assert.equal(typeof task.disclosure.originalRetained, "boolean", "task disclosure is malformed");
    assert(task.title.length > 0 && task.taskId.length > 0, "task display shape is incomplete");
  }

  const task = tasks[0]!;
  const detail = await repository.getTaskDetail(task.taskId);
  assert(detail, "published task detail is missing");
  validateCloudTaskDetailData(detail);
  assert.equal(detail.task.taskId, task.taskId);
  assert.equal(detail.task.eventCount, detail.events.length);
  assert.equal(detail.task.artifactCount, detail.artifacts.length);
  detail.events.forEach((event, index) => {
    assert.equal(event.taskId, task.taskId);
    assert.equal(event.sequence, index + 1, "events are not ordered");
  });
  for (const pipeline of detail.pipelines) assert.equal(pipeline.taskId, task.taskId);
  for (const run of detail.runs) {
    assert.equal(run.taskId, task.taskId);
    assert(detail.pipelines.some((pipeline) => pipeline.pipelineId === run.pipelineId), "run has no owning pipeline");
  }
  const objectSnapshots: string[] = [];
  for (const artifact of detail.artifacts) {
    assert.equal(artifact.taskId, task.taskId);
    assert(detail.runs.some((run) => run.runId === artifact.runId), "artifact has no owning run");
    const objectSnapshot = await checkArtifact(provider, artifact);
    if (objectSnapshot !== null) objectSnapshots.push(objectSnapshot);
  }
  let routeSnapshot: unknown = null;
  if (detail.trajectory) {
    assert.equal(detail.trajectory.taskId, task.taskId);
    assert.equal(detail.trajectory.availability, "available");
    const trajectory = await repository.getTrajectoryDescriptor(task.taskId, detail.trajectory.runId);
    assert.deepEqual(trajectory, detail.trajectory, "trajectory descriptor changed across repository calls");
    assert(detail.artifacts.some((artifact) => artifact.artifactId === detail.trajectory!.artifactId || artifact.publicKey === detail.trajectory!.publicKey), "trajectory has no artifact action");
    await loadDisplayModel(provider, repository, task.taskId, detail.trajectory.runId, detail.artifacts.filter((artifact) => artifact.runId === detail.trajectory!.runId));
    const artifact = detail.artifacts.find((candidate) => candidate.availability === "available");
    assert(artifact, "published task has no available artifact");
    routeSnapshot = await readRealRoutes(provider, repository, task.taskId, artifact.logicalPath, detail.trajectory.runId);
  }
  return JSON.stringify(normalizeJson({ status, active, history, detail, objectSnapshots, routeSnapshot }));
}

async function readHidden(provider: URL, repository: ReturnType<typeof getCloudRepository>): Promise<void> {
  const status = await repository.getStatus();
  const active = await repository.listTasks("active", { limit: 50 });
  const history = await repository.listTasks("history", { limit: 50 });
  const visibleCount = active.tasks.length + history.tasks.length;
  assert.equal(status.taskCount, visibleCount, "hidden data changed the visible count");
  assert(status.state === "empty" || status.state === "available");
  const detailRoute = await import("../app/api/steward/tasks/[taskId]/route");
  const response = await detailRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${GREENFIELD_TASK_ID}`), { params: Promise.resolve({ taskId: GREENFIELD_TASK_ID }) });
  assert.equal(response.status, 404, "hidden task remained available through the route");
}

async function assertUnavailableRoute(responsePromise: Promise<Response>, name: string): Promise<void> {
  const response = await responsePromise;
  assert.equal(response.status, 503, `${name} did not fail closed during outage`);
  const body = validateCloudProblemResponse(await response.json());
  assert.equal(body.schemaVersion, "4.0");
  assert.equal(body.problem.status, 503);
  assert.equal(body.problem.code, "UNAVAILABLE", `${name} returned an unexpected outage code`);
}

async function readUnavailable(provider: URL, _repository: ReturnType<typeof getCloudRepository>): Promise<void> {
  const [statusRoute, tasksRoute, detailRoute, artifactRoute, transcriptRoute] = await Promise.all([
    import("../app/api/steward/status/route"),
    import("../app/api/steward/tasks/route"),
    import("../app/api/steward/tasks/[taskId]/route"),
    import("../app/api/steward/tasks/[taskId]/artifact/route"),
    import("../app/api/steward/tasks/[taskId]/transcript/route"),
  ]);
  await assertUnavailableRoute(statusRoute.GET(), "status route");
  await assertUnavailableRoute(tasksRoute.GET(new Request(`${provider.origin}/api/steward/tasks?scope=history&limit=50`)), "tasks route");
  await assertUnavailableRoute(detailRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${GREENFIELD_TASK_ID}`), { params: Promise.resolve({ taskId: GREENFIELD_TASK_ID }) }), "detail route");
  await assertUnavailableRoute(artifactRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${GREENFIELD_TASK_ID}/artifact?path=run.json`), { params: Promise.resolve({ taskId: GREENFIELD_TASK_ID }) }), "artifact route");
  await assertUnavailableRoute(transcriptRoute.GET(new Request(`${provider.origin}/api/steward/tasks/${GREENFIELD_TASK_ID}/transcript?run=run-greenfield`), { params: Promise.resolve({ taskId: GREENFIELD_TASK_ID }) }), "transcript route");
}

async function readFailure(provider: URL, repository: ReturnType<typeof getCloudRepository>, expectedCase: string): Promise<void> {
  let rejected = false;
  try {
    await readPublished(provider, repository);
  } catch {
    rejected = true;
  }
  assert(rejected, `corrupt ${expectedCase} data was accepted`);
}

async function run(): Promise<void> {
  assert.equal(process.argv.length, 3, "exactly one case argument is required");
  assert(rawCase.length > 0 && rawCase.length <= MAX_CASE_LENGTH, "case is required");
  assert(SUPPORTED_CASES.has(rawCase), "unsupported greenfield case");
  const provider = assertLoopbackBase(process.env.COQUIC_GREENFIELD_PROVIDER_BASE_URL);
  const config = configFor(provider);
  const restoreFetch = installProviderFetch(provider);
  const previousEnvironment = {
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
    databaseId: process.env.COQUIC_STEWARD_D1_DATABASE_ID,
    token: process.env.COQUIC_STEWARD_D1_READ_TOKEN,
    r2: process.env.COQUIC_STEWARD_PUBLIC_R2_BASE_URL,
  };
  process.env.CLOUDFLARE_ACCOUNT_ID = config.accountId;
  process.env.COQUIC_STEWARD_D1_DATABASE_ID = config.databaseId;
  process.env.COQUIC_STEWARD_D1_READ_TOKEN = config.d1ReadToken;
  process.env.COQUIC_STEWARD_PUBLIC_R2_BASE_URL = `https://${provider.host}/r2/`;
  resetCloudRepository();
  try {
    const client = makeClient(provider, config);
    const repository = getCloudRepository({ client, config });
    if (rawCase === "empty") {
      await readEmpty(repository);
    } else if (REPLAY_CASES.has(rawCase)) {
      const first = await readPublished(provider, repository);
      resetCloudRepository();
      const replayRepository = getCloudRepository({ client, config });
      const second = await readPublished(provider, replayRepository);
      assert.equal(second, first, "replay changed the visible Site response");
    } else if (rawCase === "hidden") {
      await readHidden(provider, repository);
    } else if (rawCase === "unavailable" || rawCase === "hidden/unavailable") {
      await readUnavailable(provider, repository);
    } else if (FAILURE_CASES.has(rawCase)) {
      await readFailure(provider, repository, rawCase);
    } else if (rawCase === "published") {
      await readPublished(provider, repository);
    } else if (rawCase === "protocol-negative") {
      // Protocol negatives are exercised by the Python parent process.
    } else if (rawCase === "child-boundary") {
      // Child protocol bounds are exercised by the Python parent process.
    } else {
      throw new Error("unsupported greenfield case");
    }
  } finally {
    resetCloudRepository();
    restoreFetch();
    if (previousEnvironment.accountId === undefined) delete process.env.CLOUDFLARE_ACCOUNT_ID;
    else process.env.CLOUDFLARE_ACCOUNT_ID = previousEnvironment.accountId;
    if (previousEnvironment.databaseId === undefined) delete process.env.COQUIC_STEWARD_D1_DATABASE_ID;
    else process.env.COQUIC_STEWARD_D1_DATABASE_ID = previousEnvironment.databaseId;
    if (previousEnvironment.token === undefined) delete process.env.COQUIC_STEWARD_D1_READ_TOKEN;
    else process.env.COQUIC_STEWARD_D1_READ_TOKEN = previousEnvironment.token;
    if (previousEnvironment.r2 === undefined) delete process.env.COQUIC_STEWARD_PUBLIC_R2_BASE_URL;
    else process.env.COQUIC_STEWARD_PUBLIC_R2_BASE_URL = previousEnvironment.r2;
  }
}

void run().then(
  () => {
    process.stdout.write(`${JSON.stringify({ case: rawCase, ok: true })}\n`);
  },
  (error: unknown) => {
    process.exitCode = 1;
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.stdout.write(`${JSON.stringify({ case: rawCase, ok: false })}\n`);
  },
);
