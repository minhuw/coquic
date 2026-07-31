import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import Module, { createRequire } from "node:module";
import { test } from "node:test";
import { dirname, resolve } from "node:path";
import cleanFixture from "../../../contracts/steward-cloud/fixtures/clean-publication.json";
import redactedFixture from "../../../contracts/steward-cloud/fixtures/redacted-publication.json";
import {
  canonicalAtifBytes,
  type AtifDocument,
} from "@/lib/steward-archive/atif";

type LoaderModule = typeof import("../../lib/steward-archive/atif-loader");
const requireForTest = createRequire(resolve(process.cwd(), "tests/steward-archive/atif-loader.test.ts"));
const runtimeModule = Module as unknown as { _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string };

function loadLoader(): LoaderModule {
  const empty = resolve(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previous = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return empty;
    return previous.call(this, request, parent, isMain, options);
  };
  try { return requireForTest(resolve(process.cwd(), "lib/steward-archive/atif-loader.ts")) as LoaderModule; }
  finally { runtimeModule._resolveFilename = previous; }
}

const loader = loadLoader();
const {
  AtifLoaderError,
  DEFAULT_ATIF_LOADER_MAX_BYTES,
  loadVerifiedAtif,
  tryLoadVerifiedAtif,
} = loader;

type Fixture = typeof cleanFixture;
type FixturePublication = Fixture["publication"];

const baseUrl = "https://objects.example.test/public/";

function copy<T>(value: T): T {
  return structuredClone(value);
}

function descriptorFor(fixture: Fixture, document: AtifDocument = fixture.atif as unknown as AtifDocument) {
  const publication = fixture.publication as FixturePublication;
  const trajectory = publication.artifacts.find((artifact) => artifact.artifactId === "artifact-atif")!;
  const metadata = (document.extra as Record<string, any>).coquic;
  const artifacts = publication.artifacts.map((artifact) => ({
    artifactId: artifact.artifactId,
    taskId: artifact.taskId,
    runId: artifact.runId,
    logicalPath: artifact.logicalPath,
    publicKey: artifact.publicKey,
    mediaType: artifact.mediaType,
    byteSize: artifact.byteSize,
    sha256: artifact.sha256,
    availability: artifact.availability,
    disclosure: artifact.disclosure,
  }));
  return {
    taskId: metadata.taskId,
    pipelineId: metadata.pipelineId,
    runId: metadata.runId,
    role: metadata.role,
    runState: "completed" as const,
    startedAt: metadata.startedAt,
    completedAt: metadata.completedAt,
    durationMs: metadata.durationMs,
    artifactId: trajectory.artifactId,
    publicKey: trajectory.publicKey,
    mediaType: "application/json" as const,
    byteSize: trajectory.byteSize,
    sha256: trajectory.sha256,
    availability: "available" as const,
    disclosure: metadata.disclosure,
    artifacts,
  };
}

function bytesFor(fixture: Fixture, document: AtifDocument = fixture.atif as unknown as AtifDocument): Uint8Array {
  return canonicalAtifBytes(document);
}

function descriptorForBytes(fixture: Fixture, bytes: Uint8Array): ReturnType<typeof descriptorFor> {
  const descriptor = descriptorFor(fixture);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const publicKey = `v1/tasks/${descriptor.taskId}/objects/sha256/${sha256.slice(0, 2)}/${sha256}`;
  return {
    ...descriptor,
    publicKey,
    byteSize: bytes.byteLength,
    sha256,
    artifacts: descriptor.artifacts.map((artifact) => artifact.artifactId === descriptor.artifactId
      ? { ...artifact, publicKey, byteSize: bytes.byteLength, sha256 }
      : artifact),
  };
}

function repositoryFor(descriptor: ReturnType<typeof descriptorFor>) {
  return {
    getTrajectoryDescriptor: async () => descriptor,
  };
}

function responseFor(bytes: Uint8Array, headers?: Record<string, string>): Response {
  return new Response(bytes as unknown as BodyInit, { status: 200, headers });
}

function optionsFor(
  descriptor: ReturnType<typeof descriptorFor>,
  response: Response | (() => Promise<Response>),
  extra: Record<string, unknown> = {},
) {
  return {
    repository: repositoryFor(descriptor),
    publicR2BaseUrl: baseUrl,
    fetch: async () => typeof response === "function" ? response() : response,
    ...extra,
  } as import("../../lib/steward-archive/atif-loader").AtifLoaderOptions;
}

test("accepts exact clean and redacted trajectories and sends a bounded anonymous request", async () => {
  for (const fixture of [cleanFixture, redactedFixture]) {
    const descriptor = descriptorFor(fixture);
    const bytes = bytesFor(fixture);
    let request: { url: RequestInfo | URL; init?: RequestInit } | undefined;
    const value = await loadVerifiedAtif(fixture.publication.artifacts[0]!.taskId, {
      ...optionsFor(descriptor, responseFor(bytes), {
        fetch: async (url: RequestInfo | URL, init?: RequestInit) => {
          request = { url, init };
          return responseFor(bytes);
        },
      }),
    });
    assert.equal(value.schema_version, "ATIF-v1.7");
    assert.equal(request?.url, `${baseUrl}${descriptor.publicKey}`);
    assert.equal(request?.init?.cache, "no-store");
    assert.equal(request?.init?.redirect, "error");
    assert.equal(request?.init?.credentials, "omit");
    assert(request?.init?.signal instanceof AbortSignal);
  }
});

test("returns missing for an absent object and transient for 5xx", async () => {
  const descriptor = descriptorFor(cleanFixture);
  const bytes = bytesFor(cleanFixture);
  const missing = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, new Response(null, { status: 404 })));
  assert.deepEqual(missing, { ok: false, category: "missing" });
  const outage = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, new Response(null, { status: 503 })));
  assert.deepEqual(outage, { ok: false, category: "transient" });
  const rejected = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, new Response(bytes as unknown as BodyInit, { status: 302 })));
  assert.deepEqual(rejected, { ok: false, category: "integrity" });
});

test("classifies native redirect denial as integrity without following the target", async () => {
  const descriptor = descriptorFor(cleanFixture);
  const bytes = bytesFor(cleanFixture);
  let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    if (request.url === "/followed") {
      response.writeHead(200, {
        "content-type": "application/json",
        "content-length": String(bytes.byteLength),
        connection: "close",
      });
      response.end(Buffer.from(bytes));
      return;
    }
    response.writeHead(302, { Location: "/followed", connection: "close" });
    response.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  try {
    const address = server.address();
    assert(address && typeof address !== "string");
    const nativeFetch = globalThis.fetch.bind(globalThis);
    const result = await tryLoadVerifiedAtif("task-clean", {
      ...optionsFor(descriptor, responseFor(bytes)),
      fetch: (_url, init) => nativeFetch(`http://127.0.0.1:${address.port}/redirect`, init),
    });
    assert.deepEqual(result, { ok: false, category: "integrity" });
    assert.equal(requests, 1);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("rejects declared size conflicts and all bounded body overflows", async () => {
  const descriptor = descriptorFor(cleanFixture);
  const bytes = bytesFor(cleanFixture);
  const conflict = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, responseFor(bytes, { "content-length": String(bytes.byteLength + 1) })));
  assert.deepEqual(conflict, { ok: false, category: "integrity" });

  const resource = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, responseFor(bytes), { maxBytes: bytes.byteLength - 1 }));
  assert.deepEqual(resource, { ok: false, category: "resource" });

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([...bytes, 1]));
      controller.close();
    },
  });
  const overflow = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, new Response(stream)));
  assert.deepEqual(overflow, { ok: false, category: "integrity" });

  const truncated = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, responseFor(bytes.slice(0, -1))));
  assert.deepEqual(truncated, { ok: false, category: "integrity" });
  assert.equal(DEFAULT_ATIF_LOADER_MAX_BYTES > bytes.byteLength, true);
});

test("maps timeout and network failures without exposing transport values", async () => {
  const descriptor = descriptorFor(cleanFixture);
  const secretUrl = `${baseUrl}${descriptor.publicKey}`;
  const secretBody = "private-body-7f2e";
  let fireTimer: (() => void) | undefined;
  let cleared = false;
  const pending = new Promise<Response>(() => undefined);
  const result = loadVerifiedAtif("task-clean", optionsFor(descriptor, async () => pending, {
    setTimeout: (handler: () => void) => { fireTimer = handler; return 1; },
    clearTimeout: () => { cleared = true; },
  }));
  for (let attempt = 0; attempt < 5 && !fireTimer; attempt += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert(fireTimer);
  fireTimer!();
  await assert.rejects(result, (error: unknown) => error instanceof AtifLoaderError && error.category === "transient" && error.message === "transient");
  assert.equal(cleared, true);

  const network = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, async () => {
    throw new TypeError("fetch failed", { cause: new Error(`${secretUrl}:${secretBody}`) });
  }));
  assert.deepEqual(network, { ok: false, category: "transient" });
  assert.equal(JSON.stringify(network).includes(secretUrl), false);
  assert.equal(JSON.stringify(network).includes(secretBody), false);
});

test("rejects a mismatched publication digest before ATIF validation", async () => {
  const cleanDocument = copy(cleanFixture.atif) as unknown as AtifDocument;
  const cleanBytes = bytesFor(cleanFixture, cleanDocument);
  const descriptor = descriptorFor(cleanFixture);

  const wrongDigest = copy(descriptor);
  const digest = "f".repeat(64);
  wrongDigest.sha256 = digest;
  wrongDigest.publicKey = `v1/tasks/task-clean/objects/sha256/ff/${digest}`;
  wrongDigest.artifacts[0] = { ...wrongDigest.artifacts[0], sha256: digest, publicKey: wrongDigest.publicKey };
  const integrity = await tryLoadVerifiedAtif("task-clean", optionsFor(wrongDigest, responseFor(cleanBytes)));
  assert.deepEqual(integrity, { ok: false, category: "integrity" });
});

test("invokes strict ATIF schema, semantic, and ownership validation after integrity checks", async () => {
  const cleanDocument = copy(cleanFixture.atif) as unknown as AtifDocument;
  const mutations: ReadonlyArray<readonly [string, (document: Record<string, any>) => void]> = [
    ["schema", (document) => { document.schema_version = "ATIF-v1.6"; }],
    ["semantic", (document) => { document.steps[1].step_id = 3; }],
    ["task ownership", (document) => { document.extra.coquic.taskId = "foreign-task"; }],
    ["pipeline ownership", (document) => { document.extra.coquic.pipelineId = "foreign-pipeline"; }],
    ["run ownership", (document) => { document.extra.coquic.runId = "foreign-run"; }],
    ["logical-artifact ownership", (document) => { document.extra.coquic.artifacts[0].ownerStepId = 1; }],
  ];

  for (const [label, mutate] of mutations) {
    const candidate = copy(cleanDocument) as unknown as Record<string, any>;
    mutate(candidate);
    const bytes = bytesFor(cleanFixture, candidate as AtifDocument);
    const descriptor = descriptorForBytes(cleanFixture, bytes);
    const result = await tryLoadVerifiedAtif("task-clean", optionsFor(descriptor, responseFor(bytes)));
    assert.deepEqual(result, { ok: false, category: "integrity" }, label);
  }
});
