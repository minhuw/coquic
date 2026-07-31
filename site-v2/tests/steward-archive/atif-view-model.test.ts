import assert from "node:assert/strict";
import { test } from "node:test";
import cleanFixture from "../../../contracts/steward-cloud/fixtures/clean-publication.json";
import {
  buildAtifViewModel,
  type AtifDisplayModel,
  type AtifViewArtifactDescriptor,
} from "@/lib/steward-archive/atif-view-model";
import {
  canonicalAtifBytes,
  validateAtifBytes,
  type AtifDocument,
} from "@/lib/steward-archive/atif";

type MutableRecord = Record<string, any>;
const taskId = "task-clean";
const runId = "run-clean";
const sha = (letter: string) => letter.repeat(64);

function copy<T>(value: T): T {
  return structuredClone(value);
}

function validatedFixtureDocument(document: MutableRecord): AtifDocument {
  const provenance = document.extra.coquic as MutableRecord;
  const localIds = new Set((provenance.artifacts as MutableRecord[]).map((artifact) => artifact.artifactId));
  return validateAtifBytes(canonicalAtifBytes(document), {
    taskId: provenance.taskId,
    pipelineId: provenance.pipelineId,
    runId: provenance.runId,
    role: provenance.role,
    startedAt: provenance.startedAt,
    completedAt: provenance.completedAt,
    durationMs: provenance.durationMs,
    disclosure: provenance.disclosure,
    artifacts: cleanFixture.publication.artifacts.filter((artifact) => localIds.has(artifact.artifactId)),
  });
}

function fixtureDocument(): MutableRecord {
  const document = copy(cleanFixture.atif) as MutableRecord;
  const provenance = document.extra.coquic as MutableRecord;
  provenance.artifacts.push(
    { artifactId: "artifact-jpeg", byteSize: 2, mediaType: "image/jpeg", ownerStepId: 2, sha256: sha("a") },
    { artifactId: "artifact-gif", byteSize: 3, mediaType: "image/gif", ownerStepId: 2, sha256: sha("b") },
    { artifactId: "artifact-webp", byteSize: 4, mediaType: "image/webp", ownerStepId: 2, sha256: sha("c") },
  );
  document.steps[0].source = "system";
  document.steps[0].message = [{ type: "text", text: "System context." }, { type: "future", value: "kept safely" }];
  document.steps[1].reasoning_content = null;
  document.steps[1].model_name = "model-x";
  document.steps[1].reasoning_effort = "medium";
  document.steps[1].metrics = {
    cached_tokens: null,
    completion_tokens: 8,
    cost_usd: null,
    prompt_tokens: 12,
    prompt_token_ids: [1, 2],
    completion_token_ids: null,
    logprobs: null,
    extra: { accepted: true },
  };
  document.steps[1].message = [
    { type: "text", text: "The result is ready." },
    { type: "image", source: { media_type: "image/png", path: "artifact:artifact-plot" } },
    { type: "image", source: { media_type: "image/jpeg", path: "artifact:artifact-jpeg" } },
    { type: "image", source: { media_type: "image/gif", path: "artifact:artifact-gif" } },
    { type: "image", source: { media_type: "image/webp", path: "artifact:artifact-webp" } },
    { type: "image", source: { media_type: "image/png", path: "artifact:artifact-missing" } },
    { type: "future", privateUrl: "https://private.example/not-emitted" },
  ];
  document.steps[1].tool_calls.push({ tool_call_id: "call-2", function_name: "later", arguments: { value: 2 } });
  document.steps.push({
    step_id: 3,
    source: "agent",
    message: "A delayed result.",
    observation: {
      results: [
        { source_call_id: "call-2", content: "late" },
        { source_call_id: "unpaired", content: [{ type: "text", text: null }] },
      ],
    },
  });
  document.final_metrics = {
    total_cached_tokens: null,
    total_completion_tokens: 8,
    total_cost_usd: null,
    total_prompt_tokens: 12,
    total_steps: 3,
  };
  document.notes = null;
  document.session_id = "session-clean";
  document.trajectory_id = "trajectory-clean";
  document.steps[2].observation.results[0].subagent_trajectory_ref = [{ trajectory_id: "child-clean", session_id: null }];
  return document;
}

function descriptor(
  artifactId: string,
  mediaType: string,
  byteSize: number,
  digest: string,
  logicalPath: string,
  extra: Partial<AtifViewArtifactDescriptor> = {},
): AtifViewArtifactDescriptor {
  return {
    artifactId,
    taskId,
    runId,
    mediaType,
    byteSize,
    sha256: digest,
    logicalPath,
    availability: "available",
    disclosure: { originalRetained: true, redactionApplied: false },
    publicKey: `v1/tasks/${taskId}/objects/sha256/${digest.slice(0, 2)}/${digest}`,
    ...extra,
  };
}

function artifacts(): readonly AtifViewArtifactDescriptor[] {
  return [
    descriptor("artifact-plot", "image/png", 12, "77c76d34207ff17daffa279348c3b463de2390ee28f0ec398bc9e59e5a30fc61", "steps/2/plot image.png"),
    descriptor("artifact-log", "text/plain", 8, "32a997e9fad0c2d0f2b7a0885d232524e0c34a0e9525551c361307fb36562462", "steps/2/output.log"),
    descriptor("artifact-jpeg", "image/jpeg", 2, sha("a"), "steps/2/photo.jpg"),
    descriptor("artifact-gif", "image/gif", 3, sha("b"), "steps/2/animation.gif"),
    descriptor("artifact-webp", "image/webp", 4, sha("c"), "steps/2/photo.webp"),
  ];
}

function model(overrides: Partial<MutableRecord> = {}): AtifDisplayModel {
  const document = fixtureDocument();
  Object.assign(document.extra.coquic, overrides);
  return buildAtifViewModel(document as unknown as AtifDocument, { artifacts: artifacts() });
}

function assertNoLocators(value: unknown): void {
  const forbiddenKey = /(?:publicKey|publicUrl|private|secret|credential|password|authorization|scanner|filesystem|filePath|raw|direct|url|uri|endpoint|bucket|objectKey)/i;
  const locator = /(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?):\/\//i;
  const visit = (candidate: unknown): void => {
    if (typeof candidate === "string") {
      assert.equal(locator.test(candidate), false, `locator leaked: ${candidate}`);
      return;
    }
    if (Array.isArray(candidate)) {
      candidate.forEach(visit);
      return;
    }
    if (!candidate || typeof candidate !== "object") return;
    for (const [key, child] of Object.entries(candidate)) {
      assert.equal(forbiddenKey.test(key), false, `unsafe key leaked: ${key}`);
      visit(child);
    }
  };
  visit(value);
}

test("projects roles, content, settings, metrics, lineage, order, and stable anchors", () => {
  const value = model();
  assert.equal(value.kind, "atif-display");
  assert.equal(value.taskId, taskId);
  assert.deepEqual(value.steps.map((step) => step.source), ["system", "agent", "agent"]);
  assert.deepEqual(value.steps.map((step) => step.stepId), [1, 2, 3]);
  assert.deepEqual(value.steps.map((step) => step.anchor), ["step-1", "step-2", "step-3"]);
  assert.equal(value.steps[0]!.content[1]!.kind, "generic");
  assert.equal(value.steps[1]!.reasoning, null);
  assert.equal(value.steps[1]!.modelName, "model-x");
  assert.equal(value.steps[1]!.reasoningEffort, "medium");
  assert.equal(value.steps[1]!.metrics?.promptTokens, 12);
  assert.equal(value.steps[1]!.metrics?.cachedTokens, null);
  assert.equal(value.finalMetrics?.totalSteps, 3);
  assert.equal(value.finalMetrics?.totalCostUsd, null);
  assert.equal(value.notes, null);
  assert.equal(value.sessionId, "session-clean");
  assert.equal(value.lineage.trajectoryId, "trajectory-clean");
  assert.equal(value.lineage.references[0]!.trajectoryId, "child-clean");
  assert.equal(value.lineage.references[0]!.sessionId, null);
  assert.equal(Object.hasOwn(value.steps[0]!, "metrics"), false);
  assertNoLocators(value);
});

test("preserves colliding extension names while filtering recursive object locators", () => {
  const document = fixtureDocument();
  const digest = sha("a");
  document.agent.extra = {
    name: "extension-name-must-survive",
    reference: `v1/tasks/${taskId}/objects/sha256/aa/${digest}`,
    privateReference: `v1/originals/${taskId}/${runId}/sha256/${digest}.jsonl`,
    nested: {
      safeFact: "kept safely",
      publicKey: `v1/tasks/${taskId}/objects/sha256/aa/${digest}`,
      directReference: "https://private.example/object",
    },
  };

  const value = buildAtifViewModel(document as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(value.agent.extensions?.name, "extension-name-must-survive");
  assert.equal(value.agent.extensions?.reference, "[unavailable]");
  assert.equal(Object.hasOwn(value.agent.extensions ?? {}, "privateReference"), false);
  assert.deepEqual(value.agent.extensions?.nested, { safeFact: "kept safely" });
  assertNoLocators(value);
});

test("redacts embedded public and private object keys while retaining safe extension text", () => {
  const document = copy(cleanFixture.atif) as MutableRecord;
  const publicKey = cleanFixture.publication.artifacts.find((artifact) => artifact.artifactId === "artifact-plot")!.publicKey;
  const privateKey = `v1/originals/${taskId}/${runId}/sha256/${sha("b")}.jsonl`;
  document.agent.extra = {
    note: `object key: ${publicKey} remains safe`,
    nested: {
      safeFact: "safe surrounding text",
      details: [`private object key: ${privateKey} remains safe`],
    },
  };

  const value = buildAtifViewModel(validatedFixtureDocument(document), {
    artifacts: artifacts(),
  });
  const serialized = JSON.stringify(value);
  assert.equal(value.agent.extensions?.note, "object key: [unavailable] remains safe");
  assert.deepEqual(value.agent.extensions?.nested, {
    safeFact: "safe surrounding text",
    details: ["private object key: [unavailable] remains safe"],
  });
  assert.equal(serialized.includes(publicKey), false);
  assert.equal(serialized.includes(privateKey), false);
  assert.match(serialized, /object key: \[unavailable\] remains safe/);
  assertNoLocators(value);
});

test("leaves incomplete object-key-shaped extension text intact", () => {
  const document = copy(cleanFixture.atif) as MutableRecord;
  const incompletePublic = `v1/tasks/${taskId}/objects/sha256/aa/${"a".repeat(63)}`;
  const incompletePrivate = `v1/originals/${taskId}/${runId}/sha256/${"b".repeat(63)}.jsonl`;
  document.agent.extra = {
    note: `public ${incompletePublic}; private ${incompletePrivate}`,
  };

  const value = buildAtifViewModel(validatedFixtureDocument(document), {
    artifacts: artifacts(),
  });
  assert.equal(value.agent.extensions?.note, document.agent.extra.note);
});

test("pairs tools by canonical call id while preserving delayed and unpaired results", () => {
  const value = model();
  const calls = value.steps[1]!.calls;
  assert.deepEqual(calls.map((call) => call.callId), ["call-1", "call-2"]);
  assert.equal(calls[0]!.observations[0]!.matchedCallId, "call-1");
  assert.equal(calls[1]!.observations[0]!.matchedCallId, "call-2");
  assert.equal(value.steps[2]!.observation?.results[0]!.matchedCallId, "call-2");
  assert.equal(value.steps[2]!.observation?.results[1]!.matchedCallId, null);
  assert.equal(value.steps[1]!.toolCalls?.[1]!.anchor, "call-call-2");
});

test("keeps absent, null, and empty subagent lineage distinct", () => {
  const nullDocument = fixtureDocument();
  nullDocument.steps[2].observation.results[0].subagent_trajectory_ref = null;
  const nullValue = buildAtifViewModel(nullDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(nullValue.steps[2]!.observation?.results[0]!.lineage, null);

  const emptyDocument = fixtureDocument();
  emptyDocument.steps[2].observation.results[0].subagent_trajectory_ref = [];
  const emptyValue = buildAtifViewModel(emptyDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.deepEqual(emptyValue.steps[2]!.observation?.results[0]!.lineage, []);

  const absentDocument = fixtureDocument();
  delete absentDocument.steps[2].observation.results[0].subagent_trajectory_ref;
  const absentValue = buildAtifViewModel(absentDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(Object.hasOwn(absentValue.steps[2]!.observation?.results[0] ?? {}, "lineage"), false);
});

test("derives valid timing, preserves explicit zero, and never invents missing duration", () => {
  const derivedDocument = fixtureDocument();
  delete derivedDocument.extra.coquic.durationMs;
  const derived = buildAtifViewModel(derivedDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.deepEqual(derived.timing, {
    startedAt: "2026-07-28T00:00:00Z",
    completedAt: "2026-07-28T00:00:01Z",
    durationMs: 1000,
    durationSource: "derived",
  });

  const zeroDocument = fixtureDocument();
  zeroDocument.extra.coquic.durationMs = 0;
  const zero = buildAtifViewModel(zeroDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(zero.timing.durationMs, 0);
  assert.equal(zero.timing.durationSource, "explicit");

  const missingDocument = fixtureDocument();
  delete missingDocument.extra.coquic.durationMs;
  delete missingDocument.extra.coquic.startedAt;
  delete missingDocument.extra.coquic.completedAt;
  const missing = buildAtifViewModel(missingDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(missing.timing.durationMs, null);
  assert.equal(missing.timing.durationSource, "unavailable");
  assert.equal(missing.metadata.durationMs, null);
});

test("derives fractional canonical timestamps once and rejects unsafe deltas", () => {
  const fractionalDocument = fixtureDocument();
  delete fractionalDocument.extra.coquic.durationMs;
  fractionalDocument.extra.coquic.startedAt = "2026-07-28T00:00:00.100Z";
  fractionalDocument.extra.coquic.completedAt = "2026-07-28T00:00:00.400Z";
  const fractional = buildAtifViewModel(fractionalDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(fractional.timing.durationMs, 300);
  assert.equal(fractional.timing.durationSource, "derived");

  const negativeDocument = fixtureDocument();
  delete negativeDocument.extra.coquic.durationMs;
  negativeDocument.extra.coquic.startedAt = "2026-07-28T00:00:00.400Z";
  negativeDocument.extra.coquic.completedAt = "2026-07-28T00:00:00.100Z";
  const negative = buildAtifViewModel(negativeDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(negative.timing.durationMs, null);
  assert.equal(negative.timing.durationSource, "unavailable");

  const subMillisecondDocument = fixtureDocument();
  delete subMillisecondDocument.extra.coquic.durationMs;
  subMillisecondDocument.extra.coquic.startedAt = "2026-07-28T00:00:00.1001Z";
  subMillisecondDocument.extra.coquic.completedAt = "2026-07-28T00:00:00.1004Z";
  const subMillisecond = buildAtifViewModel(subMillisecondDocument as unknown as AtifDocument, { artifacts: artifacts() });
  assert.equal(subMillisecond.timing.durationMs, null);
  assert.equal(subMillisecond.timing.durationSource, "unavailable");
});

test("resolves only same-publication logical actions and records unavailable references", () => {
  const value = model();
  const images = value.steps[1]!.content.filter((item) => item.kind === "image");
  assert.deepEqual(images.slice(0, 4).map((item) => item.kind === "image" ? item.action.kind : null), ["image", "image", "image", "image"]);
  assert.equal(images[1]!.kind, "image");
  if (images[1]!.kind === "image") assert.match(images[1]!.action.kind === "image" ? images[1]!.action.href : "", /path=steps%2F2%2Fphoto/);
  const missing = images[4]!;
  assert.equal(missing.kind, "image");
  if (missing.kind === "image") assert.deepEqual(missing.action, { kind: "unavailable", artifactId: "artifact-missing", reason: "missing" });
  assert.equal(value.artifacts.find((item) => item.artifactId === "artifact-log")!.action.kind, "download");

  const foreign = fixtureDocument();
  const foreignDescriptors = artifacts().map((item) => item.artifactId === "artifact-jpeg" ? { ...item, taskId: "other-task" } : item);
  const foreignValue = buildAtifViewModel(foreign as unknown as AtifDocument, { artifacts: foreignDescriptors });
  const foreignImage = foreignValue.steps[1]!.content.find((item) => item.kind === "image" && item.artifactId === "artifact-jpeg");
  assert.equal(foreignImage?.kind, "image");
  if (foreignImage?.kind === "image") assert.equal(foreignImage.action.kind, "unavailable");
  assertNoLocators(value);
});

test("is deterministic across repeated projection and does not expose descriptor keys", () => {
  const document = fixtureDocument();
  const first = buildAtifViewModel({ document: document as unknown as AtifDocument, artifacts: artifacts() });
  const second = buildAtifViewModel({ document: document as unknown as AtifDocument, artifacts: artifacts() });
  assert.deepEqual(first, second);
  assertNoLocators(first);
  assert.equal(JSON.stringify(first).includes("publicKey"), false);
});
