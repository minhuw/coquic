import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import cleanExample from "../../examples/steward-cloud/complete-trajectory-clean.json";
import {
  AtifTrajectoryView,
} from "../../app/steward/tasks/[taskId]/atif-trajectory-view";
import type { AtifDisplayModel } from "../../lib/steward-archive/atif-view-model";

const sourceModel = cleanExample.data as unknown as AtifDisplayModel;

function modelCopy(): AtifDisplayModel {
  return structuredClone(sourceModel);
}

function render(model: AtifDisplayModel): string {
  return renderToStaticMarkup(createElement(AtifTrajectoryView, { model, anchorPrefix: "test" }));
}

function textPart(text: string) {
  return { kind: "text" as const, type: "text" as const, text };
}

const imageMediaTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"] as const;

function imageDescriptor(model: AtifDisplayModel, artifactId: string, mediaType: string, index: number) {
  const logicalPath = `steps/2/evidence-${index}.${mediaType.slice("image/".length)}`;
  return {
    artifactId,
    mediaType,
    sha256: String(index).repeat(64),
    byteSize: index * 10,
    ownerStepId: 2,
    action: {
      kind: "image" as const,
      artifactId,
      taskId: model.taskId,
      runId: model.runId,
      mediaType,
      logicalPath,
      href: `/api/steward/tasks/${model.taskId}/artifact?path=${encodeURIComponent(logicalPath)}`,
    },
  };
}

function setDisclosure(model: AtifDisplayModel, redactionApplied: boolean, originalRetained: boolean) {
  const disclosure = { redactionApplied, originalRetained };
  (model as any).disclosure = disclosure;
  (model.metadata as any).disclosure = disclosure;
}

test("renders typed records in source order with safe Markdown and stable anchors", () => {
  const model = modelCopy();
  const first = model.steps[0] as any;
  const text = "System **context** [safe](https://example.com) [blocked](javascript:alert(1)) <b>ignored</b>";
  const generic = { kind: "generic" as const, type: "generic" as const, record: { detail: "safe block", count: 2 } };
  first.source = "system";
  first.role = "system";
  first.message = [textPart(text), generic];
  first.parts = [textPart(text), generic];
  first.content = first.parts;

  const html = render(model);
  assert.match(html, /data-atif-trajectory/);
  assert.match(html, /id="test-event-step-1"/);
  assert.match(html, /id="test-event-step-2"/);
  assert.ok(html.indexOf('data-step-source="system"') < html.indexOf('data-step-source="agent"'));
  assert.match(html, /href="https:\/\/example\.com\/" target="_blank" rel="noreferrer"/);
  assert.doesNotMatch(html, /javascript:/i);
  assert.doesNotMatch(html, /<b>ignored<\/b>/);
  assert.match(html, /data-blocked-link/);
  assert.match(html, /data-generic-content/);
  assert.match(html, /System <strong>context<\/strong>/);
  assert.doesNotMatch(html, /load more|revision|raw JSONL|prefix/i);
  assert.equal((html.match(/data-step-source=/g) ?? []).length, model.steps.length);
});

test("renders every tool result, opens failed tools, and exposes metrics and lineage facts", () => {
  const model = modelCopy();
  const step = model.steps[1] as any;
  step.calls[0].extensions = { status: "failed", durationMs: 12 };
  step.tools = step.calls;
  step.observations = [
    ...step.observations,
    {
      content: "Unpaired operation result",
      parts: [textPart("Unpaired operation result")],
      matchedCallId: null,
      sourceCallId: null,
      extensions: null,
      lineage: null,
    },
  ];
  step.reasoning = "Internal reasoning remains collapsed.";
  (model.lineage as any).references = [{ trajectoryId: "child-trajectory", sessionId: null, extensions: null }];

  const html = render(model);
  assert.match(html, /data-tool-call="call-1"[^>]*data-tool-status="failed"[^>]*open=""/);
  assert.match(html, /Inspection complete\./);
  assert.match(html, /Unpaired operation result/);
  assert.match(html, /data-reasoning/);
  assert.doesNotMatch(html, /data-reasoning[^>]*open=""/);
  assert.match(html, /Cached tokens/);
  assert.match(html, /Unavailable/);
  assert.match(html, /child-trajectory/);
  assert.match(html, /Observation lineage|Lineage/);
  assert.match(html, /12 ms/);
});

test("renders an empty validated run as completed without progressive controls", () => {
  const model = modelCopy();
  (model as any).steps = [];
  (model as any).finalMetrics = null;

  const html = render(model);
  assert.match(html, /data-empty-run/);
  assert.match(html, /Completed empty run/);
  assert.match(html, /No trajectory records were published\./);
  assert.match(html, /Trajectory records/);
  assert.doesNotMatch(html, /data-step-source=/);
  assert.doesNotMatch(html, /load more|virtual|pagination/i);
});

test("keeps paired observations in source-record order and associated with their call", () => {
  const model = modelCopy() as any;
  const observation = {
    content: "F001-order-sentinel",
    parts: [textPart("F001-order-sentinel")],
    matchedCallId: "call-order",
    sourceCallId: "call-order",
    extensions: null,
    lineage: null,
  };
  const call = {
    anchor: "call-order",
    callId: "call-order",
    id: "call-order",
    functionName: "inspect",
    arguments: {},
    observations: [observation],
  };
  const owner = structuredClone(model.steps[1]);
  owner.stepId = 3;
  owner.id = "step-3";
  owner.anchor = "step-3";
  owner.message = "F001-owner-record";
  owner.content = [textPart("F001-owner-record")];
  owner.parts = owner.content;
  owner.calls = [];
  owner.tools = [];
  owner.observations = [observation];
  owner.observation = { results: [observation] };
  model.steps[1].calls = [call];
  model.steps[1].tools = [call];
  model.steps = [model.steps[0], model.steps[1], owner];

  const html = render(model);
  assert.ok(html.indexOf("F001-order-sentinel") > html.indexOf("F001-owner-record"));
  assert.equal((html.match(/F001-order-sentinel/g) ?? []).length, 1);
  assert.match(html, /data-paired="true"/);
  assert.match(html, /data-tool-observation-association="call-order"/);
});

test("renders safe run facts and recursively bounded child trajectories", () => {
  const model = modelCopy() as any;
  model.agent.toolDefinitions = [{ sentinel: "F002-tool-definition" }];
  model.agent.extensions = { sentinel: "F002-agent-extension" };
  model.metadata.extensions = { sentinel: "F002-metadata-extension" };
  model.extensions = { sentinel: "F002-model-extension" };
  model.notes = "F002-notes";
  const child = structuredClone(model);
  child.trajectoryId = "child-f002";
  child.steps = [structuredClone(model.steps[0])];
  child.steps[0].message = "F002-child-record";
  child.steps[0].content = [textPart("F002-child-record")];
  child.steps[0].parts = child.steps[0].content;
  child.lineage = { trajectoryId: "child-f002", sessionId: null, references: [], trajectories: [] };
  model.lineage.trajectories = [child];

  const html = render(model);
  for (const sentinel of [
    "F002-tool-definition",
    "F002-agent-extension",
    "F002-metadata-extension",
    "F002-model-extension",
    "F002-notes",
    "F002-child-record",
  ]) assert.match(html, new RegExp(sentinel));
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length);
});

test("renders supported image evidence in a stable frame with an unchanged download action", () => {
  const model = modelCopy() as any;
  setDisclosure(model, false, false);
  const imageParts = imageMediaTypes.map((mediaType, index) => {
    const artifactId = `artifact-image-${index + 1}`;
    const descriptor = imageDescriptor(model, artifactId, mediaType, index + 1);
    return { descriptor, part: { kind: "image" as const, type: "image" as const, mediaType, artifactId, action: descriptor.action } };
  });
  model.artifacts = [model.artifacts[0], ...imageParts.map(({ descriptor }) => descriptor)];
  model.metadata.artifacts = model.artifacts;
  model.steps[1].parts = [textPart("Four image formats."), ...imageParts.map(({ part }) => part)];
  model.steps[1].content = model.steps[1].parts;
  model.steps[1].message = model.steps[1].parts;

  const html = render(model);
  assert.equal((html.match(/data-artifact-image/g) ?? []).length, imageMediaTypes.length * 2);
  assert.equal((html.match(/data-artifact-frame/g) ?? []).length, imageMediaTypes.length * 2);
  assert.match(html, /object-contain/);
  assert.match(html, /data-artifact-error/);
  assert.match(html, /data-artifact-download/);
  assert.doesNotMatch(html, /_next\/image|publicKey|logicalPath/);
  for (const mediaType of imageMediaTypes) {
    assert.match(html, new RegExp(`alt="${mediaType} evidence`));
  }
  const artifactLinks = [...html.matchAll(/(?:src|href)="([^\"]*\/api\/steward\/tasks\/[^\"]*artifact[^\"]*)"/g)].map((match) => match[1]);
  assert.ok(artifactLinks.length >= imageMediaTypes.length * 2);
  assert.ok(artifactLinks.every((href) => href.startsWith("/api/steward/tasks/")));
});

test("renders compact downloads and explicit unavailable media fallbacks", () => {
  const model = modelCopy() as any;
  const missing = { kind: "image" as const, type: "image" as const, mediaType: "image/jpeg" as const, artifactId: "artifact-missing", action: { kind: "unavailable" as const, artifactId: "artifact-missing", reason: "missing" as const } };
  model.steps[1].parts = [...model.steps[1].parts, missing];
  model.steps[1].content = model.steps[1].parts;
  model.steps[1].message = model.steps[1].parts;

  const html = render(model);
  assert.match(html, /data-artifact-download-row/);
  assert.match(html, /text\/plain evidence.*8 B/);
  assert.match(html, /data-artifact-download-unavailable/);
  assert.match(html, /image\/jpeg evidence.*unavailable \(missing\)/);
  const unavailable = html.match(/<div data-artifact-unavailable[\s\S]*?<\/div>/)?.[0] ?? "";
  assert.doesNotMatch(unavailable, /href=|src=/);
});

test("shows all disclosure states without private affordances", () => {
  const cases = [
    { redactionApplied: false, originalRetained: false, text: "Original not retained", absent: false },
    { redactionApplied: true, originalRetained: false, text: "Public values redacted", absent: false },
    { redactionApplied: false, originalRetained: true, text: "Original retained", absent: false },
    { redactionApplied: true, originalRetained: true, text: "Original retained", absent: false },
  ] as const;

  for (const disclosure of cases) {
    const model = modelCopy();
    setDisclosure(model, disclosure.redactionApplied, disclosure.originalRetained);
    const html = render(model);
    if (disclosure.absent) {
      assert.doesNotMatch(html, /data-disclosure/);
      continue;
    }
    const summary = html.match(/<p data-disclosure[\s\S]*?<\/p>/)?.[0] ?? "";
    assert.match(summary, new RegExp(disclosure.text));
    if (!disclosure.redactionApplied) assert.doesNotMatch(summary, /text-warning/);
    assert.doesNotMatch(summary, /href=|src=|private|bucket|key|url|path|raw|filesystem|credential|secret|token|https?:/i);
  }
});
