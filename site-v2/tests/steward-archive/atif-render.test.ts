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

test("keeps media evidence inert in the trajectory document", () => {
  const html = render(modelCopy());
  assert.doesNotMatch(html, /<img\b|src=|\bdownload\b/i);
  assert.match(html, /data-artifact-metadata/);
});
