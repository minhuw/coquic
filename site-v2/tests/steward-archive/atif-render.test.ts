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
