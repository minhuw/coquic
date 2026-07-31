import assert from "node:assert/strict";
import { test } from "node:test";
import cleanFixture from "../../../contracts/steward-cloud/fixtures/clean-publication.json";
import redactedFixture from "../../../contracts/steward-cloud/fixtures/redacted-publication.json";
import {
  ATIF_VERSION,
  AtifValidationError,
  canonicalAtifBytes,
  isValidAtifBytes,
  tryValidateAtifBytes,
  validateAtifBytes,
  type AtifDocument,
  type AtifPublicationArtifactDescriptor,
  type AtifValidationOptions,
} from "@/lib/steward-archive/atif";

type Fixture = typeof cleanFixture;

function copy<T>(value: T): T {
  return structuredClone(value);
}

function atif(fixture: Fixture): AtifDocument {
  return copy(fixture.atif) as unknown as AtifDocument;
}

function options(
  document: AtifDocument,
  published: readonly AtifPublicationArtifactDescriptor[] = cleanFixture.publication.artifacts,
): AtifValidationOptions {
  const coqui = (document.extra as Record<string, any>).coquic;
  const localIds = new Set(coqui.artifacts.map((artifact: any) => artifact.artifactId));
  return {
    taskId: coqui.taskId,
    pipelineId: coqui.pipelineId,
    runId: coqui.runId,
    role: coqui.role,
    startedAt: coqui.startedAt,
    completedAt: coqui.completedAt,
    durationMs: coqui.durationMs,
    disclosure: coqui.disclosure,
    artifacts: published.filter((artifact) => localIds.has(artifact.artifactId)),
  };
}

function validBytes(document: AtifDocument): Uint8Array {
  return canonicalAtifBytes(document);
}

function assertRule(source: Uint8Array, expected: AtifValidationOptions, rule: string): void {
  assert.throws(() => validateAtifBytes(source, expected), (error: unknown) => {
    assert.ok(error instanceof AtifValidationError);
    assert.ok(error.issues.some((issue) => issue.rule === rule));
    return true;
  });
}

test("accepts canonical clean and redacted complete trajectories", () => {
  for (const fixture of [cleanFixture, redactedFixture]) {
    const document = atif(fixture);
    const result = validateAtifBytes(
      validBytes(document),
      options(document, fixture.publication.artifacts),
    );
    assert.equal(result.schema_version, ATIF_VERSION);
    assert.equal(
      isValidAtifBytes(
        validBytes(document),
        options(document, fixture.publication.artifacts),
      ),
      true,
    );
  }
});

test("accepts a complete text-only trajectory with no artifacts", () => {
  const document = atif(cleanFixture);
  const coqui = (document.extra as Record<string, any>).coquic;
  coqui.artifacts = [];
  coqui.disclosure = { redactionApplied: false, originalRetained: true };
  const step = document.steps[1] as Record<string, any>;
  step.message = [{ type: "text", text: "Only text remains." }];
  step.extra = { coquic: { artifactIds: [] } };
  const expected = options(document);
  (expected as any).artifacts = [];
  assert.equal(validateAtifBytes(validBytes(document), expected).steps.length, 2);
});

test("rejects noncanonical, duplicate-key, malformed, and invalid UTF-8 input", () => {
  const document = atif(cleanFixture);
  const expected = options(document);
  assertRule(new TextEncoder().encode(JSON.stringify(document)), expected, "canonicalization");
  assertRule(new TextEncoder().encode('{"agent":{},"agent":{}}'), expected, "canonicalization");
  assertRule(new TextEncoder().encode('{"agent":'), expected, "canonicalization");
  assertRule(new Uint8Array([0xff, 0xfe, 0xfd]), expected, "canonicalization");
});

test("accepts oracle-canonical floating-point lexemes without lossy reserialization", () => {
  const document = atif(cleanFixture) as Record<string, any>;
  document.final_metrics = { total_cost_usd: 1 };
  const expected = options(document as AtifDocument);
  const serialized = new TextDecoder().decode(validBytes(document as AtifDocument));
  assert.ok(serialized.includes('"total_cost_usd":1'));
  const bytesWith = (number: string) => new TextEncoder().encode(
    serialized.replace('"total_cost_usd":1', `"total_cost_usd":${number}`),
  );

  for (const number of [
    "1.0",
    "-0.0",
    "1e+20",
    "1e-07",
    "0.0001",
    "1000000000000000.0",
    "1.2345678901234567",
  ]) {
    assert.equal(validateAtifBytes(bytesWith(number), expected).schema_version, ATIF_VERSION);
  }
  for (const number of ["1.00", "1e0", "1E+20", "1e-7", "0.00010", "-0"]) {
    assertRule(bytesWith(number), expected, "canonicalization");
  }
});

test("accepts bounded large integer lexemes without losing their digits", () => {
  const document = atif(cleanFixture) as Record<string, any>;
  document.final_metrics = { total_cost_usd: 1 };
  const expected = options(document as AtifDocument);
  const baseline = new TextDecoder().decode(validBytes(document as AtifDocument));
  const digits = "9".repeat(310);
  const source = new TextEncoder().encode(
    baseline.replace(/("total_cost_usd":)1/, `$1${digits}`),
  );

  const result = tryValidateAtifBytes(source, expected);
  assert.equal(result.ok, true);
  if (result.ok) {
    const parsed = (result.value as Record<string, any>).final_metrics.total_cost_usd;
    assert.equal(typeof parsed, "bigint");
    assert.equal(parsed.toString(), digits);
    assert.deepEqual(validBytes(result.value), source);
  }
});

test("rejects schema mutations and wrong ATIF version", () => {
  const document = atif(cleanFixture);
  const expected = options(document);
  const unknown = copy(document) as Record<string, any>;
  unknown.unknown = "value";
  assertRule(validBytes(unknown as AtifDocument), expected, "schema-additionalProperties");
  const wrongVersion = copy(document) as any;
  wrongVersion.schema_version = "ATIF-v1.6";
  assertRule(validBytes(wrongVersion), expected, "root-schema-version");
  const partial = copy(document) as any;
  partial.continued_trajectory_ref = "continuation";
  assertRule(validBytes(partial), expected, "partial-run");
});

test("enforces contiguous steps, unique calls, and local observation references", () => {
  const base = atif(cleanFixture);
  const expected = options(base);
  const sequence = copy(base) as any;
  sequence.steps[1].step_id = 3;
  assertRule(validBytes(sequence), expected, "step-sequence");
  const duplicate = copy(base) as any;
  (duplicate.steps[0] as any).tool_calls = [{ tool_call_id: "call-1", function_name: "other", arguments: {} }];
  assertRule(validBytes(duplicate), expected, "tool-call-unique");
  const dangling = copy(base) as any;
  (dangling.steps[1] as any).observation.results[0].source_call_id = "missing-call";
  assertRule(validBytes(dangling), expected, "observation-reference");
});

test("enforces provenance ownership, timing, and exact disclosure", () => {
  const base = atif(cleanFixture);
  const expected = options(base);
  const wrongOwner = copy(base);
  (wrongOwner.extra as any).coquic.taskId = "other-task";
  assertRule(validBytes(wrongOwner), expected, "ownership");
  const backwards = copy(base);
  (backwards.extra as any).coquic.completedAt = "2026-07-27T00:00:01Z";
  assertRule(validBytes(backwards), expected, "timing-order");
  const invalidCalendar = copy(base);
  (invalidCalendar.extra as any).coquic.startedAt = "2026-02-30T00:00:00Z";
  assertRule(validBytes(invalidCalendar), options(invalidCalendar), "timing");
  const extraDisclosure = copy(base);
  (extraDisclosure.extra as any).coquic.disclosure.extra = false;
  assertRule(validBytes(extraDisclosure), expected, "disclosure");
  const missingProvenance = copy(base);
  delete (missingProvenance.extra as any).coquic.runId;
  assertRule(validBytes(missingProvenance), expected, "provenance-field");
});

test("resolves owned artifact references and supported image media", () => {
  const base = atif(cleanFixture);
  const expected = options(base);
  const dangling = copy(base);
  (dangling.steps[1] as any).extra.coquic.artifactIds = ["missing"];
  assertRule(validBytes(dangling), expected, "artifact-reference");
  const owner = copy(base);
  (owner.extra as any).coquic.artifacts[0].ownerStepId = 1;
  assertRule(validBytes(owner), options(owner), "artifact-owner");
  const unsupported = copy(base);
  (unsupported.steps[1] as any).message[1].source.media_type = "image/svg+xml";
  assertRule(validBytes(unsupported), options(unsupported), "media-type");
  const arbitraryUrl = copy(base);
  (arbitraryUrl.steps[1] as any).message[1].source.path = "https://private.example/image.png";
  assertRule(validBytes(arbitraryUrl), options(arbitraryUrl), "private-locator");
  const unreferenced = copy(base);
  (unreferenced.steps[1] as any).extra.coquic.artifactIds = ["artifact-log"];
  (unreferenced.steps[1] as any).message = "The image was removed.";
  assertRule(validBytes(unreferenced), options(unreferenced), "artifact-unreferenced");
});

test("checks publication artifact task and run ownership independently", () => {
  const document = atif(cleanFixture);
  const expected = options(document);
  assert.ok(
    (expected.artifacts as readonly AtifPublicationArtifactDescriptor[]).every(
      (artifact) => artifact.ownerStepId === undefined,
    ),
  );
  assert.equal(validateAtifBytes(validBytes(document), expected).schema_version, ATIF_VERSION);

  const foreignTask = (expected.artifacts as readonly AtifPublicationArtifactDescriptor[])
    .map((artifact) => ({ ...artifact, taskId: "other-task" }));
  assertRule(validBytes(document), { ...expected, artifacts: foreignTask }, "artifact-ownership");
  const foreignRun = (expected.artifacts as readonly AtifPublicationArtifactDescriptor[])
    .map((artifact) => ({ ...artifact, runId: "other-run" }));
  assertRule(validBytes(document), { ...expected, artifacts: foreignRun }, "artifact-ownership");
});

test("denies recursive private-shaped fields without echoing values", () => {
  const base = atif(cleanFixture);
  const candidate = copy(base);
  const secret = "super-secret-value-9f2e";
  (candidate.steps[0] as any).extra = { safe: { credentialPath: secret } };
  let error: AtifValidationError | undefined;
  try {
    validateAtifBytes(validBytes(candidate), options(candidate));
  } catch (caught) {
    error = caught instanceof AtifValidationError ? caught : undefined;
  }
  assert.ok(error);
  assert.ok(error.issues.some((issue) => issue.rule === "private-field"));
  assert.ok(error.issues.every((issue) => !issue.path.includes(secret)));
  assert.ok(!error.message.includes(secret));
});

test("generalizes private-shaped extension names in every diagnostic field", () => {
  const candidate = atif(cleanFixture);
  const marker = "accessToken-super-secret-9f2e";
  (candidate.agent as Record<string, unknown>)[marker] = "safe-extension-value";
  const result = tryValidateAtifBytes(validBytes(candidate), options(candidate));

  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.ok(result.issues.some((issue) => issue.rule === "private-field"));
    assert.ok(!JSON.stringify(result.issues).includes(marker));
    assert.ok(result.issues.every((issue) => !issue.segments.includes(marker)));
  }
});

test("masks candidate-controlled private ancestors in diagnostics", () => {
  const candidate = atif(cleanFixture) as Record<string, any>;
  const secretName = "sk_live_51_opaque_9f2e";
  const secretValue = "opaque-secret-value-9f2e";
  candidate.agent.extra = { [secretName]: { accessToken: secretValue } };
  const result = tryValidateAtifBytes(validBytes(candidate as AtifDocument), options(candidate as AtifDocument));

  assert.equal(result.ok, false);
  if (!result.ok) {
    const serialized = JSON.stringify(result.issues);
    assert.ok(!serialized.includes(secretName));
    assert.ok(!serialized.includes(secretValue));
    assert.ok(result.issues.every((issue) => !issue.segments.includes(secretName)));
  }
});

test("resolves embedded trajectory IDs and rejects external paths", () => {
  const base = atif(cleanFixture);
  const child = copy(base) as any;
  child.trajectory_id = "child-1";
  (child.extra as any).coquic.taskId = "child-task";
  (child.extra as any).coquic.pipelineId = "child-pipeline";
  (child.extra as any).coquic.runId = "child-run";
  (child.extra as any).coquic.artifacts = [];
  (child.steps[1] as any).message = "Child text.";
  (child.steps[1] as any).extra = { coquic: { artifactIds: [] } };
  const parent = copy(base);
  (parent as any).subagent_trajectories = [child];
  (parent.steps[1] as any).observation.results[0].subagent_trajectory_ref = [{ trajectory_id: "child-1" }];
  const parentOptions = options(parent);
  assert.equal(validateAtifBytes(validBytes(parent), parentOptions).schema_version, ATIF_VERSION);
  const external = copy(parent);
  (external.steps[1] as any).observation.results[0].subagent_trajectory_ref = [{ trajectory_path: "/private/child.json" }];
  assertRule(validBytes(external), options(external), "private-locator");
});

test("returns deterministic value-free result diagnostics", () => {
  const document = atif(cleanFixture);
  const expected = options(document);
  (document.extra as any).coquic.taskId = "other-task";
  const result = tryValidateAtifBytes(validBytes(document), expected);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.ok(result.issues.every((issue) => issue.code === issue.rule && issue.path.startsWith("$")));
    assert.deepEqual(result.issues, [...result.issues].sort((a, b) => a.path.localeCompare(b.path) || a.rule.localeCompare(b.rule)));
  }
});
