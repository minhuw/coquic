import {
  SUPPORTED_IMAGE_MEDIA_TYPES,
  type AtifDocument,
  type AtifDisclosure,
  type AtifImageMediaType,
} from "./atif";

/**
 * This module consumes a document that has already passed ATIF validation.
 * It does not retain the input document and never emits a locator supplied by
 * ATIF or by the publication repository.
 */

export type AtifDisplayScalar = string | number | boolean | null;
export type AtifSafeValue = AtifDisplayScalar | readonly AtifSafeValue[] | AtifSafeRecord;
export interface AtifSafeRecord {
  readonly [key: string]: AtifSafeValue;
}

export interface AtifViewArtifactDescriptor {
  readonly artifactId: string;
  readonly taskId: string;
  readonly runId: string;
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly logicalPath?: string;
  /** Accepted as input only. It is deliberately absent from display output. */
  readonly publicKey?: string;
  readonly availability?: "available" | "unavailable";
  readonly disclosure?: AtifDisclosure;
}

export type AtifViewArtifactCollection =
  | readonly AtifViewArtifactDescriptor[]
  | ReadonlyMap<string, AtifViewArtifactDescriptor>
  | Readonly<Record<string, AtifViewArtifactDescriptor>>;

export interface AtifViewModelOptions {
  readonly artifacts?: AtifViewArtifactCollection;
  readonly artifactMap?: AtifViewArtifactCollection;
  readonly taskId?: string;
  readonly runId?: string;
}

export interface AtifViewModelInput extends AtifViewModelOptions {
  readonly document: AtifDocument;
}

export interface AtifDisplayTiming {
  readonly startedAt?: string | null;
  readonly completedAt?: string | null;
  readonly durationMs: number | null;
  readonly durationSource: "explicit" | "derived" | "unavailable";
}

export interface AtifDisplayMetrics {
  readonly cachedTokens?: number | string | null;
  readonly promptTokens?: number | string | null;
  readonly completionTokens?: number | string | null;
  readonly costUsd?: number | string | null;
  readonly promptTokenIds?: readonly (number | string)[] | null;
  readonly completionTokenIds?: readonly (number | string)[] | null;
  readonly logprobs?: readonly (number | string)[] | null;
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayFinalMetrics {
  readonly totalSteps?: number | string | null;
  readonly totalPromptTokens?: number | string | null;
  readonly totalCompletionTokens?: number | string | null;
  readonly totalCachedTokens?: number | string | null;
  readonly totalCostUsd?: number | string | null;
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayAgent {
  readonly name: string;
  readonly version: string;
  readonly modelName?: string | null;
  readonly toolDefinitions?: AtifSafeValue[] | null;
  readonly extensions?: AtifSafeRecord | null;
}

export type AtifArtifactUnavailableReason =
  | "missing"
  | "ownership-mismatch"
  | "descriptor-mismatch"
  | "unavailable"
  | "missing-logical-path"
  | "invalid-logical-path";

export interface AtifUnavailableArtifact {
  readonly kind: "unavailable";
  readonly artifactId: string | null;
  readonly reason: AtifArtifactUnavailableReason;
}

export interface AtifLogicalArtifactAction {
  readonly kind: "image" | "download";
  readonly artifactId: string;
  readonly taskId: string;
  readonly runId: string;
  readonly mediaType: string;
  readonly logicalPath: string;
  readonly href: string;
}

export type AtifArtifactAction = AtifLogicalArtifactAction | AtifUnavailableArtifact;

export interface AtifDisplayArtifact {
  readonly artifactId: string;
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly ownerStepId: number;
  readonly action: AtifArtifactAction;
  readonly disclosure?: AtifDisclosure;
}

export interface AtifTextContent {
  readonly kind: "text";
  readonly type: "text";
  readonly text: string | null;
}

export interface AtifImageContent {
  readonly kind: "image";
  readonly type: "image";
  readonly mediaType: AtifImageMediaType;
  readonly artifactId: string | null;
  readonly action: AtifArtifactAction;
}

export interface AtifGenericContent {
  readonly kind: "generic";
  readonly type: "generic";
  readonly record: AtifSafeRecord;
}

export type AtifDisplayContent = AtifTextContent | AtifImageContent | AtifGenericContent;
export type AtifDisplayContentValue = string | null | undefined | readonly AtifDisplayContent[];

export interface AtifDisplayObservation {
  readonly content: AtifDisplayContentValue | undefined;
  readonly parts: readonly AtifDisplayContent[];
  readonly sourceCallId?: string | null;
  readonly matchedCallId: string | null;
  readonly extensions?: AtifSafeRecord | null;
  readonly lineage?: readonly AtifDisplayLineageReference[] | null;
}

export interface AtifDisplayToolCall {
  readonly anchor: string;
  readonly callId: string;
  readonly id: string;
  readonly functionName: string;
  readonly arguments: AtifSafeRecord;
  readonly observations: readonly AtifDisplayObservation[];
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayStep {
  readonly id: string;
  readonly anchor: string;
  readonly stepId: number;
  readonly source: "system" | "user" | "agent";
  readonly role: "system" | "user" | "agent";
  readonly message: AtifDisplayContentValue;
  readonly content: readonly AtifDisplayContent[];
  readonly parts: readonly AtifDisplayContent[];
  readonly timestamp?: string | null;
  readonly reasoning?: string | null;
  readonly modelName?: string | null;
  readonly reasoningEffort?: string | number | null;
  readonly copiedContext?: boolean | null;
  readonly llmCallCount?: number | null;
  readonly metrics?: AtifDisplayMetrics | null;
  readonly toolCalls?: readonly AtifDisplayToolCall[] | null;
  readonly calls: readonly AtifDisplayToolCall[];
  readonly tools: readonly AtifDisplayToolCall[];
  readonly observation?: {
    readonly results: readonly AtifDisplayObservation[];
  } | null;
  readonly observations: readonly AtifDisplayObservation[];
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayLineageReference {
  readonly trajectoryId?: string | null;
  readonly sessionId?: string | null;
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayLineage {
  readonly trajectoryId?: string | null;
  readonly sessionId?: string | null;
  readonly references: readonly AtifDisplayLineageReference[];
  readonly trajectories: readonly AtifDisplayModel[];
}

export interface AtifDisplayMetadata {
  readonly taskId: string;
  readonly pipelineId: string;
  readonly runId: string;
  readonly role: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number | null;
  readonly timing: AtifDisplayTiming;
  readonly disclosure: AtifDisclosure;
  readonly artifacts: readonly AtifDisplayArtifact[];
  readonly extensions?: AtifSafeRecord | null;
}

export interface AtifDisplayModel {
  readonly kind: "atif-display";
  readonly schemaVersion: string;
  readonly agent: AtifDisplayAgent;
  readonly metadata: AtifDisplayMetadata;
  readonly taskId: string;
  readonly pipelineId: string;
  readonly runId: string;
  readonly role: string;
  readonly timing: AtifDisplayTiming;
  readonly disclosure: AtifDisclosure;
  readonly steps: readonly AtifDisplayStep[];
  readonly finalMetrics?: AtifDisplayFinalMetrics | null;
  readonly notes?: string | null;
  readonly sessionId?: string | null;
  readonly trajectoryId?: string | null;
  readonly lineage: AtifDisplayLineage;
  readonly artifacts: readonly AtifDisplayArtifact[];
  readonly extensions?: AtifSafeRecord | null;
}

interface RawRecord {
  readonly [key: string]: unknown;
}

interface CallEntry {
  readonly callId: string;
  readonly stepId: number;
  readonly index: number;
  readonly value: RawRecord;
  readonly observations: RawRecord[];
}

interface ProjectionContext {
  readonly artifacts: ReadonlyMap<string, AtifViewArtifactDescriptor>;
  readonly taskId: string;
  readonly runId: string;
  readonly provenance: RawRecord;
  readonly localArtifacts: ReadonlyMap<string, RawRecord>;
  readonly anchors: Set<string>;
  readonly selectionValid: boolean;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
const LOCATOR = /(?:[a-z][a-z0-9+.-]*:\/\/|^(?:~[/\\]|\/{1}|[A-Za-z]:[/\\]|\\\\))/i;
const UNSAFE_KEY = /(?:url|uri|endpoint|bucket|objectkey|publickey|private|secret|credential|password|token|authorization|scanner|filesystem|filepath|raw|direct)/i;

function isRecord(value: unknown): value is RawRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function has(value: RawRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function safeClone(value: unknown, depth = 0): AtifSafeValue | undefined {
  if (depth > 32) return "[unavailable]";
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "bigint") return value.toString(10);
  if (typeof value === "string") return LOCATOR.test(value) ? "[unavailable]" : value;
  if (Array.isArray(value)) return value.map((item) => safeClone(item, depth + 1) ?? "[unavailable]");
  if (!isRecord(value)) return undefined;
  const result: Record<string, AtifSafeValue> = {};
  for (const [key, child] of Object.entries(value)) {
    if (UNSAFE_KEY.test(key) && key !== "logicalPath") continue;
    const safe = safeClone(child, depth + 1);
    if (safe !== undefined) result[key] = safe;
  }
  return result;
}

function safeRecord(value: unknown): AtifSafeRecord {
  const safe = safeClone(value);
  return isRecord(safe) ? safe : {};
}

function optionalString(value: RawRecord, key: string): string | null | undefined {
  if (!has(value, key)) return undefined;
  const candidate = value[key];
  return candidate === null ? null : typeof candidate === "string" ? candidate : undefined;
}

function optionalNumber(value: RawRecord, key: string): number | string | null | undefined {
  if (!has(value, key)) return undefined;
  const candidate = value[key];
  if (candidate === null || typeof candidate === "number") return candidate;
  return typeof candidate === "bigint" ? candidate.toString(10) : undefined;
}

function optionalNumericArray(value: RawRecord, key: string): readonly (number | string)[] | null | undefined {
  if (!has(value, key)) return undefined;
  const candidate = value[key];
  if (candidate === null) return null;
  if (!Array.isArray(candidate)) return undefined;
  return candidate.map((item) => typeof item === "bigint" ? item.toString(10) : item).filter((item): item is number | string => typeof item === "number" || typeof item === "string");
}

function extensionRecord(value: RawRecord, known: readonly string[]): AtifSafeRecord | null | undefined {
  if (!has(value, "extra")) return undefined;
  const extra = value.extra;
  if (extra === null) return null;
  if (!isRecord(extra)) return {};
  const unknown: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(extra)) if (!known.includes(key)) unknown[key] = child;
  return safeRecord(unknown);
}

function mapMetrics(value: unknown): AtifDisplayMetrics | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (!isRecord(value)) return { extensions: {} };
  const result: Record<string, unknown> = {};
  if (has(value, "cached_tokens")) result.cachedTokens = optionalNumber(value, "cached_tokens");
  if (has(value, "prompt_tokens")) result.promptTokens = optionalNumber(value, "prompt_tokens");
  if (has(value, "completion_tokens")) result.completionTokens = optionalNumber(value, "completion_tokens");
  if (has(value, "cost_usd")) result.costUsd = optionalNumber(value, "cost_usd");
  if (has(value, "prompt_token_ids")) result.promptTokenIds = optionalNumericArray(value, "prompt_token_ids");
  if (has(value, "completion_token_ids")) result.completionTokenIds = optionalNumericArray(value, "completion_token_ids");
  if (has(value, "logprobs")) result.logprobs = optionalNumericArray(value, "logprobs");
  const extensions = extensionRecord(value, ["cached_tokens", "prompt_tokens", "completion_tokens", "cost_usd", "prompt_token_ids", "completion_token_ids", "logprobs"]);
  if (extensions !== undefined) result.extensions = extensions;
  return result as AtifDisplayMetrics;
}

function mapFinalMetrics(value: unknown): AtifDisplayFinalMetrics | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (!isRecord(value)) return { extensions: {} };
  const result: Record<string, unknown> = {};
  if (has(value, "total_steps")) result.totalSteps = optionalNumber(value, "total_steps");
  if (has(value, "total_prompt_tokens")) result.totalPromptTokens = optionalNumber(value, "total_prompt_tokens");
  if (has(value, "total_completion_tokens")) result.totalCompletionTokens = optionalNumber(value, "total_completion_tokens");
  if (has(value, "total_cached_tokens")) result.totalCachedTokens = optionalNumber(value, "total_cached_tokens");
  if (has(value, "total_cost_usd")) result.totalCostUsd = optionalNumber(value, "total_cost_usd");
  const extensions = extensionRecord(value, ["total_steps", "total_prompt_tokens", "total_completion_tokens", "total_cached_tokens", "total_cost_usd"]);
  if (extensions !== undefined) result.extensions = extensions;
  return result as AtifDisplayFinalMetrics;
}

function mapAgent(value: unknown): AtifDisplayAgent {
  const agent = isRecord(value) ? value : {};
  const toolDefinitions = has(agent, "tool_definitions")
    ? agent.tool_definitions === null
      ? null
      : Array.isArray(agent.tool_definitions)
        ? agent.tool_definitions.map((item) => safeClone(item) ?? {})
        : []
    : undefined;
  const result: Record<string, unknown> = {
    name: typeof agent.name === "string" ? agent.name : "",
    version: typeof agent.version === "string" ? agent.version : "",
  };
  if (has(agent, "model_name")) result.modelName = optionalString(agent, "model_name");
  if (has(agent, "tool_definitions")) result.toolDefinitions = toolDefinitions;
  const extensions = extensionRecord(agent, ["name", "version", "model_name", "tool_definitions"]);
  if (extensions !== undefined) result.extensions = extensions;
  return result as unknown as AtifDisplayAgent;
}

function timestampNanos(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const match = RFC3339.exec(value);
  if (!match) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds)) return null;
  const fraction = `${match[7] ?? ""}000000000`.slice(0, 9);
  return BigInt(milliseconds) * 1_000_000n + BigInt(fraction);
}

function displayTiming(value: RawRecord): AtifDisplayTiming {
  const startedAt = optionalString(value, "startedAt");
  const completedAt = optionalString(value, "completedAt");
  const explicit = has(value, "durationMs") ? value.durationMs : undefined;
  if (typeof explicit === "number" && Number.isFinite(explicit) && explicit >= 0) {
    const result: AtifDisplayTiming = { durationMs: explicit, durationSource: "explicit" };
    if (startedAt !== undefined) (result as { startedAt?: string | null }).startedAt = startedAt;
    if (completedAt !== undefined) (result as { completedAt?: string | null }).completedAt = completedAt;
    return result;
  }
  const start = timestampNanos(startedAt);
  const end = timestampNanos(completedAt);
  if (start !== null && end !== null && end >= start) {
    const delta = end - start;
    if (delta % 1_000_000n === 0n && delta / 1_000_000n <= BigInt(Number.MAX_SAFE_INTEGER)) {
      const result: AtifDisplayTiming = { durationMs: Number(delta / 1_000_000n), durationSource: "derived" };
      if (startedAt !== undefined) (result as { startedAt?: string | null }).startedAt = startedAt;
      if (completedAt !== undefined) (result as { completedAt?: string | null }).completedAt = completedAt;
      return result;
    }
  }
  const result: AtifDisplayTiming = { durationMs: null, durationSource: "unavailable" };
  if (startedAt !== undefined) (result as { startedAt?: string | null }).startedAt = startedAt;
  if (completedAt !== undefined) (result as { completedAt?: string | null }).completedAt = completedAt;
  return result;
}

function validLogicalPath(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 1024
    && !value.startsWith("/")
    && !value.includes("\\")
    && !value.includes("..")
    && !value.includes("://")
    && ![...value].some((character) => character.charCodeAt(0) < 0x20);
}

function hrefFor(taskId: string, logicalPath: string): string {
  return `/api/steward/tasks/${encodeURIComponent(taskId)}/artifact?path=${encodeURIComponent(logicalPath)}`;
}

function normalizeArtifacts(value: AtifViewArtifactCollection | undefined): Map<string, AtifViewArtifactDescriptor> {
  const result = new Map<string, AtifViewArtifactDescriptor>();
  if (value === undefined) return result;
  if (value instanceof Map) {
    for (const descriptor of value.values()) if (!result.has(descriptor.artifactId)) result.set(descriptor.artifactId, descriptor);
  } else if (Array.isArray(value)) {
    for (const descriptor of value) if (!result.has(descriptor.artifactId)) result.set(descriptor.artifactId, descriptor);
  } else {
    for (const descriptor of Object.values(value)) if (!result.has(descriptor.artifactId)) result.set(descriptor.artifactId, descriptor);
  }
  return result;
}

function localArtifactMap(provenance: RawRecord): Map<string, RawRecord> {
  const result = new Map<string, RawRecord>();
  if (!Array.isArray(provenance.artifacts)) return result;
  for (const item of provenance.artifacts) {
    if (!isRecord(item) || typeof item.artifactId !== "string" || result.has(item.artifactId)) continue;
    result.set(item.artifactId, item);
  }
  return result;
}

function unavailable(artifactId: string | null, reason: AtifArtifactUnavailableReason): AtifUnavailableArtifact {
  return { kind: "unavailable", artifactId, reason };
}

function resolveAction(
  artifactId: string,
  expectedMediaType: string | undefined,
  context: ProjectionContext,
): AtifArtifactAction {
  const local = context.localArtifacts.get(artifactId);
  const descriptor = context.artifacts.get(artifactId);
  if (!descriptor || !local) return unavailable(artifactId, "missing");
  if (!context.selectionValid) return unavailable(artifactId, "ownership-mismatch");
  if (descriptor.taskId !== context.taskId || descriptor.runId !== context.runId) return unavailable(artifactId, "ownership-mismatch");
  if (descriptor.artifactId !== artifactId
    || local.mediaType !== descriptor.mediaType
    || local.sha256 !== descriptor.sha256
    || local.byteSize !== descriptor.byteSize
    || (expectedMediaType !== undefined && expectedMediaType !== descriptor.mediaType)) {
    return unavailable(artifactId, "descriptor-mismatch");
  }
  if (descriptor.availability === "unavailable") return unavailable(artifactId, "unavailable");
  if (!validLogicalPath(descriptor.logicalPath)) return unavailable(artifactId, descriptor.logicalPath === undefined ? "missing-logical-path" : "invalid-logical-path");
  const image = (SUPPORTED_IMAGE_MEDIA_TYPES as readonly string[]).includes(descriptor.mediaType);
  return {
    kind: image ? "image" : "download",
    artifactId,
    taskId: descriptor.taskId,
    runId: descriptor.runId,
    mediaType: descriptor.mediaType,
    logicalPath: descriptor.logicalPath,
    href: hrefFor(descriptor.taskId, descriptor.logicalPath),
  };
}

function mapArtifact(local: RawRecord, context: ProjectionContext): AtifDisplayArtifact | null {
  if (typeof local.artifactId !== "string" || typeof local.mediaType !== "string" || typeof local.sha256 !== "string" || typeof local.byteSize !== "number" || typeof local.ownerStepId !== "number") return null;
  const descriptor = context.artifacts.get(local.artifactId);
  const result: Record<string, unknown> = {
    artifactId: local.artifactId,
    mediaType: local.mediaType,
    sha256: local.sha256,
    byteSize: local.byteSize,
    ownerStepId: local.ownerStepId,
    action: resolveAction(local.artifactId, local.mediaType, context),
  };
  if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, "disclosure")) result.disclosure = descriptor.disclosure;
  return result as unknown as AtifDisplayArtifact;
}

function anchor(value: string, context: ProjectionContext): string {
  const encoded = encodeURIComponent(value).replace(/%/g, "-").replace(/[^A-Za-z0-9._-]/g, "-");
  const base = encoded || "item";
  let candidate = base;
  let suffix = 2;
  while (context.anchors.has(candidate)) candidate = `${base}-${suffix++}`;
  context.anchors.add(candidate);
  return candidate;
}

function mapContentPart(value: unknown, context: ProjectionContext): AtifDisplayContent {
  if (!isRecord(value)) return { kind: "generic", type: "generic", record: {} };
  if (value.type === "text") {
    return { kind: "text", type: "text", text: value.text === null || typeof value.text === "string" ? value.text : null };
  }
  if (value.type === "image" && isRecord(value.source)) {
    const mediaType = value.source.media_type;
    const path = value.source.path;
    const artifactId = typeof path === "string" && path.startsWith("artifact:") ? path.slice("artifact:".length) : null;
    if ((SUPPORTED_IMAGE_MEDIA_TYPES as readonly string[]).includes(String(mediaType))) {
      return {
        kind: "image",
        type: "image",
        mediaType: mediaType as AtifImageMediaType,
        artifactId,
        action: artifactId === null ? unavailable(null, "missing") : resolveAction(artifactId, String(mediaType), context),
      };
    }
  }
  return { kind: "generic", type: "generic", record: safeRecord(value) };
}

function mapContent(value: unknown, context: ProjectionContext): { value: AtifDisplayContentValue; parts: readonly AtifDisplayContent[] } {
  if (value === undefined) return { value: undefined, parts: [] };
  if (typeof value === "string") {
    const part: AtifTextContent = { kind: "text", type: "text", text: value };
    return { value, parts: [part] };
  }
  if (value === null) return { value: null, parts: [] };
  if (Array.isArray(value)) {
    const parts = value.map((part) => mapContentPart(part, context));
    return { value: parts, parts };
  }
  const generic = mapContentPart(value, context);
  return { value: [generic], parts: [generic] };
}

function mapObservation(value: RawRecord, context: ProjectionContext, calls: ReadonlyMap<string, CallEntry>): AtifDisplayObservation {
  const mapped = mapContent(value.content, context);
  const sourceCallId = has(value, "source_call_id")
    ? value.source_call_id === null || typeof value.source_call_id === "string" ? value.source_call_id : undefined
    : undefined;
  const matchedCallId = typeof sourceCallId === "string" && calls.has(sourceCallId) ? sourceCallId : null;
  const result: Record<string, unknown> = {
    parts: mapped.parts,
    matchedCallId,
  };
  if (has(value, "content")) result.content = mapped.value;
  const extensions = extensionRecord(value, ["content", "source_call_id", "subagent_trajectory_ref"]);
  if (extensions !== undefined) result.extensions = extensions;
  if (has(value, "source_call_id")) (result as { sourceCallId?: string | null }).sourceCallId = sourceCallId ?? null;
  if (has(value, "subagent_trajectory_ref")) {
    const refs = Array.isArray(value.subagent_trajectory_ref) ? value.subagent_trajectory_ref : [];
    (result as { lineage?: readonly AtifDisplayLineageReference[] | null }).lineage = refs.map((ref) => mapLineageReference(ref));
  }
  return result as unknown as AtifDisplayObservation;
}

function mapLineageReference(value: unknown): AtifDisplayLineageReference {
  const ref = isRecord(value) ? value : {};
  const result: Record<string, unknown> = {};
  const extensions = extensionRecord(ref, ["trajectory_id", "session_id", "trajectory_path"]);
  if (extensions !== undefined) result.extensions = extensions;
  if (has(ref, "trajectory_id")) (result as { trajectoryId?: string | null }).trajectoryId = optionalString(ref, "trajectory_id") ?? null;
  if (has(ref, "session_id")) (result as { sessionId?: string | null }).sessionId = optionalString(ref, "session_id") ?? null;
  return result as AtifDisplayLineageReference;
}

function collectCalls(steps: readonly RawRecord[]): Map<string, CallEntry> {
  const calls = new Map<string, CallEntry>();
  for (const step of steps) {
    if (!Array.isArray(step.tool_calls)) continue;
    step.tool_calls.forEach((candidate, index) => {
      if (!isRecord(candidate) || typeof candidate.tool_call_id !== "string" || calls.has(candidate.tool_call_id)) return;
      calls.set(candidate.tool_call_id, {
        callId: candidate.tool_call_id,
        stepId: typeof step.step_id === "number" ? step.step_id : 0,
        index,
        value: candidate,
        observations: [],
      });
    });
  }
  for (const step of steps) {
    const observation = isRecord(step.observation) ? step.observation : undefined;
    if (!observation || !Array.isArray(observation.results)) continue;
    for (const result of observation.results) {
      if (!isRecord(result) || typeof result.source_call_id !== "string") continue;
      calls.get(result.source_call_id)?.observations.push(result);
    }
  }
  return calls;
}

function mapCall(value: RawRecord, stepId: number, context: ProjectionContext, calls: ReadonlyMap<string, CallEntry>): AtifDisplayToolCall | null {
  if (typeof value.tool_call_id !== "string") return null;
  const entry = calls.get(value.tool_call_id);
  const observations = entry?.observations ?? [];
  const result: Record<string, unknown> = {
    anchor: anchor(`call-${value.tool_call_id}`, context),
    callId: value.tool_call_id,
    id: value.tool_call_id,
    functionName: typeof value.function_name === "string" ? value.function_name : "",
    arguments: safeRecord(value.arguments),
    observations: observations.map((item) => mapObservation(item, context, calls)),
  };
  const extensions = extensionRecord(value, ["tool_call_id", "function_name", "arguments"]);
  if (extensions !== undefined) result.extensions = extensions;
  return result as unknown as AtifDisplayToolCall;
}

function mapStep(value: RawRecord, context: ProjectionContext, calls: ReadonlyMap<string, CallEntry>): AtifDisplayStep | null {
  if (typeof value.step_id !== "number" || (value.source !== "system" && value.source !== "user" && value.source !== "agent")) return null;
  const stepId = value.step_id;
  const mapped = mapContent(value.message, context);
  const rawCalls = Array.isArray(value.tool_calls) ? value.tool_calls.map((item) => isRecord(item) ? mapCall(item, stepId, context, calls) : null).filter((item): item is AtifDisplayToolCall => item !== null) : [];
  const result: AtifDisplayStep = {
    id: anchor(`step-${stepId}`, context),
    anchor: "",
    stepId,
    source: value.source,
    role: value.source,
    message: mapped.value,
    content: mapped.parts,
    parts: mapped.parts,
    calls: rawCalls,
    tools: rawCalls,
    observations: [],
  };
  const extensions = extensionRecord(value, ["step_id", "source", "message", "timestamp", "reasoning_content", "model_name", "reasoning_effort", "is_copied_context", "llm_call_count", "metrics", "tool_calls", "observation"]);
  if (extensions !== undefined) (result as { extensions?: AtifSafeRecord | null }).extensions = extensions;
  (result as { anchor: string }).anchor = result.id;
  if (has(value, "timestamp")) (result as { timestamp?: string | null }).timestamp = optionalString(value, "timestamp") ?? null;
  if (has(value, "reasoning_content")) (result as { reasoning?: string | null }).reasoning = optionalString(value, "reasoning_content") ?? null;
  if (has(value, "model_name")) (result as { modelName?: string | null }).modelName = optionalString(value, "model_name") ?? null;
  if (has(value, "reasoning_effort")) {
    const effort = value.reasoning_effort;
    (result as { reasoningEffort?: string | number | null }).reasoningEffort = effort === null || typeof effort === "string" || typeof effort === "number" ? effort : null;
  }
  if (has(value, "is_copied_context")) {
    const copied = value.is_copied_context;
    (result as { copiedContext?: boolean | null }).copiedContext = copied === null || typeof copied === "boolean" ? copied : null;
  }
  if (has(value, "llm_call_count")) {
    const count = value.llm_call_count;
    (result as { llmCallCount?: number | null }).llmCallCount = count === null || typeof count === "number" ? count : null;
  }
  if (has(value, "metrics")) (result as { metrics?: AtifDisplayMetrics | null }).metrics = mapMetrics(value.metrics) ?? null;
  if (has(value, "tool_calls")) (result as { toolCalls?: readonly AtifDisplayToolCall[] | null }).toolCalls = value.tool_calls === null ? null : rawCalls;
  if (has(value, "observation")) {
    if (value.observation === null) (result as { observation?: { readonly results: readonly AtifDisplayObservation[] } | null }).observation = null;
    else if (isRecord(value.observation)) {
      const results = Array.isArray(value.observation.results)
        ? value.observation.results.filter(isRecord).map((item) => mapObservation(item, context, calls))
        : [];
      (result as { observation?: { readonly results: readonly AtifDisplayObservation[] } | null }).observation = { results };
      (result as { observations: readonly AtifDisplayObservation[] }).observations = results;
    }
  }
  return result;
}

function mapProvenance(document: AtifDocument): RawRecord {
  const extra = isRecord(document.extra) ? document.extra : {};
  return isRecord(extra.coquic) ? extra.coquic : {};
}

function mapDocument(document: AtifDocument, options: AtifViewModelOptions, depth: number, parentArtifacts?: ReadonlyMap<string, AtifViewArtifactDescriptor>): AtifDisplayModel {
  const raw = document as unknown as RawRecord;
  const provenance = mapProvenance(document);
  const taskId = typeof provenance.taskId === "string" ? provenance.taskId : options.taskId ?? "";
  const runId = typeof provenance.runId === "string" ? provenance.runId : options.runId ?? "";
  const artifacts = normalizeArtifacts(options.artifacts ?? options.artifactMap);
  const context: ProjectionContext = {
    artifacts: artifacts.size > 0 ? artifacts : (parentArtifacts ?? artifacts),
    taskId,
    runId,
    provenance,
    localArtifacts: localArtifactMap(provenance),
    anchors: new Set<string>(),
    selectionValid: (options.taskId === undefined || options.taskId === taskId)
      && (options.runId === undefined || options.runId === runId),
  };
  const rawSteps = Array.isArray(raw.steps) ? raw.steps.filter(isRecord) : [];
  const calls = collectCalls(rawSteps);
  const steps = rawSteps.map((step) => mapStep(step, context, calls)).filter((step): step is AtifDisplayStep => step !== null);
  const localArtifacts = Array.isArray(provenance.artifacts)
    ? provenance.artifacts.map((item) => isRecord(item) ? mapArtifact(item, context) : null).filter((item): item is AtifDisplayArtifact => item !== null)
    : [];
  const timingInput: RawRecord = {
    startedAt: provenance.startedAt,
    completedAt: provenance.completedAt,
    durationMs: provenance.durationMs,
  };
  const timing = displayTiming(timingInput);
  const lineage: AtifDisplayLineage = {
    trajectoryId: optionalString(raw, "trajectory_id"),
    sessionId: optionalString(raw, "session_id"),
    references: rawSteps.flatMap((step) => {
      const observation = isRecord(step.observation) ? step.observation : undefined;
      if (!observation || !Array.isArray(observation.results)) return [];
      return observation.results.flatMap((result) => {
        if (!isRecord(result) || !Array.isArray(result.subagent_trajectory_ref)) return [];
        return result.subagent_trajectory_ref.map((ref) => mapLineageReference(ref));
      });
    }),
    trajectories: depth >= 32 || !Array.isArray(raw.subagent_trajectories)
      ? []
      : raw.subagent_trajectories.filter(isRecord).map((child) => mapDocument(child as unknown as AtifDocument, { artifacts: artifacts }, depth + 1, artifacts)),
  };
  const extensions = extensionRecord(raw, ["agent", "steps", "schema_version", "extra", "final_metrics", "notes", "session_id", "trajectory_id", "subagent_trajectories", "continued_trajectory_ref"]);
  const metadataExtensions = extensionRecord(provenance, ["taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure", "artifacts"]);
  const agent = mapAgent(raw.agent);
  const disclosure = provenance.disclosure as AtifDisclosure;
  const metadataRecord: Record<string, unknown> = {
    taskId,
    pipelineId: typeof provenance.pipelineId === "string" ? provenance.pipelineId : "",
    runId,
    role: typeof provenance.role === "string" ? provenance.role : "",
    startedAt: typeof provenance.startedAt === "string" ? provenance.startedAt : "",
    completedAt: typeof provenance.completedAt === "string" ? provenance.completedAt : "",
    durationMs: typeof provenance.durationMs === "number" && Number.isFinite(provenance.durationMs) && provenance.durationMs >= 0
      ? provenance.durationMs
      : timing.durationMs,
    timing,
    disclosure,
    artifacts: localArtifacts,
  };
  if (metadataExtensions !== undefined) metadataRecord.extensions = metadataExtensions;
  const metadata = metadataRecord as unknown as AtifDisplayMetadata;
  const resultRecord: Record<string, unknown> = {
    kind: "atif-display",
    schemaVersion: typeof raw.schema_version === "string" ? raw.schema_version : "",
    agent,
    metadata,
    taskId,
    pipelineId: metadata.pipelineId,
    runId,
    role: metadata.role,
    timing,
    disclosure,
    steps,
    lineage,
    artifacts: localArtifacts,
  };
  if (extensions !== undefined) resultRecord.extensions = extensions;
  const result = resultRecord as unknown as AtifDisplayModel;
  if (has(raw, "final_metrics")) (result as { finalMetrics?: AtifDisplayFinalMetrics | null }).finalMetrics = mapFinalMetrics(raw.final_metrics) ?? null;
  if (has(raw, "notes")) (result as { notes?: string | null }).notes = optionalString(raw, "notes") ?? null;
  if (has(raw, "session_id")) (result as { sessionId?: string | null }).sessionId = optionalString(raw, "session_id") ?? null;
  if (has(raw, "trajectory_id")) (result as { trajectoryId?: string | null }).trajectoryId = optionalString(raw, "trajectory_id") ?? null;
  return result;
}

function normalizeInput(
  documentOrInput: AtifDocument | AtifViewModelInput,
  optionsOrArtifacts: AtifViewModelOptions | AtifViewArtifactCollection | undefined,
): { document: AtifDocument; options: AtifViewModelOptions } {
  if (isRecord(documentOrInput) && "document" in documentOrInput) {
    const input = documentOrInput as unknown as AtifViewModelInput;
    return { document: input.document, options: input };
  }
  if (Array.isArray(optionsOrArtifacts) || optionsOrArtifacts instanceof Map) return { document: documentOrInput as AtifDocument, options: { artifacts: optionsOrArtifacts } };
  if (isRecord(optionsOrArtifacts)
    && !("artifacts" in optionsOrArtifacts)
    && !("artifactMap" in optionsOrArtifacts)
    && !("taskId" in optionsOrArtifacts)
    && !("runId" in optionsOrArtifacts)) {
    return { document: documentOrInput as AtifDocument, options: { artifacts: optionsOrArtifacts as AtifViewArtifactCollection } };
  }
  return { document: documentOrInput as AtifDocument, options: (optionsOrArtifacts as AtifViewModelOptions | undefined) ?? {} };
}

export function buildAtifViewModel(document: AtifDocument, options?: AtifViewModelOptions | AtifViewArtifactCollection): AtifDisplayModel;
export function buildAtifViewModel(document: AtifDocument, artifacts: AtifViewArtifactCollection, selection?: Pick<AtifViewModelOptions, "taskId" | "runId">): AtifDisplayModel;
export function buildAtifViewModel(input: AtifViewModelInput): AtifDisplayModel;
export function buildAtifViewModel(
  documentOrInput: AtifDocument | AtifViewModelInput,
  optionsOrArtifacts?: AtifViewModelOptions | AtifViewArtifactCollection,
  selection?: Pick<AtifViewModelOptions, "taskId" | "runId">,
): AtifDisplayModel {
  const input = normalizeInput(documentOrInput, optionsOrArtifacts);
  return mapDocument(input.document, { ...input.options, ...selection }, 0);
}

export const projectAtifDisplay = buildAtifViewModel;
export const projectAtifViewModel = buildAtifViewModel;
export const mapAtifToViewModel = buildAtifViewModel;
export const buildAtifDisplayModel = buildAtifViewModel;
export const projectAtif = buildAtifViewModel;
export const projectAtifTrajectory = buildAtifViewModel;
export const mapAtifDocument = buildAtifViewModel;
