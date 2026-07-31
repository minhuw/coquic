import Ajv2020, { type AnySchema, type ErrorObject } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import atifSchema from "../../../contracts/steward-cloud/atif-v1.7.schema.json";

export const ATIF_VERSION = "ATIF-v1.7" as const;
export const SUPPORTED_IMAGE_MEDIA_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
] as const;
export type AtifImageMediaType = (typeof SUPPORTED_IMAGE_MEDIA_TYPES)[number];

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
const PRIVATE_NAME = /(?:bucket|objectkey|credential|secret|password|token|authorization|apikey|private|presign|signed|scanner|filesystem|filepath|endpoint|uri|url)/i;
const PRIVATE_VALUE = /(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?):\/\/|^(?:~[/\\]|\/{1}|[A-Za-z]:[/\\]|\\\\)|(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]key)?|url|path)(?:$|[-_])/i;
const MAX_HARD_BYTES = 64 * 1024 * 1024;
const MAX_HARD_DEPTH = 128;
const MAX_HARD_STRING = 4 * 1024 * 1024;
const MAX_HARD_COLLECTION = 1_000_000;
const MAX_HARD_NODES = 2_000_000;

export const DEFAULT_ATIF_LIMITS = Object.freeze({
  maxBytes: 16 * 1024 * 1024,
  maxDepth: 64,
  maxStringLength: 1_000_000,
  maxCollectionLength: 100_000,
  maxNodes: 500_000,
});

export type AtifJsonObject = { [key: string]: unknown };

export interface AtifDisclosure {
  readonly redactionApplied: boolean;
  readonly originalRetained: boolean;
}

export interface AtifArtifactDescriptor extends AtifJsonObject {
  readonly artifactId: string;
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly ownerStepId: number;
}

export interface AtifPublicationArtifactDescriptor extends AtifJsonObject {
  readonly artifactId: string;
  readonly taskId: string;
  readonly runId: string;
  readonly mediaType: string;
  readonly sha256: string;
  readonly byteSize: number;
}

export interface AtifCoquicMetadata extends AtifJsonObject {
  readonly taskId: string;
  readonly pipelineId: string;
  readonly runId: string;
  readonly role: string;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly disclosure: AtifDisclosure;
  readonly artifacts: readonly AtifArtifactDescriptor[];
}

export interface AtifStep extends AtifJsonObject {
  readonly step_id: number;
  readonly source: "system" | "user" | "agent";
  readonly message: string | readonly AtifJsonObject[];
}

export interface AtifDocument extends AtifJsonObject {
  readonly agent: AtifJsonObject;
  readonly steps: readonly AtifStep[];
  readonly schema_version?: string;
  readonly extra?: AtifJsonObject | null;
}

export type AtifSource = Uint8Array | ArrayBuffer | string;
export type AtifArtifactCollection =
  | readonly AtifPublicationArtifactDescriptor[]
  | ReadonlyMap<string, AtifPublicationArtifactDescriptor>
  | Readonly<Record<string, AtifPublicationArtifactDescriptor>>;

export interface AtifExpectedOwnership {
  readonly taskId?: string;
  readonly pipelineId?: string;
  readonly runId?: string;
  readonly role?: string;
  readonly startedAt?: string;
  readonly completedAt?: string;
  readonly durationMs?: number;
  readonly disclosure?: AtifDisclosure;
}

export interface AtifValidationOptions extends AtifExpectedOwnership {
  readonly expected?: AtifExpectedOwnership;
  readonly ownership?: AtifExpectedOwnership;
  readonly expectedOwnership?: AtifExpectedOwnership;
  readonly artifacts?: AtifArtifactCollection;
  readonly artifactMap?: AtifArtifactCollection;
  readonly expectedArtifacts?: AtifArtifactCollection;
  readonly requireExpectedOwnership?: boolean;
  readonly maxBytes?: number;
  readonly maxDepth?: number;
  readonly maxStringLength?: number;
  readonly maxCollectionLength?: number;
  readonly maxNodes?: number;
}

export interface AtifIssue {
  readonly rule: string;
  readonly code: string;
  readonly path: string;
  readonly jsonPath: string;
  readonly segments: readonly (string | number)[];
}

export type AtifValidationResult =
  | { readonly ok: true; readonly value: AtifDocument }
  | { readonly ok: false; readonly issues: readonly AtifIssue[] };

export class AtifValidationError extends Error {
  readonly issues: readonly AtifIssue[];

  constructor(issues: readonly AtifIssue[]) {
    const first = issues[0];
    super(first ? `${first.rule} at ${first.path}` : "invalid ATIF");
    this.name = "AtifValidationError";
    this.issues = issues;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

type PathSegment = string | number;
interface Limits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly maxStringLength: number;
  readonly maxCollectionLength: number;
  readonly maxNodes: number;
}
interface NormalizedOptions {
  readonly expected: AtifExpectedOwnership;
  readonly expectedArtifacts: Map<string, AtifPublicationArtifactDescriptor>;
  readonly limits: Limits;
  readonly requireExpectedOwnership: boolean;
}

function isObject(value: unknown): value is AtifJsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function pathString(path: readonly PathSegment[]): string {
  let result = "$";
  for (const segment of path) result += typeof segment === "number" ? `[${segment}]` : `.${segment}`;
  return result;
}

function addIssue(issues: Map<string, AtifIssue>, rule: string, path: readonly PathSegment[]): void {
  const segments = [...path];
  const rendered = pathString(segments);
  const key = `${rule}\u0000${rendered}`;
  if (issues.has(key)) return;
  issues.set(key, { rule, code: rule, path: rendered, jsonPath: rendered, segments });
}

function sortedIssues(issues: Map<string, AtifIssue>): AtifIssue[] {
  return [...issues.values()].sort((left, right) => {
    const pathOrder = left.path < right.path ? -1 : left.path > right.path ? 1 : 0;
    return pathOrder || (left.rule < right.rule ? -1 : left.rule > right.rule ? 1 : 0);
  });
}

function bounded(value: number | undefined, fallback: number, maximum: number): number {
  return value !== undefined && Number.isSafeInteger(value) && value > 0 && value <= maximum ? value : fallback;
}

function normalizeArtifacts(value: AtifArtifactCollection | undefined): Map<string, AtifPublicationArtifactDescriptor> | undefined {
  if (value === undefined) return undefined;
  const result = new Map<string, AtifPublicationArtifactDescriptor>();
  if (value instanceof Map) {
    for (const [key, descriptor] of value) result.set(key, descriptor);
  } else if (Array.isArray(value)) {
    for (const descriptor of value) result.set(descriptor.artifactId, descriptor);
  } else {
    for (const [key, descriptor] of Object.entries(value)) result.set(key, descriptor);
  }
  return result;
}

function normalizeOptions(options: AtifValidationOptions = {}, positionalArtifacts?: AtifArtifactCollection): NormalizedOptions {
  const expected = options.expected ?? options.ownership ?? options.expectedOwnership ?? options;
  const artifactInput = positionalArtifacts ?? options.artifacts ?? options.artifactMap ?? options.expectedArtifacts;
  return {
    expected,
    expectedArtifacts: normalizeArtifacts(artifactInput) ?? new Map(),
    requireExpectedOwnership: options.requireExpectedOwnership !== false,
    limits: {
      maxBytes: bounded(options.maxBytes, DEFAULT_ATIF_LIMITS.maxBytes, MAX_HARD_BYTES),
      maxDepth: bounded(options.maxDepth, DEFAULT_ATIF_LIMITS.maxDepth, MAX_HARD_DEPTH),
      maxStringLength: bounded(options.maxStringLength, DEFAULT_ATIF_LIMITS.maxStringLength, MAX_HARD_STRING),
      maxCollectionLength: bounded(options.maxCollectionLength, DEFAULT_ATIF_LIMITS.maxCollectionLength, MAX_HARD_COLLECTION),
      maxNodes: bounded(options.maxNodes, DEFAULT_ATIF_LIMITS.maxNodes, MAX_HARD_NODES),
    },
  };
}

class InputFailure extends Error {
  readonly rule: "canonicalization" | "bounds";

  constructor(rule: "canonicalization" | "bounds") {
    super(rule);
    this.rule = rule;
  }
}

function compareUnicode(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalString(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0xd800 || code > 0xdfff) continue;
    if (code <= 0xdbff && index + 1 < value.length) {
      const trailing = value.charCodeAt(index + 1);
      if (trailing >= 0xdc00 && trailing <= 0xdfff) {
        index += 1;
        continue;
      }
    }
    throw new InputFailure("canonicalization");
  }
  return JSON.stringify(value);
}

function canonicalFloat(value: number): string {
  if (!Number.isFinite(value)) throw new InputFailure("bounds");
  if (Object.is(value, -0)) return "-0.0";
  if (value === 0) return "0.0";
  const [mantissa, rawExponent] = value.toExponential().split("e");
  const exponent = Number(rawExponent);
  if (exponent < -4 || exponent >= 16) {
    const sign = exponent < 0 ? "-" : "+";
    return `${mantissa}e${sign}${Math.abs(exponent).toString().padStart(2, "0")}`;
  }
  const decimal = value.toString();
  return decimal.includes(".") ? decimal : `${decimal}.0`;
}

function sourceBytes(source: AtifSource, maxBytes: number): Uint8Array {
  let bytes: Uint8Array;
  if (typeof source === "string") bytes = new TextEncoder().encode(source);
  else if (source instanceof Uint8Array) bytes = source;
  else if (source instanceof ArrayBuffer) bytes = new Uint8Array(source);
  else throw new InputFailure("canonicalization");
  if (bytes.byteLength > maxBytes) throw new InputFailure("bounds");
  return bytes;
}

class JsonReader {
  private index = 0;
  private nodes = 0;

  constructor(private readonly source: string, private readonly limits: Limits) {}

  read(): unknown {
    const value = this.readValue(0);
    if (this.index !== this.source.length - 1 || this.source[this.index] !== "\n") {
      throw new InputFailure("canonicalization");
    }
    return value;
  }

  private fail(rule: "canonicalization" | "bounds" = "canonicalization"): never {
    throw new InputFailure(rule);
  }

  private skipWhitespace(): void {
    const code = this.source.charCodeAt(this.index);
    if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) this.fail();
  }

  private readValue(depth: number): unknown {
    if (depth > this.limits.maxDepth) this.fail("bounds");
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) this.fail("bounds");
    this.skipWhitespace();
    const token = this.source[this.index];
    if (token === "{") return this.readObject(depth);
    if (token === "[") return this.readArray(depth);
    if (token === '"') return this.readString();
    if (token === "t" && this.source.slice(this.index, this.index + 4) === "true") { this.index += 4; return true; }
    if (token === "f" && this.source.slice(this.index, this.index + 5) === "false") { this.index += 5; return false; }
    if (token === "n" && this.source.slice(this.index, this.index + 4) === "null") { this.index += 4; return null; }
    return this.readNumber();
  }

  private readString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        const raw = this.source.slice(start, this.index);
        let value: unknown;
        try { value = JSON.parse(raw); } catch { this.fail(); }
        if (typeof value !== "string" || value.length > this.limits.maxStringLength) this.fail("bounds");
        if (raw !== canonicalString(value)) this.fail();
        return value;
      }
      if (code < 0x20) this.fail();
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.source[this.index];
        if (!escape || !'"\\/bfnrtu'.includes(escape)) this.fail();
        if (escape === "u") {
          const digits = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) this.fail();
          this.index += 5;
        } else this.index += 1;
      } else this.index += 1;
    }
    this.fail();
  }

  private readNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.source.slice(this.index));
    if (!match || match[0].length > 1024) this.fail();
    const raw = match[0];
    const value = Number(raw);
    if (!Number.isFinite(value)) this.fail("bounds");
    const isFloat = raw.includes(".") || raw.includes("e") || raw.includes("E");
    if ((isFloat && raw !== canonicalFloat(value)) || (!isFloat && raw === "-0")) this.fail();
    this.index += raw.length;
    return value;
  }

  private readObject(depth: number): AtifJsonObject {
    this.index += 1;
    const result: AtifJsonObject = {};
    const keys = new Set<string>();
    let previousKey: string | undefined;
    this.skipWhitespace();
    if (this.source[this.index] === "}") { this.index += 1; return result; }
    for (let count = 0; ; count += 1) {
      if (count >= this.limits.maxCollectionLength) this.fail("bounds");
      this.skipWhitespace();
      if (this.source[this.index] !== '"') this.fail();
      const key = this.readString();
      if (keys.has(key)) this.fail();
      if (previousKey !== undefined && compareUnicode(previousKey, key) >= 0) this.fail();
      keys.add(key);
      previousKey = key;
      this.skipWhitespace();
      if (this.source[this.index] !== ":") this.fail();
      this.index += 1;
      const value = this.readValue(depth + 1);
      Object.defineProperty(result, key, { configurable: true, enumerable: true, writable: true, value });
      this.skipWhitespace();
      const separator = this.source[this.index];
      if (separator === "}") { this.index += 1; return result; }
      if (separator !== ",") this.fail();
      this.index += 1;
    }
  }

  private readArray(depth: number): unknown[] {
    this.index += 1;
    const result: unknown[] = [];
    this.skipWhitespace();
    if (this.source[this.index] === "]") { this.index += 1; return result; }
    for (let count = 0; ; count += 1) {
      if (count >= this.limits.maxCollectionLength) this.fail("bounds");
      result.push(this.readValue(depth + 1));
      this.skipWhitespace();
      const separator = this.source[this.index];
      if (separator === "]") { this.index += 1; return result; }
      if (separator !== ",") this.fail();
      this.index += 1;
    }
  }
}

function parseBytes(bytes: Uint8Array, limits: Limits): unknown {
  let source: string;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { throw new InputFailure("canonicalization"); }
  return new JsonReader(source, limits).read();
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new InputFailure("canonicalization");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort(compareUnicode).map((key) => `${canonicalString(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new InputFailure("canonicalization");
}

export function canonicalAtifBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateSchema = ajv.compile(atifSchema as AnySchema);

function pointerSegments(pointer: string): PathSegment[] {
  if (!pointer) return [];
  return pointer.slice(1).split("/").map((part) => {
    const decoded = part.replace(/~1/g, "/").replace(/~0/g, "~");
    return /^(?:0|[1-9]\d*)$/.test(decoded) && Number.isSafeInteger(Number(decoded)) ? Number(decoded) : decoded;
  });
}

function schemaIssues(value: unknown, issues: Map<string, AtifIssue>): void {
  if (validateSchema(value)) return;
  for (const error of (validateSchema.errors ?? []) as ErrorObject[]) {
    addIssue(issues, `schema-${error.keyword}`, pointerSegments(error.instancePath ?? ""));
  }
}

function privateName(value: string): boolean {
  const compact = value.replace(/[^a-z0-9]/gi, "").toLowerCase();
  return PRIVATE_NAME.test(compact) || ["url", "uri", "endpoint", "baseurl", "baseuri"].includes(compact);
}

function privateIssuePath(path: readonly PathSegment[]): PathSegment[] {
  return path.map((segment) => typeof segment === "string" && privateName(segment) ? "<private-field>" : segment);
}

function privateScan(value: unknown, path: readonly PathSegment[], issues: Map<string, AtifIssue>, key?: string): void {
  let compact: string | undefined;
  const issuePath = privateIssuePath(path);
  if (key !== undefined) {
    compact = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
    if (privateName(key)) addIssue(issues, "private-field", issuePath);
    if (["trajectorypath", "filepath", "credentialpath", "privatepath"].includes(compact)) addIssue(issues, "private-locator", issuePath);
  }
  if (typeof value === "string") {
    if (value.startsWith("/") || PRIVATE_VALUE.test(value)) addIssue(issues, "private-locator", issuePath);
    if (compact?.endsWith("path") && compact !== "logicalpath" && !value.startsWith("artifact:")) addIssue(issues, "private-locator", issuePath);
    if (compact === "mediatype" && value.toLowerCase().startsWith("image/") && !(SUPPORTED_IMAGE_MEDIA_TYPES as readonly string[]).includes(value)) addIssue(issues, "media-type", issuePath);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => privateScan(item, [...path, index], issues, key));
  } else if (isObject(value)) {
    for (const [childKey, childValue] of Object.entries(value)) privateScan(childValue, [...path, childKey], issues, childKey);
  }
}

function nonemptyId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function finiteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function timestampNanos(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const match = RFC3339.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === "Z" ? 0 : Number(match[8].slice(1, 3));
  const offsetMinute = match[8] === "Z" ? 0 : Number(match[8].slice(4, 6));
  if (year < 1 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) return null;
  const base = `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
  const milliseconds = Date.parse(base);
  if (!Number.isFinite(milliseconds)) return null;
  const calendar = new Date(milliseconds);
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() + 1 !== month || calendar.getUTCDate() !== day || calendar.getUTCHours() !== hour || calendar.getUTCMinutes() !== minute || calendar.getUTCSeconds() !== second) return null;
  const fraction = `${match[7] ?? ""}000000000`.slice(0, 9);
  const localNanos = BigInt(fraction);
  const offsetNanos = BigInt((offsetHour * 60 + offsetMinute) * 60) * 1_000_000_000n;
  return BigInt(milliseconds) * 1_000_000n + localNanos - (match[8] === "Z" || match[8][0] === "+" ? offsetNanos : -offsetNanos);
}

function exactKeys(value: AtifJsonObject, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && expected.every((key, index) => actual[index] === key);
}

function descriptorFields(value: AtifJsonObject): AtifArtifactDescriptor | null {
  if (!exactKeys(value, ["artifactId", "byteSize", "mediaType", "ownerStepId", "sha256"])) return null;
  if (typeof value.artifactId !== "string" || typeof value.mediaType !== "string" || typeof value.sha256 !== "string" || typeof value.byteSize !== "number" || typeof value.ownerStepId !== "number") return null;
  return value as AtifArtifactDescriptor;
}

function publicationDescriptorFields(value: AtifPublicationArtifactDescriptor): boolean {
  return nonemptyId(value.artifactId)
    && nonemptyId(value.taskId)
    && nonemptyId(value.runId)
    && typeof value.mediaType === "string"
    && value.mediaType.length > 0
    && DIGEST.test(value.sha256)
    && Number.isSafeInteger(value.byteSize)
    && value.byteSize >= 0;
}

function sameDescriptor(left: AtifArtifactDescriptor, right: AtifPublicationArtifactDescriptor): boolean {
  return left.artifactId === right.artifactId
    && left.mediaType === right.mediaType
    && left.sha256 === right.sha256
    && left.byteSize === right.byteSize;
}

function sameDisclosure(left: unknown, right: unknown): boolean {
  return isObject(left) && isObject(right)
    && left.redactionApplied === right.redactionApplied
    && left.originalRetained === right.originalRetained
    && exactKeys(left, ["originalRetained", "redactionApplied"])
    && exactKeys(right, ["originalRetained", "redactionApplied"]);
}

interface SemanticContext {
  readonly expected: AtifExpectedOwnership;
  readonly expectedArtifacts: Map<string, AtifPublicationArtifactDescriptor> | undefined;
  readonly requireExpectedOwnership: boolean;
  readonly issues: Map<string, AtifIssue>;
}

function checkContent(content: unknown, path: readonly PathSegment[], stepId: number, artifacts: Map<string, AtifArtifactDescriptor>, referenced: Set<string>, issues: Map<string, AtifIssue>): void {
  if (typeof content === "string" || content === null || content === undefined) return;
  if (!Array.isArray(content)) return;
  content.forEach((part, index) => {
    const partPath = [...path, index];
    if (!isObject(part)) return;
    if (part.type === "text") {
      if (typeof part.text !== "string" || (part.source !== undefined && part.source !== null)) addIssue(issues, "content-shape", partPath);
      return;
    }
    if (part.type !== "image") return;
    const source = part.source;
    if (!isObject(source)) { addIssue(issues, "media-type", [...partPath, "source"]); return; }
    if (!(SUPPORTED_IMAGE_MEDIA_TYPES as readonly string[]).includes(String(source.media_type))) addIssue(issues, "media-type", [...partPath, "source", "media_type"]);
    if (typeof source.path !== "string" || !source.path.startsWith("artifact:")) { addIssue(issues, "artifact-reference", [...partPath, "source", "path"]); return; }
    const artifactId = source.path.slice("artifact:".length);
    const descriptor = artifacts.get(artifactId);
    if (!descriptor) { addIssue(issues, "artifact-reference", [...partPath, "source", "path"]); return; }
    referenced.add(artifactId);
    if (descriptor.ownerStepId !== stepId) addIssue(issues, "artifact-owner", [...pathForArtifact(artifacts, artifactId), "ownerStepId"]);
    if (descriptor.mediaType !== source.media_type) addIssue(issues, "artifact-media-type", [...pathForArtifact(artifacts, artifactId), "mediaType"]);
  });
}

function pathForArtifact(artifacts: Map<string, AtifArtifactDescriptor>, artifactId: string): PathSegment[] {
  const index = [...artifacts.keys()].indexOf(artifactId);
  return ["extra", "coquic", "artifacts", index < 0 ? 0 : index];
}

function checkArtifactMetadata(coqui: AtifJsonObject, steps: readonly unknown[], context: SemanticContext): Map<string, AtifArtifactDescriptor> {
  const artifacts = new Map<string, AtifArtifactDescriptor>();
  const raw = coqui.artifacts;
  if (!Array.isArray(raw)) { addIssue(context.issues, "artifact-shape", ["extra", "coquic", "artifacts"]); return artifacts; }
  const stepIds = new Set(steps.filter(isObject).map((step) => step.step_id));
  raw.forEach((item, index) => {
    const itemPath: PathSegment[] = ["extra", "coquic", "artifacts", index];
    if (!isObject(item)) { addIssue(context.issues, "artifact-shape", itemPath); return; }
    const descriptor = descriptorFields(item);
    if (!descriptor) addIssue(context.issues, "artifact-shape", itemPath);
    if (typeof item.artifactId !== "string" || !nonemptyId(item.artifactId)) addIssue(context.issues, "artifact-id", [...itemPath, "artifactId"]);
    else if (artifacts.has(item.artifactId)) addIssue(context.issues, "artifact-unique", [...itemPath, "artifactId"]);
    else artifacts.set(item.artifactId, item as AtifArtifactDescriptor);
    if (typeof item.mediaType !== "string" || !item.mediaType || /\s/.test(item.mediaType)) addIssue(context.issues, "artifact-media-type", [...itemPath, "mediaType"]);
    if (typeof item.mediaType === "string" && item.mediaType.startsWith("image/") && !(SUPPORTED_IMAGE_MEDIA_TYPES as readonly string[]).includes(item.mediaType)) addIssue(context.issues, "media-type", [...itemPath, "mediaType"]);
    if (typeof item.sha256 !== "string" || !DIGEST.test(item.sha256)) addIssue(context.issues, "artifact-digest", [...itemPath, "sha256"]);
    if (typeof item.byteSize !== "number" || !Number.isSafeInteger(item.byteSize) || item.byteSize < 0) addIssue(context.issues, "artifact-size", [...itemPath, "byteSize"]);
    if (typeof item.ownerStepId !== "number" || !Number.isSafeInteger(item.ownerStepId) || !stepIds.has(item.ownerStepId)) addIssue(context.issues, "artifact-owner", [...itemPath, "ownerStepId"]);
    const expected = context.expectedArtifacts?.get(String(item.artifactId));
    if (context.expectedArtifacts && (!expected || !publicationDescriptorFields(expected))) addIssue(context.issues, "artifact-descriptor", itemPath);
    else if (expected) {
      if (expected.taskId !== context.expected.taskId || expected.runId !== context.expected.runId) addIssue(context.issues, "artifact-ownership", itemPath);
      if (!descriptor || !sameDescriptor(descriptor, expected)) addIssue(context.issues, "artifact-descriptor", itemPath);
    }
  });
  return artifacts;
}

function checkSteps(steps: readonly unknown[], context: SemanticContext, artifacts: Map<string, AtifArtifactDescriptor>): Set<string> {
  const sequenceValid = steps.length > 0 && steps.every((step, index) => isObject(step) && step.step_id === index + 1);
  if (!sequenceValid) addIssue(context.issues, "step-sequence", ["steps"]);
  const callIds = new Set<string>();
  const referenced = new Set<string>();
  steps.forEach((rawStep, index) => {
    if (!isObject(rawStep)) return;
    const stepPath: PathSegment[] = ["steps", index];
    if (Array.isArray(rawStep.tool_calls)) rawStep.tool_calls.forEach((rawCall, callIndex) => {
      if (!isObject(rawCall)) return;
      const callId = rawCall.tool_call_id;
      if (typeof callId !== "string" || !callId) addIssue(context.issues, "tool-call-id", [...stepPath, "tool_calls", callIndex, "tool_call_id"]);
      else if (callIds.has(callId)) addIssue(context.issues, "tool-call-unique", [...stepPath, "tool_calls", callIndex, "tool_call_id"]);
      else callIds.add(callId);
    });
  });
  steps.forEach((rawStep, index) => {
    if (!isObject(rawStep)) return;
    const stepId = rawStep.step_id;
    if (typeof stepId !== "number") return;
    const stepPath: PathSegment[] = ["steps", index];
    checkContent(rawStep.message, [...stepPath, "message"], stepId, artifacts, referenced, context.issues);
    if (isObject(rawStep.extra) && isObject(rawStep.extra.coquic) && "artifactIds" in rawStep.extra.coquic) {
      const refs = rawStep.extra.coquic.artifactIds;
      if (!Array.isArray(refs)) addIssue(context.issues, "artifact-reference", [...stepPath, "extra", "coquic", "artifactIds"]);
      else refs.forEach((artifactId, refIndex) => {
        const refPath = [...stepPath, "extra", "coquic", "artifactIds", refIndex];
        if (typeof artifactId !== "string" || !artifacts.has(artifactId)) { addIssue(context.issues, "artifact-reference", refPath); return; }
        referenced.add(artifactId);
        if (artifacts.get(artifactId)!.ownerStepId !== stepId) addIssue(context.issues, "artifact-owner", [...pathForArtifact(artifacts, artifactId), "ownerStepId"]);
      });
    }
    const observation = rawStep.observation;
    if (!isObject(observation) || !Array.isArray(observation.results)) return;
    observation.results.forEach((rawResult, resultIndex) => {
      if (!isObject(rawResult)) return;
      const resultPath = [...stepPath, "observation", "results", resultIndex];
      if (rawResult.source_call_id !== undefined && rawResult.source_call_id !== null && (typeof rawResult.source_call_id !== "string" || !callIds.has(rawResult.source_call_id))) addIssue(context.issues, "observation-reference", [...resultPath, "source_call_id"]);
      checkContent(rawResult.content, [...resultPath, "content"], stepId, artifacts, referenced, context.issues);
    });
  });
  return referenced;
}

function checkProvenance(value: AtifJsonObject, path: PathSegment[], context: SemanticContext, root: boolean): Map<string, AtifArtifactDescriptor> {
  const raw = value.extra;
  const coqui = isObject(raw) ? raw.coquic : undefined;
  if (!isObject(coqui)) { addIssue(context.issues, "provenance-shape", [...path, "extra", "coquic"]); return new Map(); }
  const required = ["taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure", "artifacts"] as const;
  for (const field of required) if (!(field in coqui)) addIssue(context.issues, "provenance-field", [...path, "extra", "coquic", field]);
  for (const field of ["taskId", "pipelineId", "runId"] as const) if (field in coqui && !nonemptyId(coqui[field])) addIssue(context.issues, "provenance-id", [...path, "extra", "coquic", field]);
  if ("role" in coqui && (typeof coqui.role !== "string" || !coqui.role || coqui.role.length > 128)) addIssue(context.issues, "provenance-role", [...path, "extra", "coquic", "role"]);
  const started = timestampNanos(coqui.startedAt);
  const completed = timestampNanos(coqui.completedAt);
  if (started === null || completed === null) addIssue(context.issues, "timing", [...path, "extra", "coquic"]);
  else if (completed < started) addIssue(context.issues, "timing-order", [...path, "extra", "coquic", "completedAt"]);
  if (!finiteNumber(coqui.durationMs) || coqui.durationMs < 0) addIssue(context.issues, "duration", [...path, "extra", "coquic", "durationMs"]);
  const disclosure = coqui.disclosure;
  if (!isObject(disclosure) || !exactKeys(disclosure, ["originalRetained", "redactionApplied"]) || typeof disclosure.originalRetained !== "boolean" || typeof disclosure.redactionApplied !== "boolean") addIssue(context.issues, "disclosure", [...path, "extra", "coquic", "disclosure"]);
  const expected = root ? context.expected : {};
  const expectedFields: (keyof AtifExpectedOwnership)[] = ["taskId", "pipelineId", "runId", "role", "startedAt", "completedAt", "durationMs", "disclosure"];
  for (const field of expectedFields) {
    const expectedValue = expected[field];
    const matches = field === "disclosure" ? sameDisclosure(coqui[field], expectedValue) : coqui[field] === expectedValue;
    if (expectedValue !== undefined && !matches) addIssue(context.issues, "ownership", [...path, "extra", "coquic", field]);
  }
  if (root && context.requireExpectedOwnership && ["taskId", "pipelineId", "runId"].some((field) => expected[field as keyof AtifExpectedOwnership] === undefined)) addIssue(context.issues, "expected-ownership", [...path, "extra", "coquic"]);
  return checkArtifactMetadata(coqui, Array.isArray(value.steps) ? value.steps : [], { ...context, expectedArtifacts: root ? context.expectedArtifacts : undefined });
}

function checkReferences(value: AtifJsonObject, path: PathSegment[], context: SemanticContext, root: boolean): void {
  const children = value.subagent_trajectories;
  const childIds = new Set<string>();
  if (Array.isArray(children)) children.forEach((child, index) => {
    const childPath = [...path, "subagent_trajectories", index];
    if (!isObject(child)) return;
    if (!nonemptyId(child.trajectory_id)) addIssue(context.issues, "trajectory-id", [...childPath, "trajectory_id"]);
    else if (childIds.has(child.trajectory_id)) addIssue(context.issues, "trajectory-unique", [...childPath, "trajectory_id"]);
    else childIds.add(child.trajectory_id);
    validateTrajectory(child, childPath, { ...context, expected: {}, expectedArtifacts: undefined, requireExpectedOwnership: false }, false);
  });
  const steps = value.steps;
  if (!Array.isArray(steps)) return;
  steps.forEach((step, index) => {
    if (!isObject(step) || !isObject(step.observation) || !Array.isArray(step.observation.results)) return;
    step.observation.results.forEach((result, resultIndex) => {
      if (!isObject(result) || !Array.isArray(result.subagent_trajectory_ref)) return;
      result.subagent_trajectory_ref.forEach((ref, refIndex) => {
        if (!isObject(ref)) return;
        const refPath = [...path, "steps", index, "observation", "results", resultIndex, "subagent_trajectory_ref", refIndex];
        const trajectoryId = ref.trajectory_id;
        if (ref.trajectory_path !== undefined && ref.trajectory_path !== null) addIssue(context.issues, "private-locator", [...refPath, "trajectory_path"]);
        if (trajectoryId === undefined && (ref.trajectory_path === undefined || ref.trajectory_path === null)) addIssue(context.issues, "subagent-reference", refPath);
        if (trajectoryId !== undefined && (typeof trajectoryId !== "string" || !childIds.has(trajectoryId))) addIssue(context.issues, "subagent-reference", [...refPath, "trajectory_id"]);
      });
    });
  });
}

function validateTrajectory(value: AtifJsonObject, path: PathSegment[], context: SemanticContext, root: boolean): void {
  if (value.schema_version !== ATIF_VERSION) addIssue(context.issues, "root-schema-version", [...path, "schema_version"]);
  if (value.continued_trajectory_ref !== undefined && value.continued_trajectory_ref !== null) addIssue(context.issues, "partial-run", [...path, "continued_trajectory_ref"]);
  if (!root && !nonemptyId(value.trajectory_id)) addIssue(context.issues, "trajectory-id", [...path, "trajectory_id"]);
  const steps = Array.isArray(value.steps) ? value.steps : [];
  const artifacts = checkProvenance(value, path, context, root);
  const referenced = checkSteps(steps, context, artifacts);
  for (const [artifactId] of artifacts) if (!referenced.has(artifactId)) addIssue(context.issues, "artifact-unreferenced", [...path, "extra", "coquic", "artifacts", [...artifacts.keys()].indexOf(artifactId)]);
  checkReferences(value, path, context, root);
}

function validateDocument(value: unknown, normalized: NormalizedOptions): AtifDocument {
  const issues = new Map<string, AtifIssue>();
  if (!isObject(value)) addIssue(issues, "schema-type", []);
  else {
    schemaIssues(value, issues);
    privateScan(value, [], issues);
    validateTrajectory(value, [], { expected: normalized.expected, expectedArtifacts: normalized.expectedArtifacts, requireExpectedOwnership: normalized.requireExpectedOwnership, issues }, true);
  }
  const sorted = sortedIssues(issues);
  if (sorted.length > 0) throw new AtifValidationError(sorted);
  return value as AtifDocument;
}

export function validateAtifBytes(source: AtifSource, options: AtifValidationOptions = {}, positionalArtifacts?: AtifArtifactCollection): AtifDocument {
  const normalized = normalizeOptions(options, positionalArtifacts);
  let bytes: Uint8Array;
  try { bytes = sourceBytes(source, normalized.limits.maxBytes); } catch (error) {
    const rule = error instanceof InputFailure ? error.rule : "canonicalization";
    throw new AtifValidationError([{ rule, code: rule, path: "$", jsonPath: "$", segments: [] }]);
  }
  let value: unknown;
  try { value = parseBytes(bytes, normalized.limits); } catch (error) {
    const rule = error instanceof InputFailure ? error.rule : "canonicalization";
    throw new AtifValidationError([{ rule, code: rule, path: "$", jsonPath: "$", segments: [] }]);
  }
  return validateDocument(value, normalized);
}

export function validateAtifDocument(value: unknown, options: AtifValidationOptions = {}): AtifDocument {
  return validateDocument(value, normalizeOptions(options));
}

export const parseAtif = validateAtifBytes;
export const validateAtif = validateAtifBytes;
export const validateCompleteAtif = validateAtifBytes;

export function tryValidateAtifBytes(source: AtifSource, options: AtifValidationOptions = {}, positionalArtifacts?: AtifArtifactCollection): AtifValidationResult {
  try { return { ok: true, value: validateAtifBytes(source, options, positionalArtifacts) }; }
  catch (error) {
    if (error instanceof AtifValidationError) return { ok: false, issues: error.issues };
    return { ok: false, issues: [{ rule: "canonicalization", code: "canonicalization", path: "$", jsonPath: "$", segments: [] }] };
  }
}

export const validateAtifBytesResult = tryValidateAtifBytes;

export function isValidAtifBytes(source: AtifSource, options: AtifValidationOptions = {}, positionalArtifacts?: AtifArtifactCollection): boolean {
  return tryValidateAtifBytes(source, options, positionalArtifacts).ok;
}
