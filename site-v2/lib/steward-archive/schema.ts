import Ajv2020, { type AnySchema, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import commonSchema from "../../schemas/common.schema.json";
import stewardSchema from "../../schemas/steward-dataset.schema.json";
import controlLoopSchema from "../../schemas/steward-control-loop.schema.json";

export type JsonRecord = Record<string, unknown>;

export function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function parseCompleteJson<T extends JsonRecord>(source: string, label: string): T {
  if (!source.trim()) throw new Error(`${label} is empty`);
  const value: unknown = JSON.parse(source);
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value as T;
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(commonSchema as AnySchema);
ajv.addSchema(stewardSchema as AnySchema);
ajv.addSchema(controlLoopSchema as AnySchema);

const schemaId = String(stewardSchema.$id);
const controlSchemaId = String(controlLoopSchema.$id);
const validators = new Map<string, ValidateFunction>();

function validatorFor(definition: string) {
  let validator = validators.get(definition);
  if (!validator) {
    validator = ajv.compile({ $ref: `${schemaId}#/$defs/${definition}` });
    validators.set(definition, validator);
  }
  return validator;
}

function controlValidatorFor(definition: string) {
  const key = `control:${definition}`;
  let validator = validators.get(key);
  if (!validator) {
    validator = ajv.compile({ $ref: `${controlSchemaId}#/$defs/${definition}` });
    validators.set(key, validator);
  }
  return validator;
}

function validateDefinition(value: unknown, definition: string, label: string): JsonRecord {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const validator = validatorFor(definition);
  if (!validator(value)) {
    const issue = validator.errors?.[0];
    const location = issue?.instancePath || "/";
    throw new Error(`${label} does not match the archive contract at ${location}`);
  }
  return value;
}

function validateControlDefinition(value: unknown, definition: string, label: string): JsonRecord {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const validator = controlValidatorFor(definition);
  if (!validator(value)) {
    const issue = validator.errors?.[0];
    const location = issue?.instancePath || "/";
    throw new Error(`${label} does not match the control-loop contract at ${location}`);
  }
  return value;
}

export function validateControlEpoch(value: JsonRecord) {
  return validateControlDefinition(value, "epoch", "control-loop epoch.json") as {
    epochId: string;
    formatVersion: "1.0";
    taskFormatVersion: "1.0";
    policy: "post-steward-2.0";
    startedAt: string;
  };
}

export function validateControlCurrent(value: JsonRecord) {
  return validateControlDefinition(value, "current", "control-loop current.json");
}

export function validateControlManifest(value: JsonRecord) {
  const manifest = validateControlDefinition(value, "manifest", "planner-run manifest.json");
  let previous = "";
  for (const item of manifest.files as JsonRecord[]) {
    const path = String(item.path);
    if (path <= previous) throw new Error("planner manifest files must be unique and sorted");
    previous = path;
  }
  return manifest;
}

export function validateControlEvent(value: JsonRecord) {
  return validateControlDefinition(value, "event", "control-loop event");
}

export function validateArtifact(value: unknown, label = "artifact") {
  return validateDefinition(value, "artifact", label);
}

export function validateEpoch(value: JsonRecord) {
  return validateDefinition(value, "epoch", "epoch.json") as {
    epochId: string;
    formatVersion: "1.0";
    policy: "post-steward-2.0";
    startedAt: string;
    endedAt?: string | null;
  };
}

export function validateTask(value: JsonRecord) {
  return validateDefinition(value, "task", "task.json");
}

export function validatePipeline(value: JsonRecord) {
  return validateDefinition(value, "pipeline", "pipeline.json");
}

export function validateRun(value: JsonRecord) {
  return validateDefinition(value, "run", "run.json");
}

export function validateValidation(value: JsonRecord) {
  return validateDefinition(value, "validation", "validation.json");
}

export function validateReview(value: JsonRecord) {
  return validateDefinition(value, "review", "review.json");
}

export function validateManifest(value: JsonRecord) {
  const manifest = validateDefinition(value, "manifest", "manifest.json");
  let previous = "";
  for (const item of manifest.files as JsonRecord[]) {
    const path = String(item.path);
    if (path <= previous) throw new Error("manifest files must be unique and sorted");
    previous = path;
  }
  return manifest;
}

export function safeString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function safeInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

const TASK_STATES = new Set(["queued", "running", "reviewing", "integrating", "succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
const TERMINAL_TASK_STATES = new Set(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
export { TASK_STATES, TERMINAL_TASK_STATES };
