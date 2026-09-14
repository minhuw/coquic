export const STEWARD_LIVE_SCHEMA_VERSION = "1.0" as const;

export type StewardLiveSnapshot = {
  readonly schemaVersion: typeof STEWARD_LIVE_SCHEMA_VERSION;
  readonly availability: "live" | "stale";
  readonly observedAt: string;
  readonly staleAfterSeconds: number;
  readonly daemon: { readonly mode: "production" | "dry-run" };
  readonly signals: { readonly pending: number };
  readonly planning: { readonly state: "active" | "idle" | "paused" };
  readonly tasks: { readonly active: number; readonly queued: number };
  readonly integration: { readonly active: number; readonly queued: number };
};

const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/;

function invalid(): never {
  throw new Error("invalid Steward live snapshot");
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const row = value as Record<string, unknown>;
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalid();
  return row;
}

function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) invalid();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString().slice(0, 19) !== value.slice(0, 19)) invalid();
  return value;
}

export function validateStewardLiveSnapshot(value: unknown): StewardLiveSnapshot {
  const snapshot = record(value, [
    "schemaVersion", "availability", "observedAt", "staleAfterSeconds", "daemon",
    "signals", "planning", "tasks", "integration",
  ]);
  if (snapshot.schemaVersion !== STEWARD_LIVE_SCHEMA_VERSION) invalid();
  if (snapshot.availability !== "live" && snapshot.availability !== "stale") invalid();
  const staleAfterSeconds = count(snapshot.staleAfterSeconds);
  if (staleAfterSeconds < 30 || staleAfterSeconds > 3600) invalid();

  const daemon = record(snapshot.daemon, ["mode"]);
  if (daemon.mode !== "production" && daemon.mode !== "dry-run") invalid();
  const signals = record(snapshot.signals, ["pending"]);
  const planning = record(snapshot.planning, ["state"]);
  if (planning.state !== "active" && planning.state !== "idle" && planning.state !== "paused") invalid();
  const tasks = record(snapshot.tasks, ["active", "queued"]);
  const integration = record(snapshot.integration, ["active", "queued"]);

  return {
    schemaVersion: STEWARD_LIVE_SCHEMA_VERSION,
    availability: snapshot.availability,
    observedAt: timestamp(snapshot.observedAt),
    staleAfterSeconds,
    daemon: { mode: daemon.mode },
    signals: { pending: count(signals.pending) },
    planning: { state: planning.state },
    tasks: { active: count(tasks.active), queued: count(tasks.queued) },
    integration: { active: count(integration.active), queued: count(integration.queued) },
  };
}

export function parseStewardLiveSnapshot(source: string): StewardLiveSnapshot {
  try {
    return validateStewardLiveSnapshot(JSON.parse(source));
  } catch {
    invalid();
  }
}
