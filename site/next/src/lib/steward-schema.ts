import type { PublicStewardMonitor } from '@/generated/steward-public';

export const PUBLIC_STEWARD_SCHEMA_VERSION = 3;

export type StewardSchemaDecode =
  | { ok: true; data: PublicStewardMonitor }
  | { ok: false; reason: 'malformed' | 'incompatible' | 'invalid' };

const REQUIRED_FIELDS = [
  'schema_version',
  'compatibility_state',
  'generated_at',
  'repository',
  'main_branch',
  'state',
  'counts',
  'runtime',
  'publication',
  'tasks',
  'tasks_truncated',
  'signals',
  'scheduler',
  'planner_runs',
  'planner_runs_truncated',
  'configuration',
  'integration',
] as const;

export function decodePublicStewardMonitor(value: unknown): StewardSchemaDecode {
  if (!isRecord(value)) return { ok: false, reason: 'malformed' };
  if (value.schema_version !== PUBLIC_STEWARD_SCHEMA_VERSION) {
    return { ok: false, reason: 'incompatible' };
  }
  if (REQUIRED_FIELDS.some((field) => !(field in value))) {
    return { ok: false, reason: 'invalid' };
  }
  if (
    !isRecord(value.counts)
    || !isRecord(value.runtime)
    || !isRecord(value.publication)
    || !Array.isArray(value.tasks)
    || typeof value.tasks_truncated !== 'boolean'
    || !isRecord(value.signals)
    || typeof value.signals.items_truncated !== 'boolean'
    || typeof value.signals.fetches_truncated !== 'boolean'
    || !isRecord(value.scheduler)
    || !Array.isArray(value.planner_runs)
    || typeof value.planner_runs_truncated !== 'boolean'
    || !isRecord(value.configuration)
    || !isRecord(value.integration)
  ) {
    return { ok: false, reason: 'invalid' };
  }
  return { ok: true, data: value as PublicStewardMonitor };
}

export function decodePublicStewardJson(text: string): StewardSchemaDecode {
  try {
    return decodePublicStewardMonitor(JSON.parse(text) as unknown);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
