export type StewardFreshness = 'live' | 'delayed' | 'stale' | 'offline' | 'incompatible';

export type StewardFreshnessInput = {
  compatibility_state?: string;
  generated_at?: string;
  runtime?: {
    heartbeat_at?: string;
    heartbeat_interval_seconds?: number;
    state?: string;
  };
};

export function classifyStewardFreshness(
  state: StewardFreshnessInput | null,
  nowMs = Date.now(),
  fetchFailed = false,
): StewardFreshness {
  if (!state) return 'offline';
  if (state.compatibility_state === 'incompatible') return 'incompatible';
  const heartbeatMs = Date.parse(state.runtime?.heartbeat_at ?? state.generated_at ?? '');
  if (!Number.isFinite(heartbeatMs)) return 'offline';
  const intervalMs = Math.max(5, state.runtime?.heartbeat_interval_seconds ?? 30) * 1000;
  const ageMs = Math.max(0, nowMs - heartbeatMs);
  if (fetchFailed) return 'stale';
  if (ageMs <= intervalMs * 2) return 'live';
  if (ageMs <= intervalMs * 4) return 'delayed';
  return 'stale';
}

export function stewardPollIntervalMs(
  state: StewardFreshnessInput | null,
  nowMs = Date.now(),
): number {
  const freshness = classifyStewardFreshness(state, nowMs);
  const active = state?.runtime?.state === 'active' || state?.runtime?.state === 'starting' || freshness === 'live' && state?.runtime?.state !== 'idle';
  if (active) return 10_000;
  if (freshness === 'stale' || freshness === 'offline') return 45_000;
  return 30_000;
}

export function stewardFreshnessLabel(value: StewardFreshness): string {
  return value[0].toUpperCase() + value.slice(1);
}
