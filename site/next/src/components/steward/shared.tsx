import { Activity, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react';

import { Badge } from '@/components/ui/badge';
import { classifyStewardFreshness, stewardFreshnessLabel } from '@/lib/steward-freshness';

import type {
  PublicStewardState,
} from './types';

export type StewardStatusTone = 'success' | 'warning' | 'danger' | 'neutral';

const STEWARD_STATUS_TONES: Record<StewardStatusTone, ReadonlySet<string>> = {
  success: new Set(['pushed', 'succeeded', 'ok', 'published', 'no_changes', 'complete']),
  warning: new Set(['queued', 'pending', 'delayed', 'stale', 'attention']),
  danger: new Set(['failed', 'blocked', 'error', 'invalid', 'incompatible', 'offline', 'cancelled']),
  neutral: new Set(['idle', 'running', 'reviewing', 'integrating', 'working', 'planned', 'starting', 'active', 'stopping']),
};

export function stewardStatusTone(status: string): StewardStatusTone {
  for (const [tone, statuses] of Object.entries(STEWARD_STATUS_TONES) as Array<[StewardStatusTone, ReadonlySet<string>]>) {
    if (statuses.has(status)) return tone;
  }
  return 'neutral';
}

export function handleTabKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
  const direction = event.key === 'ArrowRight' || event.key === 'ArrowDown'
    ? 1
    : event.key === 'ArrowLeft' || event.key === 'ArrowUp'
      ? -1
      : 0;
  const tablist = event.currentTarget.closest('[role="tablist"]');
  const tabs = tablist ? Array.from(tablist.querySelectorAll<HTMLElement>('[role="tab"]')) : [];
  const currentIndex = tabs.indexOf(event.currentTarget);
  if (!tabs.length || currentIndex < 0 || (!direction && event.key !== 'Home' && event.key !== 'End')) return;

  const nextIndex = event.key === 'Home'
    ? 0
    : event.key === 'End'
      ? tabs.length - 1
      : (currentIndex + direction + tabs.length) % tabs.length;
  event.preventDefault();
  tabs[nextIndex]?.focus();
  tabs[nextIndex]?.click();
}

export function StatusBadge({ status }: { status: string }) {
  if (['pushed', 'succeeded', 'ok', 'idle'].includes(status)) return <Badge variant="success">{status}</Badge>;
  if (['running', 'reviewing', 'integrating', 'working', 'planned'].includes(status)) return <Badge variant="primary">{status}</Badge>;
  if (['queued', 'pending'].includes(status)) return <Badge variant="warning">{status}</Badge>;
  if (['failed', 'blocked', 'error', 'attention'].includes(status)) return <Badge variant="danger">{status}</Badge>;
  return <Badge>{status}</Badge>;
}

export function StatusPill({ status }: { status: string }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

export function PanelTitle({ description, icon, title }: { description?: string; icon?: ReactNode; title: string }) {
  return (
    <div className="steward-panel-title">
      {icon}
      <div>
        <h3>{title}</h3>
        {description && <p>{description}</p>}
      </div>
    </div>
  );
}

export function relativeTime(value: string | null | undefined) {
  if (!value) return '-';
  const ms = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(ms)) return '-';
  const abs = Math.abs(ms);
  const suffix = ms >= 0 ? 'ago' : 'from now';
  if (abs < 60_000) return `${Math.max(1, Math.round(abs / 1000))}s ${suffix}`;
  if (abs < 3_600_000) return `${Math.round(abs / 60_000)}m ${suffix}`;
  if (abs < 86_400_000) return `${Math.round(abs / 3_600_000)}h ${suffix}`;
  return `${Math.round(abs / 86_400_000)}d ${suffix}`;
}

export function shortDate(value: string) {
  if (!value) return '-';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
}

export function shortSha(value: string) {
  return value.length > 12 ? value.slice(0, 12) : value;
}

export function StewardUnavailableNotice() {
  return (
    <div className="rounded-[var(--radius)] border border-[var(--line)] bg-[var(--surface-2)] p-4 text-sm text-[var(--muted)]">
      <div className="mb-2 flex items-center gap-2 font-medium text-[var(--ink)]">
        <AlertTriangle className="size-4 text-[var(--warning)]" />
        Public Steward mirror unavailable
      </div>
      The daemon will publish this file after its next state change.
    </div>
  );
}

export function StewardFreshness({
  state,
  fetchError = false,
}: {
  state: PublicStewardState | null;
  fetchError?: boolean;
}) {
  const freshness = classifyStewardFreshness(state, Date.now(), fetchError);
  const Icon = freshness === 'live' ? CheckCircle2 : freshness === 'incompatible' || freshness === 'offline' ? XCircle : AlertTriangle;
  return (
    <div className={`steward-freshness freshness-${freshness}`} role="status" aria-live="polite">
      <Icon className="size-4" />
      <span>{stewardFreshnessLabel(freshness)}</span>
      <span className="steward-freshness-detail">
        {state ? `heartbeat ${relativeTime(state.runtime?.heartbeat_at ?? state.generated_at)}` : 'waiting for snapshot'}
      </span>
    </div>
  );
}
