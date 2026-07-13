import { readFileSync } from 'node:fs';
import path from 'node:path';

import type { PublicArtifact, PublicPlannerRun, PublicStewardMonitor } from '../src/generated/steward-public';
import type { PublicStewardState, PublicStewardTaskDetail } from '../src/components/steward-public';

const repositoryRoot = path.resolve(process.cwd(), '../..');
export const monitorFixtureDirectory = path.join(
  repositoryRoot,
  'steward',
  'schema',
  'fixtures',
  'public-monitor-v3',
);

export function loadMonitorFixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(path.join(monitorFixtureDirectory, `${name}.json`), 'utf8'),
  ) as Record<string, unknown>;
}

export function loadMonitorFixtureText(name: string): string {
  return readFileSync(path.join(monitorFixtureDirectory, `${name}.json`), 'utf8');
}

export const PRODUCER_FIXTURE_NAMES = [
  'active',
  'blocked',
  'empty',
  'failed',
  'idle',
  'integration',
  'stale',
] as const;
export type ProducerFixtureName = (typeof PRODUCER_FIXTURE_NAMES)[number];

export function producerFixture(name: ProducerFixtureName): PublicStewardMonitor {
  return loadMonitorFixture(name) as unknown as PublicStewardMonitor;
}

export function producerFixtureText(name: ProducerFixtureName): string {
  return loadMonitorFixtureText(name);
}

export function asLegacyStewardState(monitor: PublicStewardMonitor): PublicStewardState {
  return monitor as unknown as PublicStewardState;
}

export function taskWindow(count = 11): PublicStewardMonitor {
  const monitor = producerFixture('active');
  const template = monitor.tasks[0];
  if (!template) throw new Error('active producer fixture has no task');
  monitor.tasks = Array.from({ length: count }, (_, index) => ({
    ...template,
    id: `task-202607131159${String(45 + index).padStart(2, '0')}-a1b2c3d4`,
    title: `${template.title} ${index + 1}`,
    updated_at: `2026-07-13T12:${String(index).padStart(2, '0')}:00Z`,
  }));
  monitor.counts.tasks = count;
  monitor.counts.active = count;
  return monitor;
}

export function signalMonitor(): PublicStewardMonitor {
  const monitor = producerFixture('active');
  monitor.scheduler.providers = [{
    provider: 'github-actions:ci',
    poll_interval_minutes: 30,
    error_retry_minutes: 30,
    idle_poll_interval_minutes: 30,
    suppression_hours: 1,
    max_items: 3,
    last_fetch_at: '2026-07-13T11:55:00Z',
    last_status: 'ok',
    last_error: null,
    next_due_at: '2026-07-13T12:25:00Z',
    idle_next_due_at: '2026-07-13T12:25:00Z',
    due: false,
    idle_due: false,
  }];
  return monitor;
}

function artifact(overrides: Partial<NonNullable<PublicArtifact>> = {}): NonNullable<PublicArtifact> {
  return {
    availability: 'available',
    mode: 'redacted',
    text: 'planner output is safe for the public monitor',
    size_bytes: 48,
    original_size_bytes: 48,
    truncated: false,
    sha256: null,
    url: null,
    ...overrides,
  };
}

function plannerRun(run: number, status: PublicPlannerRun['status'] = 'succeeded'): PublicPlannerRun {
  const id = `planner-task-2026071312${String(run).padStart(2, '0')}-a1b2c3d4`;
  return {
    id,
    status,
    started_at: '2026-07-13T11:50:00Z',
    completed_at: status === 'running' ? null : '2026-07-13T11:50:30Z',
    accepted_count: status === 'succeeded' ? 1 : 0,
    proposed_count: status === 'invalid' ? 0 : 2,
    consumed_signal_ids: ['wi-signal-item-a1b2c3d4'],
    diagnostics: {
      summary: status === 'failed' ? 'planner provider failed' : 'planner completed',
      exit_code: status === 'succeeded' ? 0 : status === 'running' ? null : 1,
      error_category: status === 'succeeded' ? 'none' : status === 'invalid' ? 'invalid_output' : 'provider_error',
      last_message_present: status !== 'invalid',
    },
    artifacts: {
      transcript: status === 'invalid'
        ? artifact({ availability: 'redacted', text: '', original_size_bytes: 1024, size_bytes: 0, truncated: true })
        : artifact(),
      last_message: status === 'failed' ? null : artifact({ text: 'accepted one public signal' }),
    },
  };
}

export function plannerMonitor(): PublicStewardMonitor {
  const monitor = producerFixture('idle');
  monitor.planner_runs = [
    plannerRun(1, 'succeeded'),
    plannerRun(2, 'failed'),
    plannerRun(3, 'invalid'),
    ...Array.from({ length: 8 }, (_, index) => plannerRun(index + 4)),
  ];
  monitor.planner_runs_truncated = true;
  return monitor;
}

export function taskDetail(): PublicStewardTaskDetail {
  const monitor = producerFixture('active');
  const summary = monitor.tasks[0];
  if (!summary) throw new Error('active producer fixture has no task');
  return {
    schema_version: 1,
    generated_at: monitor.generated_at,
    repository: monitor.repository,
    main_branch: monitor.main_branch,
    task: {
      ...summary,
      branch_name: 'steward/task-20260713115945-a1b2c3d4',
      spec: {
        id: summary.id,
        kind: summary.kind,
        workflow: summary.workflow,
        worker: summary.worker,
        title: summary.title,
        prompt: 'Run the focused public monitor checks.',
        priority: summary.priority,
        risk: summary.risk,
        source: summary.source,
        allow_main_write: false,
        metadata: {},
      },
      has_patch: false,
      has_transcript: false,
      has_last_message: false,
    },
    source_task: null,
    events: [{
      task_id: summary.id,
      kind: 'task.created',
      message: 'Task created',
      created_at: summary.created_at,
      data: {},
    }],
    source_events: [],
    attempts: [],
    plan_runs: [],
    validations: [],
    artifacts: { patch: null, transcript: null, last_message: null },
    integration: { is_integration_task: false, source_task_id: null, runs: [] },
    remote: { commit: null, commit_url: null },
  };
}
