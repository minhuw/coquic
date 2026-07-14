export type PublicStewardTask = {
  id: string;
  title: string;
  kind: string;
  workflow?: string;
  worker: string;
  priority: string;
  risk: string;
  status: string;
  summary: string;
  source: string;
  created_at: string;
  updated_at: string;
  detail_url?: string;
  detail_json?: string;
  validations: Array<{
    passed: boolean;
    exit_code: number;
    summary: string;
    iteration: number | null;
    started_at: string;
    completed_at: string;
  }>;
};

export type PublicStewardArtifact = {
  text: string;
  size: number;
  truncated: boolean;
  tail_bytes: number;
  mode?: 'redacted' | 'raw' | string;
  url?: string;
  sha256?: string;
} | null;

export type PublicStewardRunArtifact = {
  name: string;
  role: string;
  label: string;
  exit_code: number | null;
  completed: boolean | null;
  model?: string;
  reasoning_effort?: string;
  diagnostics: {
    status: string;
    summary: string;
    exit_code: number | null;
    last_message_present: boolean;
    event_count: number;
    error_count: number;
    last_event_type: string;
    last_item_type: string;
    last_item_status: string;
    last_error: string;
    last_output: string;
    timed_out: boolean;
  };
  transcript: PublicStewardArtifact;
  last_message: PublicStewardArtifact;
} | null;

export type PublicStewardValidationDetail = {
  index: number;
  command: string[];
  passed: boolean;
  exit_code: number;
  summary: string;
  iteration: number | null;
  started_at: string;
  completed_at: string;
  log: PublicStewardArtifact;
};

export type PublicStewardAttempt = {
  attempt: number;
  label: string;
  started_at?: string;
  updated_at?: string;
  worker: PublicStewardRunArtifact;
  reviewer: PublicStewardRunArtifact;
  review: Record<string, unknown> | null;
  patch: PublicStewardArtifact;
  validations: PublicStewardValidationDetail[];
};

export type PublicStewardPlanRun = {
  run: number;
  name: string;
  model: string;
  reasoning_effort: string;
  exit_code: number | null;
  completed: boolean | null;
  started_at: string;
  updated_at: string;
  plan: Record<string, unknown> | null;
  planner: PublicStewardRunArtifact;
};

export type PublicStewardEvent = {
  task_id: string;
  kind: string;
  message: string;
  created_at: string;
  data: Record<string, unknown>;
};

export type PublicStewardTaskDetail = {
  schema_version: number;
  generated_at: string;
  repository: string;
  main_branch: string;
  task: PublicStewardTask & {
    branch_name: string;
    spec: {
      id: string;
      kind: string;
      workflow?: string;
      worker: string;
      title: string;
      prompt: string;
      priority: string;
      risk: string;
      source: string;
      allow_main_write: boolean;
      metadata: Record<string, unknown>;
    };
    has_patch: boolean;
    has_transcript: boolean;
    has_last_message: boolean;
  };
  source_task: PublicStewardTaskDetail['task'] | null;
  events: PublicStewardEvent[];
  source_events: PublicStewardEvent[];
  attempts: PublicStewardAttempt[];
  plan_runs?: PublicStewardPlanRun[];
  validations: PublicStewardValidationDetail[];
  artifacts: {
    patch: PublicStewardArtifact;
    transcript: PublicStewardArtifact;
    last_message: PublicStewardArtifact;
  };
  integration: {
    is_integration_task: boolean;
    source_task_id: string | null;
    runs: Array<{
      task: PublicStewardTask;
      remote: { commit: string | null; commit_url: string | null };
      commit_message: { transcript: PublicStewardArtifact; last_message: PublicStewardArtifact } | null;
      push_log: PublicStewardArtifact;
    }>;
  };
  remote: { commit: string | null; commit_url: string | null };
};

export type PublicStewardSignalItem = {
  id: string;
  provider: string;
  kind: string;
  title: string;
  summary: string;
  severity: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  planned_at: string | null;
  planned_task_id: string | null;
  links: Array<{ label: string; url: string }>;
};

export type PublicStewardFetch = {
  id: string;
  provider: string;
  status: 'ok' | 'error';
  started_at: string;
  completed_at: string;
  item_count: number;
  new_item_count: number;
  has_more: boolean;
  summary: string;
  error: string | null;
};

export type PublicStewardProvider = {
  provider: string;
  poll_interval_minutes: number;
  error_retry_minutes: number;
  idle_poll_interval_minutes: number;
  suppression_hours: number;
  max_items: number;
  last_fetch_at: string | null;
  last_status: 'ok' | 'error' | null;
  last_error: string | null;
  next_due_at: string;
  idle_next_due_at?: string | null;
  due: boolean;
  idle_due?: boolean;
};

export type PublicStewardWakeup = {
  id: string;
  reason: string;
  status: string;
  created_at: string;
  consumed_at: string | null;
  data: Record<string, unknown>;
};

export type PublicStewardState = {
  schema_version: number;
  compatibility_state?: 'compatible' | 'unknown_additive' | 'incompatible' | string;
  generated_at: string;
  repository: string;
  main_branch: string;
  state: 'working' | 'queued' | 'attention' | 'idle';
  counts: {
    tasks: number;
    active: number;
    queued: number;
    attention: number;
    completed: number;
    signals: number;
    pending_signals: number;
  };
  audit: string[];
  configuration: {
    repository: string;
    main_branch: string;
    integration_mode: string;
    local_only: boolean;
    enabled_signals: string[];
    scheduler_wait_interval_sec: number;
    limits: Record<string, number | null>;
    signal_providers: Record<string, {
      poll_interval_minutes: number;
      error_retry_minutes: number;
      idle_poll_interval_minutes: number;
      suppression_hours: number;
      max_items: number;
    }>;
  };
  tasks: PublicStewardTask[];
  signals: {
    schema_version: number;
    repository: string;
    enabled_signals: string[];
    generated_at: string;
    summary: string;
    items: PublicStewardSignalItem[];
    fetches: PublicStewardFetch[];
  };
  scheduler: {
    source_active: number;
    source_capacity: number;
    source_queued: number;
    integration_active: number;
    integration_queued: number;
    pending_wakeups: PublicStewardWakeup[];
    recent_wakeups: PublicStewardWakeup[];
    providers: PublicStewardProvider[];
  };
  integration: {
    active: PublicStewardTask[];
    queue: PublicStewardTask[];
    commits: Array<{
      task_id: string;
      title: string;
      status: string;
      summary: string;
      commit: string;
      commit_url: string;
      updated_at: string;
    }>;
  };
  runtime?: {
    instance_id: string;
    started_at: string;
    heartbeat_at: string;
    state: 'starting' | 'idle' | 'active' | 'stopping' | string;
    current_cycle_started_at: string | null;
    current_cycle_reason: string | null;
    last_completed_cycle: {
      completed_at: string;
      reason: string;
      result: Record<string, number>;
    } | null;
    heartbeat_interval_seconds: number;
  };
  publication?: {
    state: 'disabled' | 'pending' | 'published' | 'failed' | string;
    generated_at: string;
    last_attempt_at: string | null;
    last_success_at: string | null;
    last_failure_at: string | null;
    last_failure_category: string | null;
    retry_count: number;
    last_accepted_digest: string | null;
  };
  tasks_truncated?: boolean;
  planner_runs?: unknown[];
  planner_runs_truncated?: boolean;
};

export type PublicTaskStageKey = 'plan' | 'code' | 'validation' | 'review' | 'integration';
export type PublicTaskStageState = 'pending' | 'active' | 'complete' | 'blocked';
export type PublicAttemptTab = 'transcript' | 'patch' | 'validation' | 'review';
export type PublicTaskStage = {
  detail: string;
  key: PublicTaskStageKey;
  label: string;
  state: PublicTaskStageState;
};
export type PublicTaskFlow = {
  activeKey: PublicTaskStageKey;
  loops: Record<'integration' | 'review' | 'validation', number>;
  stages: PublicTaskStage[];
};

export type PublicTimelineTone = 'neutral' | 'success' | 'danger' | 'review' | 'created';
export type PublicTimelineField = {
  label: string;
  value: string;
  kind?: 'path' | 'text';
};
export type PublicTimelineChip = {
  label: string;
  value: string;
  tone?: PublicTimelineTone;
};
export type PublicReviewShape = {
  verdict: string;
  summary: string;
  findings: Record<string, unknown>[];
  validation_gaps: string[];
  remaining_risk: string;
};
export type PublicTimelineModel = {
  title: string;
  description: string;
  tone: PublicTimelineTone;
  chips: PublicTimelineChip[];
  fields: PublicTimelineField[];
  review: PublicReviewShape | null;
};
export type PublicReviewFinding = {
  detail: string;
  file: string;
  line: number | null;
  recommendation: string;
  severity: string;
  title: string;
};
export type PublicReviewRecord = {
  attempt: number;
  command: string;
  created_at: string;
  event_kind: string;
  exit_code: number | null;
  findings: PublicReviewFinding[];
  remaining_risk: string;
  summary: string;
  validation_gaps: string[];
  verdict: string;
};
