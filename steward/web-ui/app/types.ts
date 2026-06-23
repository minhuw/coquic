export type TaskStatus =
  | "queued"
  | "running"
  | "reviewing"
  | "integrating"
  | "succeeded"
  | "pushed"
  | "no_changes"
  | "blocked"
  | "failed"
  | "cancelled";

export type TaskSpec = {
  id: string;
  kind: string;
  worker: string;
  title: string;
  prompt: string;
  priority: string;
  risk: string;
  source: string;
  allow_main_write: boolean;
  metadata: Record<string, unknown>;
};

export type ValidationResult = {
  command: string[];
  cwd: string;
  passed: boolean;
  exit_code: number;
  output_path: string;
  summary: string;
  iteration: number | null;
  started_at: string;
  completed_at: string;
};

export type CodexRunDiagnostics = {
  status: string;
  summary: string;
  exit_code: number | null;
  transcript_path: string | null;
  last_message_path: string | null;
  last_message_present: boolean;
  event_count: number;
  error_count: number;
  last_event_type: string;
  last_item_type: string;
  last_item_status: string;
  last_error: string;
  last_output: string;
  thread_id: string | null;
  timed_out: boolean;
};

export type TaskRecord = {
  spec: TaskSpec;
  status: TaskStatus;
  summary: string;
  created_at: string;
  updated_at: string;
  worktree_path: string | null;
  branch_name: string | null;
  transcript_path: string | null;
  last_message_path: string | null;
  patch_path: string | null;
  validations: ValidationResult[];
};

export type TaskRunArtifact = {
  name: string;
  role: "worker" | "reviewer";
  attempt: number;
  review_run?: number;
  label: string;
  transcript_path: string;
  prompt_path: string | null;
  last_message_path: string | null;
  updated_at: string;
  exit_code?: number | null;
  completed?: boolean | null;
  diagnostics?: CodexRunDiagnostics | null;
};

export type TaskAttempt = {
  attempt: number;
  label: string;
  worker: TaskRunArtifact | null;
  reviewer: TaskRunArtifact | null;
  review?: Record<string, unknown> | null;
  patch_path?: string | null;
  validations: Array<ValidationResult & { index: number }>;
};

export type EventRecord = {
  task_id: string;
  kind: string;
  message: string;
  created_at: string;
  data: Record<string, unknown>;
};

export type PlannedTask = {
  task: TaskSpec;
  dedupe_key: string;
};

export type StewardProject = {
  id: string;
  label: string;
  state_dir: string;
  active: boolean;
  task_count: number;
};

export type SignalItem = {
  id: string;
  provider: string;
  kind: string;
  fingerprint: string;
  title: string;
  summary: string;
  severity: string | null;
  location: Record<string, unknown> | null;
  links: Array<{ label: string; url: string }>;
  payload: Record<string, unknown>;
  status: "pending" | "planned" | "superseded" | "errored";
  created_at: string;
  updated_at: string;
  planned_at: string | null;
  planner_run_id: string | null;
  planned_task_id: string | null;
  source_fetch_id: string | null;
};

export type SignalFetchRun = {
  id: string;
  provider: string;
  status: "ok" | "error";
  started_at: string;
  completed_at: string;
  item_count: number;
  new_item_count: number;
  has_more: boolean;
  error: string | null;
  summary: string;
};

export type SchedulerWakeup = {
  id: string;
  reason: string;
  status: "pending" | "consumed";
  created_at: string;
  consumed_at: string | null;
  data: Record<string, unknown>;
};

export type SchedulerProviderState = {
  provider: string;
  poll_interval_minutes: number;
  error_retry_minutes: number;
  suppression_hours: number;
  max_items: number;
  last_fetch_at: string | null;
  last_status: "ok" | "error" | null;
  last_error: string | null;
  next_due_at: string;
  due: boolean;
};

export type SchedulerState = {
  source_active: number;
  source_capacity: number;
  source_queued: number;
  integration_active: number;
  integration_queued: number;
  pending_wakeups: SchedulerWakeup[];
  recent_wakeups: SchedulerWakeup[];
  providers: SchedulerProviderState[];
};

export type IntegrationRun = {
  run_id: string;
  task_id: string;
  title: string;
  status: string;
  summary: string;
  source_task_id: string | null;
  source_title: string;
  source_status: string;
  source_patch_path: string | null;
  patch_path: string | null;
  transcript_path: string | null;
  worktree_path: string | null;
  updated_at: string;
  remote: {
    commit: string | null;
    commit_url: string | null;
  };
  events: EventRecord[];
};

export type IntegrationCommit = {
  task_id: string;
  title: string;
  status: string;
  summary: string;
  commit: string;
  commit_url: string;
  updated_at: string;
};

export type IntegrationDetail = {
  run: IntegrationRun;
  source_task: TaskRecord | null;
  events: EventRecord[];
  source_events: EventRecord[];
  validations: Array<ValidationResult & { index: number }>;
  remote: {
    commit: string | null;
    commit_url: string | null;
  };
  commit_message?: {
    transcript_path: string | null;
    last_message_path: string | null;
    transcript: string;
    last_message: string;
    diagnostics?: CodexRunDiagnostics | null;
  } | null;
  push_log?: {
    path: string;
    text: string;
  } | null;
};

export type StewardState = {
  tasks: TaskRecord[];
  audit: string[];
  planned: PlannedTask[];
  projects?: StewardProject[];
  kinds: string[];
  workers: string[];
  signals: {
    schema_version: number;
    repository: string;
    enabled_signals: string[];
    generated_at: string;
    summary: string;
    items: SignalItem[];
    fetches: SignalFetchRun[];
  };
  signal_inbox?: {
    items: SignalItem[];
    fetch_runs: SignalFetchRun[];
  };
  scheduler?: SchedulerState;
  integration: {
    queue: IntegrationRun[];
    active: IntegrationRun[];
    runs?: IntegrationRun[];
    commits: IntegrationCommit[];
  };
  config: {
    repo_root: string;
    state_dir: string;
    worktrees_dir: string;
    integration_mode: string;
    local_only: boolean;
    main_branch: string;
    github_repository: string;
    enabled_signals: string[];
  };
};

export type PlannerRunSummary = {
  run_id: string;
  prompt_path: string | null;
  transcript_path: string | null;
  prompt_bytes: number;
  transcript_bytes: number;
  updated_at: string | null;
  diagnostics?: CodexRunDiagnostics | null;
};

export type PlannerRunArtifact = PlannerRunSummary & {
  prompt: string;
  transcript: string;
};

export type TaskDetail = {
  task: TaskRecord;
  events: EventRecord[];
  attempts: TaskAttempt[];
  remote: {
    commit: string | null;
    commit_url: string | null;
  };
  files: {
    worktree: string | null;
    patch: string | null;
    transcript: string | null;
    integration_transcript: string | null;
    last_message: string | null;
    review_transcript: string | null;
  };
};
