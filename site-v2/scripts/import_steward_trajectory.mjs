import { readFileSync, writeFileSync } from "node:fs";
import parseDiff from "parse-diff";

const sourcePath = process.argv[2];
const outputPath = process.argv[3];
const statusPath = process.argv[4];

if (!sourcePath || !outputPath || !statusPath) {
  throw new Error("usage: node scripts/import_steward_trajectory.mjs <public-task.json> <v2-example.json> <public-status.json>");
}

const source = JSON.parse(readFileSync(sourcePath, "utf8"));
const status = JSON.parse(readFileSync(statusPath, "utf8"));

if (source.schema_version !== 2 || source.task?.id !== "task-20260712124934-e08ef7c8") {
  throw new Error("unexpected Steward task publication");
}

function assertRedacted(value) {
  if (Array.isArray(value)) {
    value.forEach(assertRedacted);
    return;
  }
  if (!value || typeof value !== "object") return;
  if ("mode" in value && value.mode !== "redacted") {
    throw new Error(`refusing to import ${value.mode} artifact`);
  }
  Object.values(value).forEach(assertRedacted);
}

assertRedacted(source);

const selectedSignalIds = new Set(source.task.spec.metadata.selected_signal_item_ids);
const issueUrl = status.signals?.items
  ?.find((item) => selectedSignalIds.has(item.id) && item.kind === "github-issues.feature-request")
  ?.links?.find((link) => link.label === "Open GitHub issue")?.url ?? null;

function durationSeconds(start, end) {
  return Math.max(0, Math.round((Date.parse(end) - Date.parse(start)) / 1000));
}

function excerpt(text, limit = 8000) {
  if (!text || text.length <= limit) return text || "";
  return `[earlier redacted transcript omitted]\n${text.slice(-limit)}`;
}

function validationSummary(record) {
  const truncated = record.log?.truncated === true;
  let text = excerpt(record.summary, 1800);
  if (truncated) {
    const firstLineEnd = text.indexOf("\n");
    if (firstLineEnd !== -1) text = text.slice(firstLineEnd + 1).trimStart();
  }
  return { text, truncated };
}

function commandFor(iteration, position) {
  const event = source.events.find((item) => item.data?.iteration === iteration && item.data?.position === position && Array.isArray(item.data.command));
  if (!event) return `validation gate ${position + 1}`;
  const command = event.data.command;
  const lastPlaceholder = command.lastIndexOf("[local-path]");
  return command.slice(lastPlaceholder >= 0 ? lastPlaceholder + 1 : 0).join(" ");
}

function patchFor(item, finalAttempt) {
  const files = parseDiff(item.patch.text).map((file) => ({
    path: file.to === "/dev/null" ? file.from : file.to,
    status: file.from === "/dev/null" ? "added" : file.to === "/dev/null" ? "deleted" : file.from !== file.to ? "renamed" : "modified",
    additions: file.additions,
    deletions: file.deletions,
    hunks: file.chunks.map((chunk) => ({
      header: chunk.content,
      lines: chunk.changes.map((change) => ({
        type: change.type === "add" ? "addition" : change.type === "del" ? "deletion" : "context",
        oldLine: change.type === "add" ? null : change.ln1 ?? change.ln ?? null,
        newLine: change.type === "del" ? null : change.ln2 ?? change.ln ?? null,
        content: change.content.slice(1),
      })),
    })),
  }));
  return {
    attempt: item.attempt,
    filesChanged: files.length,
    additions: files.reduce((sum, file) => sum + file.additions, 0),
    deletions: files.reduce((sum, file) => sum + file.deletions, 0),
    rawUrl: item.attempt === finalAttempt ? `${source.remote.commit_url}.patch` : null,
    files,
  };
}

function attemptStatus(item) {
  if (item.review?.verdict === "approve") return "accepted";
  if (item.review?.verdict === "block") return "revision-requested";
  if (item.validations.some((record) => !record.passed)) return "validation-failed";
  return "complete";
}

function attemptSummary(item) {
  if (item.review) return item.review.summary;
  const failure = item.validations.find((record) => !record.passed);
  if (failure) return `Validation returned the patch to implementation after ${commandFor(item.attempt, item.validations.indexOf(failure))} failed.`;
  return item.worker.last_message.text.split("\n").find(Boolean) || item.label;
}

const finalAttempt = source.attempts.at(-1).attempt;
const failedValidations = source.attempts.flatMap((item) => item.validations).filter((record) => !record.passed).length;
const blockedReviews = source.attempts.filter((item) => item.review?.verdict === "block").length;
const planRun = source.plan_runs[0];

function planRunStatus(item) {
  if (item.completed && item.exit_code === 0 && item.plan) return "succeeded";
  if (item.completed && item.exit_code === 0) return "invalid";
  if (item.exit_code !== null && item.exit_code !== undefined) return "failed";
  return "running";
}

const planRuns = source.plan_runs.map((item) => ({
  number: item.run,
  name: item.name,
  status: planRunStatus(item),
  startedAt: item.started_at,
  completedAt: item.updated_at ?? null,
  durationSeconds: item.updated_at ? durationSeconds(item.started_at, item.updated_at) : null,
  model: item.model ?? item.planner?.model ?? null,
  reasoningEffort: item.reasoning_effort ?? item.planner?.reasoning_effort ?? null,
  eventCount: item.planner?.diagnostics?.event_count ?? 0,
  exitCode: item.exit_code ?? null,
  summary: item.plan?.summary ?? item.planner?.last_message?.text?.split("\n").find(Boolean) ?? "No structured plan was produced.",
  transcript: {
    availability: item.planner?.transcript?.availability ?? "unavailable",
    mode: item.planner?.transcript?.mode ?? "redacted",
    sizeBytes: item.planner?.transcript?.size_bytes ?? 0,
    originalSizeBytes: item.planner?.transcript?.original_size_bytes ?? 0,
    truncated: item.planner?.transcript?.truncated === true,
    text: excerpt(item.planner?.transcript?.text, 8000),
  },
}));

const attempts = source.attempts.map((item) => ({
  number: item.attempt,
  label: item.label,
  status: attemptStatus(item),
  startedAt: item.started_at,
  completedAt: item.updated_at,
  summary: attemptSummary(item),
  workerRun: {
    name: item.worker.name,
    model: item.worker.model ?? null,
    reasoningEffort: item.worker.reasoning_effort ?? null,
    events: item.worker.diagnostics.event_count,
    exitCode: item.worker.exit_code,
    status: item.worker.diagnostics.status,
  },
  reviewerRun: item.reviewer ? {
    name: item.reviewer.name,
    model: item.reviewer.model ?? null,
    reasoningEffort: item.reviewer.reasoning_effort ?? null,
    events: item.reviewer.diagnostics.event_count,
    exitCode: item.reviewer.exit_code,
    status: item.reviewer.diagnostics.status,
  } : null,
  artifacts: {
    transcriptBytes: item.worker.transcript.size_bytes,
    patchBytes: item.patch.size_bytes,
    lastMessageBytes: item.worker.last_message.size_bytes,
    transcriptTruncated: item.worker.transcript.truncated,
  },
}));

const transcript = source.attempts.flatMap((item) => {
  const validationItems = item.validations.map((record, position) => {
    const published = validationSummary(record);
    return {
      id: `a${item.attempt}-validation-${position}`,
      attempt: item.attempt,
      kind: "tool",
      label: `Validation gate ${position + 1}`,
      timestamp: record.started_at,
      durationSeconds: durationSeconds(record.started_at, record.completed_at),
      command: commandFor(item.attempt, position),
      output: published.text,
      outputTruncated: published.truncated,
      exitCode: record.exit_code,
    };
  });
  return [
    {
      id: `a${item.attempt}-transcript`,
      attempt: item.attempt,
      kind: "reasoning",
      label: "Published worker transcript tail",
      timestamp: item.started_at,
      text: excerpt(item.worker.transcript.text),
    },
    ...validationItems,
    {
      id: `a${item.attempt}-final`,
      attempt: item.attempt,
      kind: "assistant",
      label: "Worker final message",
      timestamp: item.updated_at,
      text: item.worker.last_message.text,
    },
  ];
});

const validations = source.attempts.flatMap((item) => item.validations.map((record, position) => {
  const published = validationSummary(record);
  return {
    id: `attempt-${item.attempt}-validation-${position}`,
    attempt: item.attempt,
    command: commandFor(item.attempt, position),
    status: record.passed ? "passed" : "failed",
    exitCode: record.exit_code,
    durationSeconds: durationSeconds(record.started_at, record.completed_at),
    summary: published.text,
    summaryTruncated: published.truncated,
  };
}));

const reviews = source.attempts.filter((item) => item.review).map((item) => ({
  attempt: item.attempt,
  verdict: item.review.verdict === "approve" ? "accept" : "block",
  summary: item.review.summary,
  findings: item.review.findings,
  validationGaps: item.review.validation_gaps,
  remainingRisk: item.review.remaining_risk,
}));

const attemptsWithValidation = source.attempts.filter((item) => item.validations.length > 0);
const failedValidationAttempts = source.attempts.flatMap((item) => {
  const position = item.validations.findIndex((record) => !record.passed);
  return position === -1 ? [] : [{ item, position }];
});
const reviewedAttempts = source.attempts.filter((item) => item.review);
const blockedAttempts = reviewedAttempts.filter((item) => item.review.verdict === "block");
const approvedAttempts = reviewedAttempts.filter((item) => item.review.verdict === "approve");

const transitions = [
  {
    from: "plan",
    to: "implementation",
    count: source.attempts.length ? 1 : 0,
    label: "Plan to implementation",
    attempts: source.attempts.length ? [source.attempts[0].attempt] : [],
    causes: source.attempts.length ? [{ attempt: source.attempts[0].attempt, detail: "The completed plan released the first worker attempt." }] : [],
  },
  {
    from: "implementation",
    to: "validation",
    count: attemptsWithValidation.length,
    label: "Implementation to validation",
    attempts: attemptsWithValidation.map((item) => item.attempt),
    causes: attemptsWithValidation.map((item) => ({ attempt: item.attempt, detail: `${item.label} submitted ${item.validations.length} validation gates.` })),
  },
  {
    from: "validation",
    to: "implementation",
    count: failedValidationAttempts.length,
    label: "Validation returned to implementation",
    attempts: failedValidationAttempts.map(({ item }) => item.attempt),
    causes: failedValidationAttempts.map(({ item, position }) => ({ attempt: item.attempt, detail: `${commandFor(item.attempt, position)} failed.` })),
  },
  {
    from: "validation",
    to: "review",
    count: reviewedAttempts.length,
    label: "Validation to review",
    attempts: reviewedAttempts.map((item) => item.attempt),
    causes: reviewedAttempts.map((item) => ({ attempt: item.attempt, detail: `All ${item.validations.length} validation gates passed.` })),
  },
  {
    from: "review",
    to: "implementation",
    count: blockedAttempts.length,
    label: "Review returned to implementation",
    attempts: blockedAttempts.map((item) => item.attempt),
    causes: blockedAttempts.map((item) => ({ attempt: item.attempt, detail: item.review.findings[0]?.title || item.review.summary })),
  },
  {
    from: "review",
    to: "integration",
    count: approvedAttempts.length,
    label: "Review to integration",
    attempts: approvedAttempts.map((item) => item.attempt),
    causes: approvedAttempts.map((item) => ({ attempt: item.attempt, detail: "Review approved the attempt for integration." })),
  },
];

const timeline = [
  {
    id: "plan-started",
    stage: "plan",
    kind: "plan.started",
    timestamp: planRun.started_at,
    title: "Implementation plan started",
    detail: `${planRun.planner.model} scoped ${planRun.plan.steps.length} implementation steps.`,
  },
  {
    id: "plan-completed",
    stage: "plan",
    kind: "plan.completed",
    timestamp: planRun.updated_at,
    title: "Implementation plan completed",
    detail: planRun.plan.summary,
  },
  ...source.attempts.flatMap((item) => {
    const events = [{
      id: `attempt-${item.attempt}-started`,
      stage: "implementation",
      kind: "worker.started",
      timestamp: item.started_at,
      title: `${item.label} started`,
      detail: item.worker.last_message.text.split("\n").find(Boolean) || item.label,
    }];
    const failure = item.validations.find((record) => !record.passed);
    if (failure) events.push({
      id: `attempt-${item.attempt}-validation-failed`,
      stage: "validation",
      kind: "validation.failed",
      timestamp: failure.completed_at,
      title: "Validation returned the patch",
      detail: `${commandFor(item.attempt, item.validations.indexOf(failure))} exited ${failure.exit_code}.`,
    });
    if (item.review) events.push({
      id: `attempt-${item.attempt}-review`,
      stage: "review",
      kind: item.review.verdict === "approve" ? "review.accepted" : "review.blocked",
      timestamp: item.updated_at,
      title: item.review.verdict === "approve" ? "Reviewer approved" : "Reviewer requested revision",
      detail: item.review.summary,
    });
    return events;
  }),
  {
    id: "integration-pushed",
    stage: "integration",
    kind: "integration.pushed",
    timestamp: source.task.updated_at,
    title: "Integrated to main",
    detail: `Integration task ${source.integration.runs[0].task.id} pushed commit ${source.remote.commit.slice(0, 10)}.`,
  },
];

const output = {
  schemaVersion: "2.2",
  generatedAt: source.generated_at,
  data: {
    task: {
      id: source.task.id,
      title: source.task.title,
      kind: source.task.kind,
      workflow: source.task.workflow,
      worker: source.task.worker,
      priority: source.task.priority,
      risk: source.task.risk,
      status: source.task.status,
      summary: `Five attempts resolved ${failedValidations} validation failures and ${blockedReviews} blocked reviews before approval and integration.`,
      createdAt: source.task.created_at,
      updatedAt: source.task.updated_at,
      sourceSignalIds: source.task.spec.metadata.selected_signal_item_ids,
      issueUrl,
      plannerRunId: planRun.name,
      commit: source.remote.commit,
      commitUrl: source.remote.commit_url,
    },
    pipeline: {
      stages: [
        { id: "plan", label: "Plan", state: "complete", detail: `${planRun.plan.steps.length} scoped steps` },
        { id: "implementation", label: "Implement", state: "complete", detail: `${attempts.length} worker attempts` },
        { id: "validation", label: "Validate", state: "complete", detail: `${validations.length} gate executions` },
        { id: "review", label: "Review", state: "complete", detail: `${blockedReviews} blocks, 1 approval` },
        { id: "integration", label: "Integrate", state: "complete", detail: "Pushed to main" },
      ],
      transitions,
    },
    plan: {
      objective: planRun.plan.summary,
      sourceContext: "GitHub issue #20 · connection: replay exact close packet while closing",
      constraints: planRun.plan.non_goals,
      validationCommands: planRun.plan.validation.map((item) => item.replaceAll("`", "")),
      completeness: "complete",
      steps: planRun.plan.steps,
    },
    planRuns,
    attempts,
    transcript,
    patches: source.attempts.map((item) => patchFor(item, finalAttempt)),
    validations,
    reviews,
    timeline,
    completeness: {
      state: "partial",
      transcript: "Sanitized public transcript tails are excerpted for this local V2 preview; the public task publication remains authoritative.",
      warnings: ["All displayed transcripts are redacted public artifacts.", "Long transcript tails are shortened again for the local preview."],
    },
  },
};

writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`);
