import {
  Activity,
  CheckCircle2,
  Circle,
  GitBranch,
  ListChecks,
  XCircle,
} from "lucide-react";
import type { ReactNode } from "react";
import type { EventRecord } from "./types";

type TimelineTone = "neutral" | "success" | "danger" | "review" | "created";

type TimelineField = {
  label: string;
  value: string;
  kind?: "path" | "text";
};

type TimelineChip = {
  label: string;
  value: string;
  tone?: TimelineTone;
};

type ReviewShape = {
  verdict: string;
  summary: string;
  findings: Record<string, unknown>[];
  validation_gaps: string[];
  remaining_risk: string;
};

type TimelineModel = {
  title: string;
  description: string;
  tone: TimelineTone;
  chips: TimelineChip[];
  fields: TimelineField[];
  review: ReviewShape | null;
};

export function TimelineEvent({ event }: { event: EventRecord }) {
  const model = timelineModel(event);
  return (
    <li className={`timeline-item ${model.tone}`}>
      <div className="timeline-marker" aria-hidden="true">
        {timelineIcon(event.kind)}
      </div>
      <div className="timeline-card">
        <div className="timeline-head">
          <b className="timeline-kind mono">{event.kind}</b>
          <time className="timeline-time mono" dateTime={event.created_at}>
            {shortDate(event.created_at)}
          </time>
        </div>
        <div className="timeline-title-row">
          <h3>{model.title}</h3>
          {model.review?.verdict && (
            <span className={`timeline-verdict ${model.review.verdict}`}>
              {model.review.verdict}
            </span>
          )}
        </div>
        {model.description && <p className="timeline-message">{model.description}</p>}
        {model.chips.length > 0 && (
          <div className="timeline-chips">
            {model.chips.map((chip) => (
              <span className={`timeline-chip ${chip.tone || ""}`} key={`${chip.label}-${chip.value}`}>
                <b>{chip.label}</b>
                <span>{chip.value}</span>
              </span>
            ))}
          </div>
        )}
        {model.fields.length > 0 && (
          <dl className="timeline-fields">
            {model.fields.map((field) => (
              <div className="timeline-field" key={`${field.label}-${field.value}`}>
                <dt>{field.label}</dt>
                <dd className={field.kind === "path" ? "mono path" : undefined}>{field.value}</dd>
              </div>
            ))}
          </dl>
        )}
        {model.review && <ReviewTimelineDetails review={model.review} />}
      </div>
    </li>
  );
}

function ReviewTimelineDetails({ review }: { review: ReviewShape }) {
  const findings = review.findings;
  const gaps = review.validation_gaps;
  if (!review.remaining_risk && findings.length === 0 && gaps.length === 0) return null;
  return (
    <div className="timeline-review">
      {findings.length > 0 && (
        <div>
          <h4>Findings</h4>
          <ul>
            {findings.map((finding, index) => (
              <li key={`${stringValue(finding.title, "finding")}-${index}`}>
                <b>{stringValue(finding.title, "Finding")}</b>
                {stringValue(finding.file, "") && (
                  <span className="mono">
                    {stringValue(finding.file, "")}
                    {typeof finding.line === "number" ? `:${finding.line}` : ""}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {gaps.length > 0 && (
        <div>
          <h4>Validation gaps</h4>
          <ul>
            {gaps.map((gap, index) => <li key={`${gap}-${index}`}>{gap}</li>)}
          </ul>
        </div>
      )}
      {review.remaining_risk && (
        <div>
          <h4>Remaining risk</h4>
          <p>{review.remaining_risk}</p>
        </div>
      )}
    </div>
  );
}

function timelineModel(event: EventRecord): TimelineModel {
  const data = event.data || {};
  const messageRecord = parseRecord(event.message);
  const review = reviewShape(data.review) || reviewShape(messageRecord);
  const base: TimelineModel = {
    title: humanizeKind(event.kind),
    description: cleanMessage(event.message, messageRecord),
    tone: timelineTone(event.kind),
    chips: primitiveChips(data),
    fields: pathFields(data),
    review: null,
  };

  if (event.kind === "review.finished" && review) {
    return {
      ...base,
      title: review.verdict === "approve" ? "Review approved" : "Review blocked",
      description: review.summary,
      tone: review.verdict === "approve" ? "success" : "danger",
      chips: [
        { label: "verdict", value: review.verdict, tone: review.verdict === "approve" ? "success" : "danger" },
        { label: "attempt", value: stringValue(data.attempt, "-") },
        { label: "findings", value: String(review.findings.length) },
        { label: "gaps", value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind === "review.failed" || event.kind === "review.invalid_output") {
    return {
      ...base,
      title: event.kind === "review.failed" ? "Review failed" : "Review returned invalid output",
      description: base.description || stringValue(data.summary, ""),
      tone: "danger",
      chips: [
        { label: "attempt", value: stringValue(data.attempt, "-") },
        { label: "run", value: stringValue(data.review_run, "-") },
        { label: "retryable", value: stringValue(data.retryable, "-") },
        { label: "exit", value: stringValue(data.exit_code, "-") },
      ],
    };
  }

  if (event.kind === "task.status") {
    return {
      ...base,
      title: stringValue(data.summary, `Task moved to ${event.message}`),
      description: "",
      tone: statusTone(event.message),
      chips: [
        { label: "status", value: event.message, tone: statusTone(event.message) },
        { label: "phase", value: stringValue(data.phase, "-") },
      ],
    };
  }

  if (event.kind === "worktree.ready") {
    return {
      ...base,
      title: "Worktree ready",
      description: "",
      tone: "success",
      chips: [],
      fields: [
        { label: "Worktree", value: event.message, kind: "path" },
        ...fieldIf("Branch", data.branch),
      ],
    };
  }

  if (event.kind === "patch.saved") {
    return {
      ...base,
      title: "Patch saved",
      description: "",
      tone: "success",
      chips: [{ label: "label", value: stringValue(data.label, "-") }],
      fields: [{ label: "Patch", value: event.message, kind: "path" }],
    };
  }

  if (event.kind === "validation.failed") {
    const failed = Array.isArray(data.failed) ? data.failed : [];
    return {
      ...base,
      title: "Validation failed",
      description: event.message,
      tone: "danger",
      chips: [
        { label: "label", value: stringValue(data.label, "-") },
        { label: "failed", value: String(failed.length), tone: "danger" },
      ],
      fields: [
        ...fieldIf("Patch", data.patch_path, "path"),
        ...failed.slice(0, 3).flatMap((item, index) =>
          isRecord(item) ? fieldIf(`Command ${index + 1}`, commandText(item.command)) : [],
        ),
      ],
    };
  }

  if (
    event.kind === "worker.finished"
    || event.kind === "worker.revision_finished"
    || event.kind === "worker.integration_revision_finished"
  ) {
    return {
      ...base,
      title: event.kind === "worker.finished" ? "Worker finished" : "Worker revision finished",
      description: "",
      tone: event.message === "0" ? "success" : "danger",
      chips: [
        { label: "exit", value: event.message, tone: event.message === "0" ? "success" : "danger" },
        ...chipIf("revision", data.revision),
      ],
    };
  }

  if (event.kind === "worker.integration_revision_requested") {
    return {
      ...base,
      title: `Integration revision ${stringValue(data.revision, "-")} requested`,
      description: "Patch did not apply on latest main.",
      tone: "review",
      chips: [
        { label: "revision", value: stringValue(data.revision, "-") },
      ],
    };
  }

  if (event.kind === "worker.revision_requested" && review) {
    return {
      ...base,
      title: `Revision ${stringValue(data.revision, "-")} requested`,
      description: review.summary || base.description,
      tone: "review",
      chips: [
        { label: "revision", value: stringValue(data.revision, "-") },
        { label: "review", value: review.verdict || "-" },
        { label: "gaps", value: String(review.validation_gaps.length) },
      ],
      review,
    };
  }

  if (event.kind.startsWith("integration.")) {
    return {
      ...base,
      title: humanizeKind(event.kind),
      description: "",
      tone: "review",
      chips: [
        ...chipIf("created", data.created),
        ...chipIf("task", data.integration_task_id || event.message),
      ],
    };
  }

  if (event.kind === "main.pushed") {
    return {
      ...base,
      title: "Pushed to main",
      description: "",
      tone: "success",
      chips: [{ label: "commit", value: event.message.slice(0, 12), tone: "success" }],
    };
  }

  if (event.kind === "task.created") {
    return {
      ...base,
      title: "Task created",
      description: event.message,
      tone: "created",
      chips: [],
    };
  }

  return base;
}

function timelineIcon(kind: string): ReactNode {
  if (kind.includes("failed") || kind.includes("recovered") || kind.includes("invalid")) return <XCircle size={14} />;
  if (kind.includes("finished") || kind.includes("ready") || kind.includes("saved")) return <CheckCircle2 size={14} />;
  if (kind.includes("review")) return <ListChecks size={14} />;
  if (kind.includes("worktree") || kind.includes("branch") || kind.includes("push") || kind.includes("integration")) return <GitBranch size={14} />;
  if (kind.includes("status")) return <Activity size={14} />;
  return <Circle size={10} />;
}

function timelineTone(kind: string): TimelineTone {
  if (kind.includes("failed") || kind.includes("recovered") || kind.includes("invalid")) return "danger";
  if (kind.includes("finished") || kind.includes("ready") || kind.includes("saved")) return "success";
  if (kind.includes("review") || kind.includes("integration")) return "review";
  if (kind.includes("created")) return "created";
  return "neutral";
}

function statusTone(status: string): TimelineTone {
  if (["failed", "blocked", "cancelled"].includes(status)) return "danger";
  if (["succeeded", "pushed", "no_changes"].includes(status)) return "success";
  if (["reviewing", "integrating"].includes(status)) return "review";
  return "neutral";
}

function reviewShape(value: unknown): ReviewShape | null {
  if (!isRecord(value)) return null;
  const findings = Array.isArray(value.findings) ? value.findings.filter(isRecord) : [];
  return {
    verdict: stringValue(value.verdict, ""),
    summary: stringValue(value.summary, ""),
    findings,
    validation_gaps: Array.isArray(value.validation_gaps) ? value.validation_gaps.map(String) : [],
    remaining_risk: stringValue(value.remaining_risk, ""),
  };
}

function cleanMessage(message: string, parsed: Record<string, unknown> | null): string {
  if (!message || parsed) return "";
  return message;
}

function parseRecord(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function primitiveChips(data: Record<string, unknown>): TimelineChip[] {
  return Object.entries(data)
    .filter(([, value]) => isPrimitive(value) && !looksLikePath(String(value)))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value) }));
}

function pathFields(data: Record<string, unknown>): TimelineField[] {
  return Object.entries(data)
    .filter(([, value]) => typeof value === "string" && looksLikePath(value))
    .slice(0, 4)
    .map(([key, value]) => ({ label: labelize(key), value: String(value), kind: "path" }));
}

function fieldIf(label: string, value: unknown, kind: "path" | "text" = "text"): TimelineField[] {
  const text = commandText(value);
  return text ? [{ label, value: text, kind }] : [];
}

function chipIf(label: string, value: unknown): TimelineChip[] {
  const text = stringValue(value, "");
  return text ? [{ label, value: text }] : [];
}

function commandText(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join(" ");
  return typeof value === "string" ? value : "";
}

function looksLikePath(value: string) {
  return value.startsWith("/") || value.includes("/worktrees/") || value.includes("/transcripts/") || value.includes("/patches/");
}

function humanizeKind(kind: string) {
  return kind
    .split(".")
    .map((part) => part.replace(/_/g, " "))
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function labelize(value: string) {
  return value.replace(/_/g, " ");
}

function stringValue(value: unknown, fallback: string) {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function isPrimitive(value: unknown) {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function shortDate(value: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(date);
}
