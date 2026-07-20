"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

type DailyStewardReportProps = {
  summary: {
    ranges: Array<{
      id: string;
      startDate: string;
      endDate: string;
      modelUsage: {
        availability: string;
        sessions: number | null;
        requests: number | null;
        toolCalls: number | null;
        totalTokens: number | null;
      };
      repository: {
        availability: string;
        commits: number | null;
        changedLines: number | null;
      };
      outcomes: {
        availability: string;
        issuesResolved: number | null;
        validationsPassed: number | null;
        validationsCompleted: number | null;
      };
    }>;
    live: {
      availability: string;
      observedAt: string;
      windowSeconds: number;
      tokens: number | null;
      requests: number | null;
      activeSessions: number | null;
      toolCalls: number | null;
      commitsToday: number | null;
      changedLinesToday: number | null;
      issuesResolvedToday: number | null;
      validationsRunning: number | null;
    };
  };
};

const rangeOptions = [
  { id: "day", label: "Day", compactLabel: "Day" },
  { id: "7d", label: "7 days", compactLabel: "7d" },
  { id: "30d", label: "30 days", compactLabel: "30d" },
  { id: "all", label: "All time", compactLabel: "All" },
] as const;

const integer = new Intl.NumberFormat("en-US");
const compactInteger = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 3,
});

function formatInteger(value: number | null) {
  return value === null ? "Not reported" : integer.format(value);
}

function formatMetricInteger(value: number | null, available: boolean) {
  const exact = available ? formatInteger(value) : "Not reported";
  const compact =
    available && value !== null && value >= 1_000_000_000
      ? compactInteger.format(value)
      : exact;

  return { value: exact, compactValue: compact };
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    month: "long",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${value}T00:00:00Z`));
}

function formatCompactDate(value: string, includeYear = false) {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: includeYear ? "numeric" : undefined,
    timeZone: "UTC",
  }).format(new Date(`${value}T00:00:00Z`));
}

function formatRangeDescription(range: { startDate: string; endDate: string }) {
  if (range.startDate === range.endDate) {
    return formatDate(range.endDate);
  }

  return `${formatCompactDate(range.startDate)} - ${formatCompactDate(range.endDate, true)}`;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function formatPassRate(passed: number | null, completed: number | null) {
  if (passed === null || completed === null || completed === 0) {
    return "Not reported";
  }

  return new Intl.NumberFormat("en-US", {
    style: "percent",
    maximumFractionDigits: 1,
  }).format(passed / completed);
}

export function DailyStewardReport({ summary }: DailyStewardReportProps) {
  const [rangeId, setRangeId] = useState("day");
  const activeRange =
    summary.ranges.find((range) => range.id === rangeId) ?? summary.ranges[0]!;
  const modelAvailable = activeRange.modelUsage.availability === "available";
  const repositoryAvailable =
    activeRange.repository.availability === "available";
  const outcomesAvailable = activeRange.outcomes.availability === "available";
  const liveAvailable = ["available", "stale"].includes(
    summary.live.availability,
  );
  const liveValue = (value: number | null) =>
    liveAvailable && value !== null ? formatInteger(value) : "Not reported";
  const deltaValue = (value: number | null) =>
    liveAvailable && value !== null
      ? `+${formatInteger(value)}`
      : "Not reported";
  const rollingUnit =
    summary.live.windowSeconds === 60
      ? "/ min"
      : `/ ${formatInteger(summary.live.windowSeconds)} sec`;
  const liveDescription = (value: number | null, description: string) =>
    liveAvailable && value !== null
      ? `${formatInteger(value)} ${description}`
      : "Current value not reported";
  const snapshotLabel =
    summary.live.availability === "available"
      ? "Live snapshot"
      : summary.live.availability === "stale"
        ? "Stale snapshot"
        : "Snapshot unavailable";
  const snapshotTone =
    summary.live.availability === "available"
      ? "text-positive"
      : summary.live.availability === "stale"
        ? "text-warning"
        : "text-contrast-muted";
  const snapshotDot =
    summary.live.availability === "available"
      ? "bg-positive"
      : summary.live.availability === "stale"
        ? "bg-warning"
        : "bg-contrast-muted";
  const passRate = outcomesAvailable
    ? formatPassRate(
        activeRange.outcomes.validationsPassed,
        activeRange.outcomes.validationsCompleted,
      )
    : "Not reported";
  const metrics = [
    {
      label: "Model tokens",
      ...formatMetricInteger(
        activeRange.modelUsage.totalTokens,
        modelAvailable,
      ),
      progressValue: deltaValue(summary.live.tokens),
      progressContext: rollingUnit,
      progressLabel: liveDescription(
        summary.live.tokens,
        `additional model tokens in the last ${formatInteger(summary.live.windowSeconds)} seconds`,
      ),
    },
    {
      label: "Model requests",
      ...formatMetricInteger(activeRange.modelUsage.requests, modelAvailable),
      progressValue: deltaValue(summary.live.requests),
      progressContext: rollingUnit,
      progressLabel: liveDescription(
        summary.live.requests,
        `additional model requests in the last ${formatInteger(summary.live.windowSeconds)} seconds`,
      ),
    },
    {
      label: "Agent sessions",
      ...formatMetricInteger(activeRange.modelUsage.sessions, modelAvailable),
      progressValue: liveValue(summary.live.activeSessions),
      progressContext: "active",
      progressLabel: liveDescription(
        summary.live.activeSessions,
        "active agent sessions",
      ),
    },
    {
      label: "Tool calls",
      ...formatMetricInteger(activeRange.modelUsage.toolCalls, modelAvailable),
      progressValue: deltaValue(summary.live.toolCalls),
      progressContext: rollingUnit,
      progressLabel: liveDescription(
        summary.live.toolCalls,
        `additional tool calls in the last ${formatInteger(summary.live.windowSeconds)} seconds`,
      ),
    },
    {
      label: "Commits landed",
      ...formatMetricInteger(
        activeRange.repository.commits,
        repositoryAvailable,
      ),
      progressValue: deltaValue(summary.live.commitsToday),
      progressContext: "today",
      progressLabel: liveDescription(
        summary.live.commitsToday,
        "additional commits landed today UTC",
      ),
    },
    {
      label: "Lines changed",
      ...formatMetricInteger(
        activeRange.repository.changedLines,
        repositoryAvailable,
      ),
      progressValue: deltaValue(summary.live.changedLinesToday),
      progressContext: "today",
      progressLabel: liveDescription(
        summary.live.changedLinesToday,
        "additional lines changed today UTC",
      ),
    },
    {
      label: "Issues resolved",
      ...formatMetricInteger(
        activeRange.outcomes.issuesResolved,
        outcomesAvailable,
      ),
      progressValue: deltaValue(summary.live.issuesResolvedToday),
      progressContext: "today",
      progressLabel: liveDescription(
        summary.live.issuesResolvedToday,
        "additional issues resolved today UTC",
      ),
    },
    {
      label: "Validation pass rate",
      value: passRate,
      compactValue: passRate,
      progressValue: liveValue(summary.live.validationsRunning),
      progressContext: "running",
      progressLabel: liveDescription(
        summary.live.validationsRunning,
        "validations running",
      ),
    },
  ];

  return (
    <section
      aria-labelledby="growth-report-title"
      className="bg-contrast-field text-contrast-ink"
    >
      <div className="flex flex-col gap-5 border-b border-contrast-line px-5 py-5 sm:flex-row sm:items-start sm:justify-between sm:px-7">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className="size-2 rounded-full bg-positive"
              aria-hidden="true"
            />
            <h2 id="growth-report-title" className="text-sm font-semibold">
              Steward growth report
            </h2>
          </div>
          <p
            className="mt-2 text-xs leading-5 text-contrast-muted data-text"
            aria-live="polite"
          >
            {formatRangeDescription(activeRange)}
          </p>
        </div>

        <div className="flex shrink-0 flex-col items-start gap-3 sm:items-end">
          <div
            className="inline-flex border border-contrast-line p-0.5"
            role="group"
            aria-label="Metric period"
          >
            {rangeOptions.map((option) => {
              const selected = option.id === rangeId;

              return (
                <button
                  key={option.id}
                  type="button"
                  className={`min-h-8 min-w-10 cursor-pointer px-2.5 text-xs font-medium transition-colors pointer-coarse:min-h-11 pointer-coarse:min-w-11 ${
                    selected
                      ? "bg-contrast-ink text-contrast-field"
                      : "bg-transparent text-contrast-muted hover:text-contrast-ink"
                  }`}
                  aria-label={option.label}
                  aria-pressed={selected}
                  onClick={() => setRangeId(option.id)}
                >
                  <span className="sm:hidden">{option.compactLabel}</span>
                  <span className="hidden sm:inline">{option.label}</span>
                </button>
              );
            })}
          </div>

          <p
            className={`flex items-center gap-2 text-xs font-medium sm:justify-end ${snapshotTone}`}
          >
            <span
              className={`size-2 rounded-full ${snapshotDot}`}
              aria-hidden="true"
            />
            <span>{snapshotLabel}</span>
            <span className="text-contrast-muted" aria-hidden="true">
              ·
            </span>
            <time dateTime={summary.live.observedAt}>
              {formatTime(summary.live.observedAt)}
            </time>
          </p>
        </div>
      </div>

      <dl className="grid grid-cols-2">
        {metrics.map((metric) => (
          <div
            key={metric.label}
            className="min-w-0 border-b border-contrast-line px-5 py-5 odd:border-r sm:px-7 sm:py-6"
          >
            <dt className="text-xs text-contrast-muted">{metric.label}</dt>
            <dd
              className="mt-2 text-xl font-medium data-text sm:text-2xl"
              aria-label={metric.value}
              title={metric.value}
            >
              <span
                className={
                  metric.compactValue === metric.value ? "" : "sm:hidden"
                }
              >
                {metric.compactValue}
              </span>
              {metric.compactValue === metric.value ? null : (
                <span className="hidden sm:inline">{metric.value}</span>
              )}
            </dd>
            <dd
              className="mt-2 min-w-0 text-xs text-contrast-muted data-text"
              aria-label={metric.progressLabel}
            >
              <span className={`font-medium ${snapshotTone}`}>
                {metric.progressValue}
              </span>
              {metric.progressValue === "Not reported" ? null : (
                <> {metric.progressContext}</>
              )}
            </dd>
          </div>
        ))}
      </dl>

      <Link
        href="/steward"
        className="flex min-h-14 items-center justify-between border-t border-contrast-line px-5 text-sm font-medium text-contrast-ink no-underline transition-colors duration-fast hover:bg-contrast-ink hover:text-contrast-field sm:px-7"
      >
        Inspect Steward evidence
        <ArrowRight aria-hidden="true" size={16} strokeWidth={1.8} />
      </Link>
    </section>
  );
}
