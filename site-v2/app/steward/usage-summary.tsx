import type {
  CloudUsageCostTotals,
  CloudUsageGlobal,
  CloudUsageGlobalGroup,
  CloudUsageReadResult,
  CloudUsageSummary,
  CloudUsageTokenTotals,
  CloudUsageUnavailable,
} from "@/lib/steward-archive/cloud-schema";

const MICRO_USD = 1_000_000;
const integerFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
  useGrouping: true,
});

export function formatToken(value: number | null): string {
  return value === null ? "N.A." : integerFormatter.format(value);
}

/** Keep the six micro-USD digits intact instead of converting through a float. */
export function formatMicroUsd(value: number | null): string {
  if (value === null) return "N.A.";
  const whole = Math.floor(value / MICRO_USD);
  const micros = String(value % MICRO_USD).padStart(6, "0");
  return `$${integerFormatter.format(whole)}.${micros}`;
}

export function formatCoverage(
  coverage: CloudUsageSummary["coverage"] | CloudUsageGlobal["coverage"] | null,
  coveredInvocations: number | null,
  expectedInvocations: number | null,
): string {
  if (coverage === null || coveredInvocations === null || expectedInvocations === null) return "N.A.";
  const label = coverage === "complete" ? "Complete" : coverage === "partial" ? "Partial" : "Unavailable";
  return `${label} - ${formatToken(coveredInvocations)}/${formatToken(expectedInvocations)} invocations`;
}

export function formatOwnership(value: CloudUsageGlobal["ownershipClass"]): string {
  return value === "steward-overhead" ? "Steward overhead" : "Task-owned";
}

export function isUsageUnavailable(value: unknown): value is CloudUsageUnavailable {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && (value as { kind?: unknown }).kind === "unavailable";
}

function tokenValue(value: CloudUsageTokenTotals & { knownTokenSubtotal?: number | null }): number | null {
  return value.totalTokens ?? value.knownTokenSubtotal ?? null;
}

function costValue(value: CloudUsageCostTotals & { knownCostSubtotalMicroUsd?: number | null }): number | null {
  return value.totalCostMicroUsd ?? value.knownCostSubtotalMicroUsd ?? null;
}

function UsageDisclosure({
  tokens,
  costs,
}: {
  tokens: CloudUsageTokenTotals;
  costs: CloudUsageCostTotals;
}) {
  const components = [
    ["Prompt tokens", tokens.promptTokens, formatToken],
    ["Cached tokens", tokens.cachedTokens, formatToken],
    ["Uncached tokens", tokens.uncachedTokens, formatToken],
    ["Completion tokens", tokens.completionTokens, formatToken],
    ["Reasoning tokens", tokens.reasoningTokens, formatToken],
    ["Total tokens", tokens.totalTokens, formatToken],
    ["Uncached input cost", costs.uncachedInputCostMicroUsd, formatMicroUsd],
    ["Cached input cost", costs.cachedInputCostMicroUsd, formatMicroUsd],
    ["Output cost", costs.outputCostMicroUsd, formatMicroUsd],
    ["Total cost", costs.totalCostMicroUsd, formatMicroUsd],
  ] as const;

  return (
    <details className="mt-3 border-t border-line pt-2 text-xs">
      <summary className="cursor-pointer text-accent">Usage components</summary>
      <dl className="mt-3 grid min-w-0 gap-x-4 gap-y-2 sm:grid-cols-2">
        {components.map(([label, value, formatter]) => (
          <div key={label} className="flex min-w-0 justify-between gap-3">
            <dt className="min-w-0 break-words text-muted">{label}</dt>
            <dd className="shrink-0 text-right text-ink data-text">{formatter(value)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

export function TaskUsageSummary({
  usage,
}: {
  usage: CloudUsageReadResult<CloudUsageSummary> | null;
}) {
  if (isUsageUnavailable(usage)) {
    return (
      <div className="mt-3 border-t border-line pt-3 text-xs text-unavailable" data-usage-state="unavailable">
        Usage unavailable
      </div>
    );
  }

  const summary = usage;
  const tokenTotal = summary ? tokenValue(summary) : null;
  const costTotal = summary ? costValue(summary) : null;
  return (
    <div className="mt-3 border-t border-line pt-3" data-usage-state={summary ? summary.coverage : "missing"}>
      <dl className="grid min-w-0 grid-cols-3 gap-3 text-xs">
        <div className="min-w-0">
          <dt className="text-muted">Token</dt>
          <dd className="mt-1 break-words text-ink data-text">{formatToken(tokenTotal)}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Estimated cost</dt>
          <dd className="mt-1 break-words text-ink data-text">{formatMicroUsd(costTotal)}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-muted">Coverage</dt>
          <dd className="mt-1 break-words text-ink">{summary ? formatCoverage(summary.coverage, summary.coveredInvocations, summary.expectedInvocations) : "N.A."}</dd>
        </div>
      </dl>
      {summary ? <UsageDisclosure tokens={summary} costs={summary} /> : null}
    </div>
  );
}

function GlobalRow({
  row,
  date,
}: {
  row: CloudUsageGlobal;
  date?: string;
}) {
  const tokenTotal = tokenValue(row);
  const costTotal = costValue(row);
  return (
    <tr>
      {date !== undefined ? <th scope="row" className="px-3 py-3 text-left font-normal text-ink data-text">{date}</th> : null}
      <th scope="row" className="px-3 py-3 text-left font-normal text-ink data-text">{row.model}</th>
      <td className="px-3 py-3 text-left text-ink">{formatOwnership(row.ownershipClass)}</td>
      <td className="px-3 py-3 text-right text-ink data-text">{formatToken(tokenTotal)}</td>
      <td className="px-3 py-3 text-right text-ink data-text">{formatMicroUsd(costTotal)}</td>
      <td className="px-3 py-3 text-left text-ink">{formatCoverage(row.coverage, row.coveredInvocations, row.expectedInvocations)}</td>
      <td className="px-3 py-3 text-right"><UsageDisclosure tokens={row} costs={row} /></td>
    </tr>
  );
}

function GlobalTable({
  title,
  rows,
  daily,
}: {
  title: string;
  rows: readonly CloudUsageGlobal[];
  daily: boolean;
}) {
  if (rows.length === 0) return null;
  return (
    <div className="mt-7 min-w-0">
      <h3 className="text-lg font-semibold text-ink">{title}</h3>
      <div className="mt-3 max-w-full overflow-x-auto border-y border-line">
        <table className="w-full min-w-[46rem] border-collapse text-xs">
          <caption className="sr-only">{title}</caption>
          <thead className="border-b border-line text-left text-muted">
            <tr>
              {daily ? <th scope="col" className="px-3 py-3 font-medium">UTC date</th> : null}
              <th scope="col" className="px-3 py-3 font-medium">Model</th>
              <th scope="col" className="px-3 py-3 font-medium">Ownership</th>
              <th scope="col" className="px-3 py-3 text-right font-medium">Token</th>
              <th scope="col" className="px-3 py-3 text-right font-medium">Estimated cost</th>
              <th scope="col" className="px-3 py-3 font-medium">Coverage</th>
              <th scope="col" className="px-3 py-3 text-right font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((row) => <GlobalRow key={`${row.globalId}-${row.periodKey}`} row={row} date={daily ? row.periodKey : undefined} />)}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function UsageEvidence({
  usage,
}: {
  usage: CloudUsageGlobalGroup[] | CloudUsageUnavailable;
}) {
  if (isUsageUnavailable(usage)) {
    return (
      <section className="mt-8 border-y border-line py-7" aria-labelledby="usage-evidence-title" data-usage-state="unavailable">
        <div className="grid gap-3 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-10">
          <p className="text-sm font-medium text-muted">Cached usage</p>
          <div>
            <h2 id="usage-evidence-title" className="text-xl font-semibold text-ink">Usage unavailable</h2>
            <p className="mt-2 text-sm leading-6 text-muted">Cached usage evidence could not be read. Task status and navigation remain available.</p>
          </div>
        </div>
      </section>
    );
  }

  const lifetime = usage.flatMap((group) => group.lifetime ? [group.lifetime] : []);
  const daily = usage.flatMap((group) => group.daily);
  return (
    <section className="mt-8 border-y border-line py-7" aria-labelledby="usage-evidence-title" data-usage-state={usage.length ? "ready" : "missing"}>
      <div className="grid gap-3 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-10">
        <p className="text-sm font-medium text-muted">Cached usage</p>
        <div>
          <h2 id="usage-evidence-title" className="text-xl font-semibold text-ink">Token and estimated-cost evidence</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Validated lifetime and UTC-daily summaries are shown exactly as cached. Missing prices remain N.A.</p>
          {usage.length === 0 ? <p className="mt-6 border-t border-line pt-6 text-sm text-muted">No cached usage evidence is published yet.</p> : null}
          <GlobalTable title="Lifetime totals by model and ownership" rows={lifetime} daily={false} />
          <GlobalTable title="UTC daily evidence" rows={daily} daily />
        </div>
      </div>
    </section>
  );
}
