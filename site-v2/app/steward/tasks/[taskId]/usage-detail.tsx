import type {
  CloudUsageInvocation,
  CloudUsageInvocationPage,
  CloudUsageTurn,
  CloudUsageTurnPage,
  CloudUsageUnavailable,
} from "@/lib/steward-archive/cloud-schema";
import { formatMicroUsd, formatToken, isUsageUnavailable } from "../../usage-summary";

type UsagePage = CloudUsageInvocationPage | null | CloudUsageUnavailable;
type TurnPage = CloudUsageTurnPage | null | CloudUsageUnavailable;

export type UsageDetailProps = {
  readonly taskId: string;
  readonly pipelineId: string | null;
  readonly runId: string | null;
  readonly runRole: string | null;
  readonly state: "ready" | "missing" | "unavailable";
  readonly invocationPage: UsagePage;
  readonly turnPage: TurnPage;
  readonly selectedInvocationId: string | null;
  readonly invocationCursor?: string | null;
};

function formatDateTime(value: string | null): string {
  if (!value) return "Unavailable";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function formatInvocationCoverage(invocation: CloudUsageInvocation): string {
  const label = invocation.coverage === "complete" ? "Complete" : invocation.coverage === "partial" ? "Partial" : "Unavailable";
  return `${label} - ${formatToken(invocation.coveredTurns)}/${formatToken(invocation.expectedTurns)} turns`;
}

function metricDisclosure(value: CloudUsageInvocation | CloudUsageTurn) {
  const components = [
    ["Prompt tokens", value.promptTokens, formatToken],
    ["Cached tokens", value.cachedTokens, formatToken],
    ["Uncached tokens", value.uncachedTokens, formatToken],
    ["Completion tokens", value.completionTokens, formatToken],
    ["Reasoning tokens", value.reasoningTokens, formatToken],
    ["Total tokens", value.totalTokens, formatToken],
    ["Uncached input cost", value.uncachedInputCostMicroUsd, formatMicroUsd],
    ["Cached input cost", value.cachedInputCostMicroUsd, formatMicroUsd],
    ["Output cost", value.outputCostMicroUsd, formatMicroUsd],
    ["Total cost", value.totalCostMicroUsd, formatMicroUsd],
  ] as const;
  return (
    <details className="mt-3 border-t border-line pt-2 text-xs">
      <summary className="cursor-pointer text-accent">Usage components</summary>
      <dl className="mt-3 grid min-w-0 gap-x-4 gap-y-2 sm:grid-cols-2">
        {components.map(([label, component, formatter]) => (
          <div key={label} className="flex min-w-0 justify-between gap-3">
            <dt className="min-w-0 break-words text-muted">{label}</dt>
            <dd className="shrink-0 text-right text-ink data-text">{formatter(component)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function selectionHref(
  taskId: string,
  pipelineId: string | null,
  runId: string,
  invocationId: string,
  invocationCursor?: string | null,
  turnCursor?: string | null,
  anchor = "usage-invocations",
): string {
  const params = new URLSearchParams();
  if (pipelineId) params.set("pipeline", pipelineId);
  params.set("run", runId);
  params.set("invocation", invocationId);
  if (invocationCursor) params.set("invocationCursor", invocationCursor);
  if (turnCursor) params.set("cursor", turnCursor);
  return `/steward/tasks/${encodeURIComponent(taskId)}?${params.toString()}#${anchor}`;
}

function invocationPageHref(taskId: string, pipelineId: string | null, runId: string, cursor: string, anchor = "usage-invocations"): string {
  const params = new URLSearchParams();
  if (pipelineId) params.set("pipeline", pipelineId);
  params.set("run", runId);
  params.set("invocationCursor", cursor);
  return `/steward/tasks/${encodeURIComponent(taskId)}?${params.toString()}#${anchor}`;
}

function Unavailable({ children }: { readonly children: string }) {
  return <p className="border-y border-line py-5 text-sm leading-6 text-unavailable" data-usage-state="unavailable">{children}</p>;
}

function InvocationRow({
  taskId,
  pipelineId,
  runId,
  role,
  invocation,
  selected,
  invocationCursor,
}: {
  readonly taskId: string;
  readonly pipelineId: string | null;
  readonly runId: string;
  readonly role: string | null;
  readonly invocation: CloudUsageInvocation;
  readonly selected: boolean;
  readonly invocationCursor: string | null;
}) {
  const invocationId = invocation.invocationId!;
  return (
    <tr className={selected ? "bg-accent-soft" : undefined}>
      <th scope="row" className="px-3 py-4 text-left font-normal">
        <a
          href={selectionHref(taskId, pipelineId, runId, invocationId, invocationCursor)}
          aria-current={selected ? "page" : undefined}
          className="break-all font-medium text-ink no-underline hover:text-accent"
        >
          {invocationId}
        </a>
        <span className="mt-1 block text-xs text-muted">Retry {invocation.retryOrdinal}</span>
      </th>
      <td className="px-3 py-4 text-left text-ink">{role ?? "Unavailable"}</td>
      <td className="px-3 py-4 text-left text-ink data-text">{invocation.model ?? "Unavailable"}</td>
      <td className="px-3 py-4 text-left text-ink data-text">{formatDateTime(invocation.startedAt)}</td>
      <td className="px-3 py-4 text-left text-ink">{invocation.processOutcome ?? "Unavailable"}</td>
      <td className="px-3 py-4 text-right text-ink data-text">{formatToken(invocation.totalTokens)}</td>
      <td className="px-3 py-4 text-right text-ink data-text">{formatMicroUsd(invocation.totalCostMicroUsd)}</td>
      <td className="px-3 py-4 text-left text-ink">{formatInvocationCoverage(invocation)}</td>
      <td className="px-3 py-4 text-left">{metricDisclosure(invocation)}</td>
    </tr>
  );
}

function InvocationTable({
  taskId,
  pipelineId,
  runId,
  role,
  page,
  selectedInvocationId,
  invocationCursor,
}: {
  readonly taskId: string;
  readonly pipelineId: string | null;
  readonly runId: string | null;
  readonly role: string | null;
  readonly page: UsagePage;
  readonly selectedInvocationId: string | null;
  readonly invocationCursor: string | null;
}) {
  if (isUsageUnavailable(page)) return <Unavailable>Invocation usage unavailable. Task and trajectory evidence remain available.</Unavailable>;
  if (page === null || runId === null) return <p className="border-y border-line py-5 text-sm leading-6 text-muted">No invocation usage is published for the selected run.</p>;
  if (page.invocations.length === 0) return <p className="border-y border-line py-5 text-sm leading-6 text-muted">No invocation or retry rows are published for the selected run.</p>;
  return (
    <div className="max-w-full overflow-x-auto border-y border-line" data-usage-state="ready">
      <table className="w-full min-w-[72rem] border-collapse text-xs">
        <caption className="sr-only">Invocation and retry usage</caption>
        <thead className="border-b border-line text-left text-muted">
          <tr>
            <th scope="col" className="px-3 py-3 font-medium">Invocation / retry</th>
            <th scope="col" className="px-3 py-3 font-medium">Role</th>
            <th scope="col" className="px-3 py-3 font-medium">Model</th>
            <th scope="col" className="px-3 py-3 font-medium">UTC start</th>
            <th scope="col" className="px-3 py-3 font-medium">Outcome</th>
            <th scope="col" className="px-3 py-3 text-right font-medium">Token</th>
            <th scope="col" className="px-3 py-3 text-right font-medium">Estimated cost</th>
            <th scope="col" className="px-3 py-3 font-medium">Coverage</th>
            <th scope="col" className="px-3 py-3 font-medium">Details</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {page.invocations.map((invocation) => (
            <InvocationRow
              key={invocation.invocationId}
              taskId={taskId}
              pipelineId={pipelineId}
              runId={runId}
              role={role}
              invocation={invocation}
              selected={invocation.invocationId === selectedInvocationId}
              invocationCursor={invocationCursor}
            />
          ))}
        </tbody>
      </table>
      <nav className="flex flex-wrap gap-x-5 gap-y-2 px-3 py-3 text-sm" aria-label="Invocation usage pages">
        {page.previousCursor ? <a className="text-accent" href={invocationPageHref(taskId, pipelineId, runId, page.previousCursor)}>Previous invocations</a> : null}
        {page.nextCursor ? <a className="text-accent" href={invocationPageHref(taskId, pipelineId, runId, page.nextCursor)}>Next invocations</a> : null}
        <span className="text-muted">Showing {page.invocations.length} of {page.total} invocations</span>
      </nav>
    </div>
  );
}

function TurnRow({ turn, invocation }: { readonly turn: CloudUsageTurn; readonly invocation: CloudUsageInvocation }) {
  return (
    <tr>
      <th scope="row" className="px-3 py-4 text-left font-medium text-ink data-text">{turn.ordinal}</th>
      <td className="px-3 py-4 text-left text-ink data-text">{turn.turnId}</td>
      <td className="px-3 py-4 text-left text-ink data-text">{formatDateTime(invocation.startedAt)}</td>
      <td className="px-3 py-4 text-left text-ink data-text">{invocation.model ?? "Unavailable"}</td>
      <td className="px-3 py-4 text-left text-ink">{formatInvocationCoverage(invocation)}</td>
      <td className="px-3 py-4 text-right text-ink data-text">{formatToken(turn.totalTokens)}</td>
      <td className="px-3 py-4 text-right text-ink data-text">{formatMicroUsd(turn.totalCostMicroUsd)}</td>
      <td className="px-3 py-4 text-left text-ink">{turn.priceEntryDigest ? "Priced" : "N.A."}</td>
      <td className="px-3 py-4 text-left">{metricDisclosure(turn)}</td>
    </tr>
  );
}

function TurnTable({
  taskId,
  pipelineId,
  runId,
  invocationId,
  page,
  invocation,
  invocationCursor,
}: {
  readonly taskId: string;
  readonly pipelineId: string | null;
  readonly runId: string;
  readonly invocationId: string;
  readonly page: TurnPage;
  readonly invocation: CloudUsageInvocation;
  readonly invocationCursor: string | null;
}) {
  if (isUsageUnavailable(page)) return <Unavailable>Turn usage unavailable. The task page and selected invocation remain available.</Unavailable>;
  if (page === null || page.turns.length === 0) return <p className="border-y border-line py-5 text-sm leading-6 text-muted">No turns are published for this invocation.</p>;
  const first = page.turns[0]!;
  const last = page.turns[page.turns.length - 1]!;
  return (
    <>
      <div className="max-w-full overflow-x-auto border-y border-line" data-usage-state="ready">
        <table className="w-full min-w-[72rem] border-collapse text-xs">
          <caption className="sr-only">Bounded turn usage</caption>
          <thead className="border-b border-line text-left text-muted">
            <tr>
              <th scope="col" className="px-3 py-3 font-medium">Turn</th>
              <th scope="col" className="px-3 py-3 font-medium">Turn ID</th>
              <th scope="col" className="px-3 py-3 font-medium">UTC start</th>
              <th scope="col" className="px-3 py-3 font-medium">Model</th>
              <th scope="col" className="px-3 py-3 font-medium">Coverage</th>
              <th scope="col" className="px-3 py-3 text-right font-medium">Token</th>
              <th scope="col" className="px-3 py-3 text-right font-medium">Estimated cost</th>
              <th scope="col" className="px-3 py-3 font-medium">Price</th>
              <th scope="col" className="px-3 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {page.turns.map((turn) => <TurnRow key={turn.turnId} turn={turn} invocation={invocation} />)}
          </tbody>
        </table>
      </div>
      <nav className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-sm" aria-label="Turn usage pages">
        {page.previousCursor ? <a className="text-accent" href={selectionHref(taskId, pipelineId, runId, invocationId, invocationCursor, page.previousCursor, "usage-turns")}>Previous turns</a> : null}
        {page.nextCursor ? <a className="text-accent" href={selectionHref(taskId, pipelineId, runId, invocationId, invocationCursor, page.nextCursor, "usage-turns")}>Next turns</a> : null}
        <span className="text-muted">Showing {first.ordinal}-{last.ordinal} of {page.total} turns</span>
      </nav>
    </>
  );
}

export function UsageDetail({
  taskId,
  pipelineId,
  runId,
  runRole,
  state,
  invocationPage,
  turnPage,
  selectedInvocationId,
  invocationCursor = null,
}: UsageDetailProps) {
  const selectedInvocation = !isUsageUnavailable(invocationPage)
    ? invocationPage?.invocations.find((invocation) => invocation.invocationId === selectedInvocationId) ?? null
    : null;
  return (
    <section id="usage" aria-labelledby="usage-title" className="border-b border-line py-8 sm:py-10" data-usage-state={state}>
      <div className="grid min-w-0 gap-3 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-10">
        <p className="text-sm font-medium text-muted">Cached usage</p>
        <div className="min-w-0">
          <h2 id="usage-title" className="text-xl font-semibold text-ink">Run, invocation, and turn usage</h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-muted">Cached Token and estimated-cost evidence stays attached to the selected run. Retry and failed rows remain visible; missing prices remain N.A.</p>
          {state === "unavailable" ? <Unavailable>Usage unavailable. Task status, trajectory, and artifacts remain available.</Unavailable> : null}
          {state === "missing" ? <p className="mt-5 border-y border-line py-5 text-sm leading-6 text-muted">No cached usage evidence is published for this task.</p> : null}
          {state === "ready" ? (
            <>
              <section id="usage-invocations" aria-labelledby="usage-invocations-title" className="mt-7">
                <div className="flex flex-wrap items-baseline justify-between gap-3">
                  <h3 id="usage-invocations-title" className="text-lg font-semibold text-ink">Invocations and retries</h3>
                  {runId ? <span className="break-all text-xs text-muted data-text">Run {runId}</span> : null}
                </div>
                <p className="mt-2 text-sm leading-6 text-muted">Rows are selected only when their task and run ownership match the current page.</p>
                <div className="mt-4"><InvocationTable taskId={taskId} pipelineId={pipelineId} runId={runId} role={runRole} page={invocationPage} selectedInvocationId={selectedInvocationId} invocationCursor={invocationCursor} /></div>
              </section>
              <section id="usage-turns" aria-labelledby="usage-turns-title" className="mt-8">
                <h3 id="usage-turns-title" className="text-lg font-semibold text-ink">Turns</h3>
                {selectedInvocation ? (
                  <>
                    <dl className="mt-3 grid gap-x-6 gap-y-2 text-xs text-muted sm:grid-cols-4">
                      <div><dt className="inline">Invocation </dt><dd className="inline break-all text-ink data-text">{selectedInvocation.invocationId}</dd></div>
                      <div><dt className="inline">Model </dt><dd className="inline text-ink data-text">{selectedInvocation.model ?? "Unavailable"}</dd></div>
                      <div><dt className="inline">UTC start </dt><dd className="inline text-ink data-text">{formatDateTime(selectedInvocation.startedAt)}</dd></div>
                      <div><dt className="inline">Coverage </dt><dd className="inline text-ink">{formatInvocationCoverage(selectedInvocation)}</dd></div>
                    </dl>
                    <div className="mt-4">{runId && selectedInvocation.invocationId ? <TurnTable taskId={taskId} pipelineId={pipelineId} runId={runId} invocationId={selectedInvocation.invocationId} page={turnPage} invocation={selectedInvocation} invocationCursor={invocationCursor} /> : null}</div>
                    {metricDisclosure(selectedInvocation)}
                  </>
                ) : <p className="mt-4 border-y border-line py-5 text-sm leading-6 text-muted">Select a published invocation to inspect its bounded turns.</p>}
              </section>
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}
