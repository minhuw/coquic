type TranscriptTiming = {
  items: Array<{ kind: string; durationMs?: number; id: string; label: string }>;
  timing: { startedAt: string; endedAt: string; totalDurationMs: number; messageIntervals: number } | null;
};

const segmentTones = ["bg-muted", "bg-ink", "bg-faint", "bg-line-strong"];

function formatDuration(durationMs: number) {
  if (durationMs < 1_000) return `${durationMs}ms`;
  if (durationMs < 60_000) return `${(durationMs / 1_000).toFixed(1)}s`;
  const minutes = Math.floor(durationMs / 60_000);
  const seconds = Math.round((durationMs % 60_000) / 1_000);
  return seconds === 60 ? `${minutes + 1}m` : `${minutes}m ${seconds}s`;
}

function formatTime(timestamp: string) {
  return new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
  }).format(new Date(timestamp));
}

export function DurationStrip({ anchorPrefix, transcript }: { anchorPrefix: string; transcript: TranscriptTiming }) {
  if (!transcript.timing) return null;
  const intervals = transcript.items.filter((item) => item.kind === "assistant" && item.durationMs !== undefined);
  if (!intervals.length) return null;
  let elapsedMs = 0;

  return (
    <section aria-labelledby={`${anchorPrefix}-cadence-title`} className="border-b border-line py-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between sm:gap-6">
        <h3 id={`${anchorPrefix}-cadence-title`} className="text-sm font-semibold text-ink">Run cadence</h3>
        <p className="text-xs text-muted data-text">{intervals.length} message intervals · {formatDuration(transcript.timing.totalDurationMs)}</p>
      </div>
      <div className="mt-3 flex h-6 min-w-0 bg-diff-gutter" aria-label="Message interval timeline">
        {intervals.map((item, index) => {
          const duration = formatDuration(item.durationMs!);
          const midpoint = ((elapsedMs + item.durationMs! / 2) / transcript.timing!.totalDurationMs) * 100;
          elapsedMs += item.durationMs!;
          const tooltipPosition = midpoint < 40 ? "left-0" : midpoint > 60 ? "right-0" : "left-1/2 -translate-x-1/2";
          return (
            <a
              key={item.id}
              href={`#${anchorPrefix}-event-${item.id}`}
              aria-label={`Message ${index + 1}: ${duration}`}
              className={`${segmentTones[index % segmentTones.length]} group relative block h-full min-w-0 border-r border-surface no-underline transition-[filter] duration-fast last:border-r-0 hover:brightness-125 focus-visible:z-10 focus-visible:brightness-125`}
              style={{ width: `${(item.durationMs! / transcript.timing!.totalDurationMs) * 100}%` }}
            >
              <span aria-hidden="true" data-cadence-tooltip className={`pointer-events-none invisible absolute bottom-[calc(100%+0.5rem)] z-20 block w-max max-w-72 overflow-hidden text-ellipsis whitespace-nowrap bg-ink px-3 py-2 text-left text-xs text-canvas opacity-0 shadow-temporary transition-opacity duration-fast group-hover:visible group-hover:opacity-100 group-focus-visible:visible group-focus-visible:opacity-100 ${tooltipPosition}`}>
                <span className="font-semibold data-text">{String(index + 1).padStart(2, "0")} · {duration}</span>
                <span className="mx-2 text-canvas/50">·</span>
                <span className="text-canvas/75">{item.label}</span>
              </span>
            </a>
          );
        })}
      </div>
      <div className="mt-2 flex items-baseline justify-between gap-4 text-xs text-faint data-text">
        <time dateTime={transcript.timing.startedAt}>{formatTime(transcript.timing.startedAt)}</time>
        <time dateTime={transcript.timing.endedAt}>{formatTime(transcript.timing.endedAt)} UTC</time>
      </div>
    </section>
  );
}
