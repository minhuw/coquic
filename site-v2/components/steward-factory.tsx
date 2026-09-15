"use client";

import { useEffect, useRef, useState, type CSSProperties } from "react";
import Link from "next/link";
import type { StewardLiveSnapshot } from "@/lib/steward-live/schema";

const stations = [
  { name: "Signals", machine: "Observation intake", description: "Collect repository observations for planning. The public snapshot exposes the pending count, not signal contents." },
  { name: "Planning", machine: "Planning sorter", description: "Triage observations and select work. Only the planner state is public; plans and run details appear only in published tasks." },
  { name: "Tasks", machine: "Parallel workstations", description: "Execute, validate, and review work in parallel. Active and queued counts are live; identities, transcripts, and usage belong to published tasks." },
  { name: "Integration", machine: "Integration assembly", description: "Bring reviewed work together for integration. Active and queued counts do not expose progress or completion events; available evidence is in published tasks." },
] as const;

// Fixed illustrative pieces and paths, deliberately unrelated to snapshot counters.
const widePaths = [
  "M 40 130 H 150 Q 200 130 240 230 H 365", "M 40 330 H 150 Q 200 330 240 230 H 365",
  "M 405 230 H 465 Q 490 230 490 110 H 650", "M 405 230 H 650",
  "M 405 230 H 465 Q 490 230 490 350 H 650",
  "M 690 110 H 750 Q 800 110 810 230 H 930", "M 690 350 H 750 Q 800 350 810 230 H 930",
  "M 690 230 H 930", "M 970 230 H 1160",
];
const compactPaths = [
  "M 65 40 V 65 Q 65 110 180 110 V 255", "M 295 40 V 65 Q 295 110 180 110 V 255",
  "M 180 285 V 330 Q 180 350 75 350 V 420", "M 180 285 V 420",
  "M 180 285 V 330 Q 180 350 285 350 V 420",
  "M 75 450 V 495 Q 75 550 180 550 V 610", "M 285 450 V 495 Q 285 550 180 550 V 610",
  "M 180 450 V 610", "M 180 640 V 735",
];

function FactoryScene({ compact, inspect }: { compact: boolean; inspect: (station: number, item?: boolean, trigger?: SVGGElement) => void }) {
  const paths = compact ? compactPaths : widePaths;
  const machines = compact ? [[180, 100, 0], [180, 255, 1], [75, 420, 2], [180, 420, 2], [285, 420, 2], [180, 610, 3]] : [[215, 210, 0], [380, 210, 1], [650, 90, 2], [650, 210, 2], [650, 330, 2], [930, 210, 3]];
  return (
    <svg className={compact ? "factory-scene factory-compact" : "factory-scene factory-wide"} viewBox={compact ? "0 0 360 760" : "0 0 1200 440"} aria-label="Illustrative conveyor: signals converge at planning, split into parallel tasks, then rejoin integration" role="group">
      <g className="factory-tracks" fill="none" strokeLinecap="round" strokeLinejoin="round">
        {paths.map((d) => <path key={d} d={d} />)}
      </g>
      <g className="factory-rails" fill="none" strokeDasharray="2 12">
        {paths.map((d) => <path key={d} d={d} />)}
      </g>
      {machines.map(([x, y, station], index) => (
        <g key={index} transform={`translate(${x}, ${y})`}>
          <g className={`factory-machine factory-machine-${station}`} onClick={(event) => inspect(station!, false, event.currentTarget)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inspect(station!, false, event.currentTarget); } }} role="button" tabIndex={0} data-station={station} aria-label={`Inspect ${stations[station!]!.name}`}>
            <rect x={compact ? -40 : -62} y="-40" width={compact ? 80 : 124} height="90" rx="8" />
            <path d={station === 0 ? "M-24-20H24L12 8H-12Z M-12 8V22H12V8" : station === 1 ? "M-25-18H25L0 10Z M0 10V28 M-22 28L0 10L22 28" : station === 2 ? "M-25 25H25 M-20 25V-18H20V10H-20 M-10-6L-3 0L-10 6 M3 6H12" : "M-25 24H25 M-22-22V4 M22-22V4 M-22-10H22 M-12 10L0 3L12 10V25H-12Z"} />
            <g className="factory-mechanism"><path d="M-16-30H16" /></g>
          </g>
          {!compact && <text y="78" textAnchor="middle">{station === 2 ? ["Execute", "Validate", "Review"][index - 2] : stations[station!]!.machine}</text>}
        </g>
      ))}
      {paths.map((d, index) => {
        const station = index < 2 ? 0 : index < 5 ? 2 : 3;
        const label = index < 2 ? "signal piece" : index < 5 ? "task piece" : "integration piece";
        return <g key={d} className={`factory-item factory-item-${station}`} data-factory-item style={{ offsetPath: `path('${d}')`, animationDelay: `${-index * 1.7}s` } as CSSProperties}>
          <foreignObject x={compact ? -32 : -48} y={compact ? -32 : -48} width={compact ? 64 : 96} height={compact ? 64 : 96}>
            <button type="button" tabIndex={-1} aria-label={`Inspect illustrative ${label}`} onMouseDown={(event) => event.preventDefault()} onClick={() => inspect(station, true)} className="factory-piece">
              <svg viewBox="0 0 40 40" aria-hidden="true"><path d={index < 2 ? "M10 6H26L32 12V34H10Z M16 17H26 M16 23H26" : index < 5 ? "M6 10H34V30H6Z M12 16L17 20L12 24 M22 24H28" : "M5 13L20 5L35 13V29L20 37L5 29Z M5 13L20 21L35 13 M20 21V37"} /></svg>
            </button>
          </foreignObject>
        </g>;
      })}
      {!compact && <><text x="40" y="55">Incoming observations</text><text x="1130" y="310" textAnchor="middle">Repository output</text></>}
    </svg>
  );
}

export function StewardFactory({ snapshot, activeView }: { snapshot: StewardLiveSnapshot | null; activeView: "signals" | "planning" | "tasks" }) {
  const [paused, setPaused] = useState(true);
  const [reduced, setReduced] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [selection, setSelection] = useState<{ station: number; item: boolean } | null>(null);
  const root = useRef<HTMLElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<SVGGElement | null>(null);
  const close = () => {
    const trigger = returnFocus.current?.getBoundingClientRect().width ? returnFocus.current : [...(root.current?.querySelectorAll<SVGGElement>(`[data-station="${selection?.station}"][tabindex="0"]`) ?? [])].find((node) => node.getBoundingClientRect().width > 0);
    setSelection(null);
    trigger?.focus();
  };
  useEffect(() => { if (selection) panel.current?.focus(); }, [selection]);
  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(media.matches);
    setPaused(media.matches);
    const preference = () => { setReduced(media.matches); if (media.matches) setPaused(true); };
    const visibility = () => setHidden(document.hidden);
    visibility();
    media.addEventListener("change", preference);
    document.addEventListener("visibilitychange", visibility);
    return () => { media.removeEventListener("change", preference); document.removeEventListener("visibilitychange", visibility); };
  }, []);
  const inspect = (station: number, item = false, trigger?: SVGGElement) => {
    returnFocus.current = trigger ?? null;
    setSelection({ station, item });
  };
  const selected = selection ? stations[selection.station]! : null;
  const values = snapshot ? [String(snapshot.signals.pending), snapshot.planning.state.replace(/^./, (letter) => letter.toUpperCase()), `${snapshot.tasks.active} / ${snapshot.tasks.queued}`, `${snapshot.integration.active} / ${snapshot.integration.queued}`] : stations.map(() => "Unavailable");
  return <section ref={root} aria-label="Steward task channels" className="steward-factory" data-motion={paused || hidden || reduced ? "paused" : "running"} onKeyDown={(event) => { if (event.key === "Escape" && selection) { event.preventDefault(); close(); } }}>
    <header className="factory-opening">
      <h1 className="text-2xl font-medium">Steward</h1>
      <div className="flex flex-wrap items-center gap-2"><span className="text-xs text-muted">Demo animation</span><button className="factory-control" type="button" disabled={reduced} aria-label={reduced ? "Play animation (reduced motion)" : paused ? "Play animation" : "Pause animation"} onClick={() => setPaused(!paused)}>{paused || reduced ? "Play" : "Pause"}</button><a className="factory-control text-accent" href="#steward-evidence">View evidence</a></div>
    </header>
    <div className="factory-freshness">
      {snapshot ? <details><summary>{`Updated ${snapshot.observedAt.slice(11, 16)} UTC${snapshot.availability === "stale" ? " (stale)" : ""}`}</summary><span>Daemon {snapshot.daemon.mode === "production" ? "Production" : "Dry run"} · observed <time dateTime={snapshot.observedAt}>{snapshot.observedAt}</time> · stale after {snapshot.staleAfterSeconds}s</span></details> : <span>Live data unavailable · Reload to try again.</span>}
    </div>
    <div className="factory-floor">
      <div className="factory-drawing"><FactoryScene compact={false} inspect={inspect} /><FactoryScene compact inspect={inspect} />
        <nav aria-label="Steward evidence views">{stations.map((station, index) => <Link key={station.name} className={`factory-readout factory-readout-${index}`} href={`/steward?view=${index === 3 ? "tasks" : station.name.toLowerCase()}`} aria-current={index < 3 && station.name.toLowerCase() === activeView ? "page" : undefined}>
          <span>{station.name}</span><span className="data-text">{values[index]}</span><span className="text-muted">{index === 0 ? "pending" : index === 1 ? "planner state" : "active / queued"}</span>
        </Link>)}</nav>
      </div>
      {selection && selected && <div ref={panel} tabIndex={-1} className="factory-inspector" role="region" aria-label="Workflow inspector">
        <h2 className="text-lg font-semibold">{selection.item ? "Demo piece · " : ""}{selected.machine}</h2>
        <p className="text-sm text-muted">{selected.description}</p>
        <div className="flex items-center gap-4"><Link className="text-sm text-accent" href={`/steward?view=${selection.station === 3 ? "tasks" : selected.name.toLowerCase()}#steward-evidence`}>View {selection.station === 3 ? "task" : selected.name.toLowerCase()} evidence</Link><button type="button" className="factory-control" onClick={close}>Close</button></div>
      </div>}
    </div>
  </section>;
}
