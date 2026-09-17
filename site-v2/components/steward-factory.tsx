"use client";

import { useEffect, useRef, useState, type CSSProperties } from "react";
import Link from "next/link";
import { GitMerge, ListTree, Radio, ScanEye, ShieldCheck, SquareTerminal } from "lucide-react";
import type { StewardLiveSnapshot } from "@/lib/steward-live/schema";

const stations = [
  { name: "Signals", machine: "Signals", description: "Collect repository observations for planning. The public snapshot exposes the pending count, not signal contents." },
  { name: "Planning", machine: "Planning", description: "Triage observations and select work. Only the planner state is public; plans and run details appear only in published tasks." },
  { name: "Tasks", machine: "Task workflow", description: "Each task proceeds through Execute, Validate, then Review. Multiple tasks can move through this sequence concurrently. Active and queued counts are live; identities, transcripts, and usage belong to published tasks." },
  { name: "Integration", machine: "Integration assembly", description: "Bring reviewed work together for integration. Active and queued counts do not expose progress or completion events; available evidence is in published tasks." },
] as const;

// Coordinates and representative pieces are illustrative, never snapshot counters.
const machines = [
  { label: "Signals", station: 0, Icon: Radio, x: 150, y: 100 },
  { label: "Planning", station: 1, Icon: ListTree, x: 330, y: 250 },
  { label: "Execute", station: 2, Icon: SquareTerminal, x: 510, y: 400 },
  { label: "Validate", station: 2, Icon: ShieldCheck, x: 690, y: 550 },
  { label: "Review", station: 2, Icon: ScanEye, x: 870, y: 700 },
  { label: "Integration", station: 3, Icon: GitMerge, x: 1050, y: 850 },
] as const;
const pieces = [
  { kind: "signal", station: 0, wide: "M 40 230 H 330", compact: "M 95 30 V 250", delay: -2, duration: 10, glyph: "M10 6H26L32 12V34H10Z M16 17H26 M16 23H26" },
  { kind: "task", station: 2, wide: "M 330 230 H 1050", compact: "M 95 250 V 850", delay: 0, duration: 18, glyph: "M6 10H34V30H6Z M12 16L17 20L12 24 M22 24H28" },
  { kind: "integration", station: 3, wide: "M 1050 230 H 1160", compact: "M 95 850 V 930", delay: -4, duration: 10, glyph: "M5 13L20 5L35 13V29L20 37L5 29Z M5 13L20 21L35 13 M20 21V37" },
] as const;

function FactoryScene({ compact, inspect }: { compact: boolean; inspect: (station: number, item?: boolean, trigger?: SVGGElement) => void }) {
  const track = compact ? "M 95 30 V 930" : "M 40 230 H 1160";
  return (
    <svg className={compact ? "factory-scene factory-compact" : "factory-scene factory-wide"} viewBox={compact ? "0 0 360 960" : "0 0 1200 440"} aria-label="Illustrative conveyor: Signals → Planning → Tasks (Execute → Validate → Review) → Integration" role="group">
      <path className="factory-tracks" d={track} fill="none" strokeLinecap="round" />
      <path className="factory-rails" d={track} fill="none" strokeDasharray="2 12" />
      <path className="factory-task-bracket" d={compact ? "M 148 355 H 160 V 750 H 148" : "M 448 152 V 140 H 932 V 152"} fill="none" />
      {machines.map(({ label, station, Icon, x, y }) => (
        <g key={label} transform={`translate(${compact ? 95 : x}, ${compact ? y : 230})`}>
          <g className={`factory-machine factory-machine-${station}`} onClick={(event) => inspect(station, false, event.currentTarget)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inspect(station, false, event.currentTarget); } }} role="button" tabIndex={0} data-station={station} aria-label={`Inspect ${label}`}>
            <rect x={compact ? -40 : -62} y="-40" width={compact ? 80 : 124} height="90" rx="8" />
            <Icon className="factory-machine-icon" x={-22} y={-17} width={44} height={44} strokeWidth={1.8} aria-hidden="true" focusable="false" />
          </g>
          <text className="factory-step-label" y="78" textAnchor="middle">{label}</text>
        </g>
      ))}
      {pieces.map(({ kind, station, wide, compact: compactPath, delay, duration, glyph }) => (
        <g key={kind} className={`factory-item factory-item-${station}`} data-factory-item={kind} style={{ offsetPath: `path('${compact ? compactPath : wide}')`, animationDelay: `${delay}s`, animationDuration: `${duration}s` } as CSSProperties}>
          <foreignObject x={compact ? -32 : -48} y={compact ? -32 : -48} width={compact ? 64 : 96} height={compact ? 64 : 96}>
            <button type="button" tabIndex={-1} aria-label={`Inspect illustrative ${kind} piece`} onMouseDown={(event) => event.preventDefault()} onClick={() => inspect(station, true)} className="factory-piece">
              <svg viewBox="0 0 40 40" aria-hidden="true"><path d={glyph} /></svg>
            </button>
          </foreignObject>
        </g>
      ))}
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
      {snapshot ? <time dateTime={snapshot.observedAt}>{`Updated ${snapshot.observedAt.slice(11, 16)} UTC${snapshot.availability === "stale" ? " (stale)" : ""}`}</time> : <span>Live data unavailable · Reload to try again.</span>}
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
