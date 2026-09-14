"use client";

import { useEffect, useState, type CSSProperties } from "react";
import Link from "next/link";
import type { StewardLiveSnapshot } from "@/lib/steward-live/schema";

const stations = [
  { name: "Signals", machine: "Observation intake", input: "Repository observations.", work: "Collect signals for planning to consider.", output: "Pending signals awaiting triage.", evidence: "Only a pending count is public; no signal contents or event feed." },
  { name: "Planning", machine: "Planning sorter", input: "Pending signals.", work: "Triage observations and select a plan.", output: "Planned work for task execution.", evidence: "Only active, idle, or paused is public; no live plans or run details." },
  { name: "Tasks", machine: "Parallel workstations", input: "Planned tasks.", work: "Execute work in parallel and validate results.", output: "Task output and validation evidence for review.", evidence: "Only active and queued counts are live. Task identities and transcripts come from the separate archive." },
  { name: "Integration", machine: "Integration assembly", input: "Task output and review evidence.", work: "Bring reviewed work together for integration.", output: "Integrated repository output.", evidence: "Only active and queued counts are public; no live progress or completion events. Published evidence remains in the task archive." },
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

function FactoryScene({ compact, inspect }: { compact: boolean; inspect: (station: number, item?: boolean) => void }) {
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
          <g className={`factory-machine factory-machine-${station}`} onClick={() => inspect(station!)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inspect(station!); } }} role="button" tabIndex={-1} aria-label={`Inspect ${stations[station!]!.machine}`}>
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
            <button type="button" tabIndex={-1} aria-label={`Inspect illustrative ${label}`} onClick={() => inspect(station, true)} className="factory-piece">
              <svg viewBox="0 0 40 40" aria-hidden="true"><path d={index < 2 ? "M10 6H26L32 12V34H10Z M16 17H26 M16 23H26" : index < 5 ? "M6 10H34V30H6Z M12 16L17 20L12 24 M22 24H28" : "M5 13L20 5L35 13V29L20 37L5 29Z M5 13L20 21L35 13 M20 21V37"} /></svg>
            </button>
          </foreignObject>
        </g>;
      })}
      {compact && <><text x="180" y="185" textAnchor="middle">Signals</text><text x="180" y="320" textAnchor="middle">Planning</text><text x="180" y="695" textAnchor="middle">Integration ↓ output</text></>}
      {!compact && <><text x="40" y="55">Incoming observations</text><text x="1130" y="310" textAnchor="middle">Repository output</text></>}
    </svg>
  );
}

export function StewardFactory({ snapshot, activeView, historyCount }: { snapshot: StewardLiveSnapshot | null; activeView: "signals" | "planning" | "tasks"; historyCount: number | null }) {
  const [paused, setPaused] = useState(true);
  const [reduced, setReduced] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [selection, setSelection] = useState({ station: 1, item: false });
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
  const inspect = (station: number, item = false) => setSelection({ station, item });
  const selected = stations[selection.station]!;
  const values = snapshot ? [String(snapshot.signals.pending), snapshot.planning.state.replace(/^./, (letter) => letter.toUpperCase()), `${snapshot.tasks.active} / ${snapshot.tasks.queued}`, `${snapshot.integration.active} / ${snapshot.integration.queued}`] : stations.map(() => "Unavailable");
  return <section aria-label="Steward task channels" className="steward-factory" data-motion={paused || hidden || reduced ? "paused" : "running"}>
    <header className="factory-opening">
      <div><p className="text-sm text-muted">Repository automation · Explore factory</p><h1 className="mt-2 text-display-compact sm:text-display font-medium">Steward</h1><p className="mt-3 text-muted">From observation to integrated output. Follow a piece through the line.</p></div>
      <div className="flex flex-wrap items-center gap-4"><button className="factory-control" type="button" disabled={reduced} onClick={() => setPaused(!paused)}>{paused || reduced ? "Play illustration" : "Pause illustration"}</button><a className="factory-control text-accent" href="#steward-evidence">Detailed evidence ↓</a></div>
    </header>
    <p className="factory-caption">Illustrative workflow — not live job tracking. {reduced ? "Reduced motion: illustration paused." : "Select a machine or a moving piece to explore."}</p>
    <div className="factory-floor"><FactoryScene compact={false} inspect={inspect} /><FactoryScene compact inspect={inspect} /></div>
    <div className="factory-explore">
      <ol aria-label="Production line in workflow order" className="factory-stations">
        {stations.map((station, index) => <li key={station.name}><button className="factory-control" aria-pressed={!selection.item && selection.station === index} onClick={() => inspect(index)}>{index + 1}. {station.name}<span aria-hidden="true"> →</span></button></li>)}
      </ol>
      <div className="factory-inspector" role="region" aria-label="Workflow inspector" aria-live="polite">
        <div><h2 className="text-lg font-semibold">{selection.item ? "Illustrative piece · " : ""}{selected.machine}</h2><p className="mt-2 text-sm text-muted">{selected.evidence}</p><button className="factory-control mt-2 text-accent" onClick={() => inspect(selection.station, !selection.item)}>{selection.item ? "Inspect station" : "Inspect representative item"}</button></div>
        <dl>{(["Input", "Work", "Output"] as const).map((term) => <div key={term}><dt className="text-sm font-semibold">{term}</dt><dd className="mt-1 text-sm text-muted">{selected[term.toLowerCase() as "input" | "work" | "output"]}</dd></div>)}</dl>
      </div>
    </div>
    <div className="factory-telemetry">
      <p className="text-sm font-medium">{snapshot ? `Live snapshot ${snapshot.availability}` : "Live snapshot unavailable"} · Literal aggregate evidence</p>
      {snapshot && <p className="mt-1 text-xs text-muted">Daemon {snapshot.daemon.mode === "production" ? "Production" : "Dry run"} · observed <time>{snapshot.observedAt}</time> · stale after {snapshot.staleAfterSeconds}s</p>}
      <nav aria-label="Steward evidence views"><ul className="factory-values">{stations.map((station, index) => <li key={station.name}><Link href={`/steward?view=${index === 3 ? "tasks" : station.name.toLowerCase()}`} aria-current={index < 3 && station.name.toLowerCase() === activeView ? "page" : undefined}><span>{station.name} <span className="text-muted">· {index === 0 ? "pending" : index === 1 ? "planner state" : "active / queued"}</span></span><span className="data-text">{values[index]}{snapshot?.availability === "stale" ? " (stale)" : ""}</span></Link></li>)}</ul></nav>
      <p className="text-xs text-muted">Zero counts and an idle planner can coexist with this illustration: motion does not indicate actual activity. Archive history: {historyCount ?? "Unavailable"} · independent of live counts.</p>
    </div>
  </section>;
}
