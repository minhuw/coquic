"use client";

import { Clock3, PanelRightClose, X } from "lucide-react";
import { useEffect, useState } from "react";

interface TimelineEvent {
  id: string;
  stage: string;
  timestamp: string;
  title: string;
  detail: string;
}

function titleCase(value: string) {
  return value.replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase());
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }).format(new Date(value));
}

export function TimelineDrawer({ events, completeness }: { events: TimelineEvent[]; completeness: { state: string; warnings: string[] } }) {
  const [hovered, setHovered] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [hoverSuppressed, setHoverSuppressed] = useState(false);
  const open = pinned || hovered && !hoverSuppressed;

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setPinned(false);
        setHovered(false);
        setHoverSuppressed(true);
      }
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, []);

  return (
    <aside
      aria-label="Execution timeline"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); setHoverSuppressed(false); }}
      className={`fixed right-0 z-40 overflow-hidden border-y border-l border-line bg-surface transition-[width] duration-layer ${open ? "bottom-4 top-16 w-[min(24rem,calc(100vw-1rem))] shadow-temporary" : "bottom-4 h-10 w-10 shadow-none xl:top-16 xl:h-auto"}`}
    >
      <button
        type="button"
        aria-label={open ? "Close timeline" : "Open timeline"}
        aria-expanded={open}
        aria-controls="timeline-drawer-content"
        onClick={() => {
          if (pinned) {
            setPinned(false);
            setHovered(false);
            setHoverSuppressed(true);
          } else {
            setPinned(true);
            setHoverSuppressed(false);
          }
        }}
        title={open ? "Close timeline" : "Open timeline"}
        className="absolute left-0 top-0 flex h-full w-10 cursor-pointer flex-col items-center gap-3 border-0 border-r border-line bg-surface px-0 py-4 text-muted hover:text-ink"
      >
        {open ? <PanelRightClose aria-hidden="true" size={17} /> : <Clock3 aria-hidden="true" size={17} />}
        <span className="hidden text-xs data-text xl:block">{events.length}</span>
        <span className="hidden text-xs font-medium [writing-mode:vertical-rl] xl:block">Timeline</span>
      </button>
      {open ? <div id="timeline-drawer-content" className="ml-10 h-full overflow-y-auto px-5 py-5">
        <div className="flex items-baseline justify-between gap-4">
          <div><p className="text-xs font-medium text-muted">Ordered evidence</p><h2 className="mt-1 text-lg font-semibold text-ink">Timeline</h2></div>
          <button type="button" onClick={() => { setPinned(false); setHovered(false); setHoverSuppressed(true); }} title="Close timeline" className="flex size-9 cursor-pointer items-center justify-center border-0 bg-transparent text-muted hover:text-ink"><X aria-hidden="true" size={16} /></button>
        </div>
        <ol className="mt-4 border-t border-line">{events.map((event) => <li key={event.id} className="border-b border-line py-4"><div className="flex items-baseline justify-between gap-3"><h3 className="text-sm font-semibold text-ink">{event.title}</h3><span className="text-xs text-muted">{titleCase(event.stage)}</span></div><p className="mt-2 text-xs leading-5 text-muted">{event.detail}</p><time className="mt-2 block text-xs text-faint data-text" dateTime={event.timestamp}>{formatDateTime(event.timestamp)}</time></li>)}</ol>
        <div className="mt-6 border-y border-line py-4" aria-label="Publication completeness"><p className="text-sm font-medium text-warning">{titleCase(completeness.state)} publication</p><ul className="mt-2 text-xs leading-5 text-muted">{completeness.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div>
      </div> : null}
    </aside>
  );
}
