"use client";

import {
  BookOpenText,
  ChevronLeft,
  ChevronRight,
  CodeXml,
  FlaskConical,
  Search,
  ShieldCheck,
} from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";

export type RunPhaseKind = "understand" | "inspect" | "implement" | "validate" | "review";

export interface RunOutlinePhase {
  kind: RunPhaseKind;
  label: string;
  summary: string;
  events: Array<{
    id: string;
    sequence: number;
    label: string;
    outcome: "passed" | "failed" | "running" | null;
  }>;
}

const phaseIcons = {
  understand: BookOpenText,
  inspect: Search,
  implement: CodeXml,
  validate: FlaskConical,
  review: ShieldCheck,
};

export function TranscriptLayout({ anchorPrefix, phases, children }: { anchorPrefix: string; phases: RunOutlinePhase[]; children: ReactNode }) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className={`mt-6 grid min-w-0 gap-6 lg:items-start ${expanded ? "lg:grid-cols-[15rem_minmax(0,1fr)] lg:gap-10" : "lg:grid-cols-[2.75rem_minmax(0,1fr)] lg:gap-6"}`}>
      <aside aria-label="Run outline" className="min-w-0 border-t border-line lg:sticky lg:top-20">
        <div className={`flex min-h-11 items-center border-b border-line ${expanded ? "justify-between gap-3" : "justify-center"}`}>
          {expanded ? <p className="text-xs font-semibold text-ink">Run outline</p> : null}
          <button
            type="button"
            aria-label={expanded ? "Collapse run outline" : "Expand run outline"}
            title={expanded ? "Collapse run outline" : "Expand run outline"}
            className="flex size-9 shrink-0 cursor-pointer items-center justify-center text-muted transition-colors duration-fast hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? <ChevronLeft aria-hidden="true" size={16} /> : <ChevronRight aria-hidden="true" size={16} />}
          </button>
        </div>

        {expanded ? (
          <ol>
            {phases.map((phase) => {
              const Icon = phaseIcons[phase.kind];
              return (
                <li key={phase.kind} className="border-b border-line">
                  <details className="group">
                    <summary className="cursor-pointer list-none py-3">
                      <span className="grid grid-cols-[1rem_minmax(0,1fr)_1rem] items-start gap-2">
                        <Icon aria-hidden="true" size={14} className="mt-0.5 shrink-0 text-faint transition-colors group-hover:text-accent" />
                        <span className="min-w-0">
                          <span className="block text-xs font-semibold text-ink">{phase.label}</span>
                          <span className="mt-1 block text-xs leading-4 text-faint data-text">{phase.summary}</span>
                        </span>
                        <ChevronRight aria-hidden="true" size={14} className="mt-0.5 text-faint transition-transform duration-fast group-open:rotate-90" />
                      </span>
                    </summary>
                    <ol className="border-t border-line pb-1">
                      {phase.events.map((event) => (
                        <li key={event.id}>
                          <a
                            href={`#${anchorPrefix}-event-${event.id}`}
                            className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-2 py-2 text-muted no-underline hover:text-ink"
                          >
                            <span className="text-xs text-faint data-text">{String(event.sequence).padStart(2, "0")}</span>
                            <span className={`text-xs leading-4 [overflow-wrap:anywhere] ${event.outcome === "failed" ? "text-negative" : event.outcome === "running" ? "text-accent" : ""}`}>{event.label}</span>
                          </a>
                        </li>
                      ))}
                    </ol>
                  </details>
                </li>
              );
            })}
          </ol>
        ) : null}
      </aside>
      <div className="min-w-0">{children}</div>
    </div>
  );
}
