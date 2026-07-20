"use client";

import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { RunConfiguration } from "./run-configuration";

interface AttemptDisclosureProps {
  id: string;
  current: boolean;
  number: number;
  label: string;
  summary: string;
  status: ReactNode;
  eventCount: number;
  model?: string | null;
  reasoningEffort?: string | null;
  children: ReactNode;
}

export function AttemptDisclosure({ id, current, number, label, summary, status, eventCount, model, reasoningEffort, children }: AttemptDisclosureProps) {
  const [open, setOpen] = useState(current);

  useEffect(() => {
    if (current) setOpen(true);
  }, [current]);

  const contentId = `${id}-content`;
  return (
    <div id={id} className="scroll-mt-20 border-b-2 border-line-strong last:border-b-0">
      <div className="relative grid w-full gap-3 px-3 py-4 text-left text-inherit sm:grid-cols-[6rem_minmax(0,1fr)_9rem_14rem] sm:items-start sm:gap-5">
        <button
          type="button"
          aria-label={`Attempt ${String(number + 1).padStart(2, "0")}: ${label}`}
          aria-expanded={open}
          aria-controls={contentId}
          onClick={() => setOpen((value) => !value)}
          className="absolute inset-0 z-0 cursor-pointer border-0 bg-transparent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        />
        <span className="pointer-events-none relative z-10 text-xs text-muted data-text">Attempt {String(number + 1).padStart(2, "0")}</span>
        <span className="pointer-events-none relative z-10"><span className="block text-sm font-semibold text-ink">{label}</span><span className="mt-1 block max-w-3xl text-sm leading-6 text-muted">{summary}</span></span>
        <span className="pointer-events-none relative z-10 text-sm">{status}</span>
        <span className="pointer-events-none relative z-10 flex self-stretch items-start justify-end gap-3 text-xs text-muted data-text"><span className="flex min-h-full min-w-0 flex-col items-end justify-between gap-2 text-right"><span>{eventCount} events</span><RunConfiguration model={model} reasoningEffort={reasoningEffort} /></span><ChevronDown aria-hidden="true" size={16} className={`mt-0.5 shrink-0 transition-transform duration-fast ${open ? "rotate-180" : ""}`} /></span>
      </div>
      {open ? <div id={contentId} className="pb-8 pt-6">{children}</div> : null}
    </div>
  );
}
