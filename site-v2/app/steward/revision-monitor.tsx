"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

export function RevisionMonitor({ initialRevision }: { initialRevision?: number } = {}) {
  const router = useRouter();
  const revision = useRef<string | null>(initialRevision === undefined ? null : String(initialRevision));
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abort = useRef<AbortController | null>(null);
  const failures = useRef(0);
  const [degraded, setDegraded] = useState(false);
  useEffect(() => {
    let stopped = false;
    let delay = 30_000;
    const schedule = (ms: number) => { if (stopped || document.hidden) return; if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(check, ms); };
    const check = async () => {
      if (stopped) return;
      if (document.hidden) return;
      abort.current?.abort();
      const controller = new AbortController(); abort.current = controller;
      try {
        const response = await fetch("/api/steward/revision", { cache: "no-store", signal: controller.signal });
        if (!response.ok) throw new Error("revision unavailable");
        const payload = await response.json() as { data?: { revision?: number } };
        const next = payload.data?.revision === undefined ? null : String(payload.data.revision);
        if (next !== null && revision.current !== null && next !== revision.current) router.refresh();
        if (next !== null) revision.current = next;
        delay = 30_000;
        failures.current = 0; setDegraded(false);
      } catch (error) {
        if (stopped || error instanceof DOMException && error.name === "AbortError") return;
        failures.current += 1; if (failures.current >= 2) setDegraded(true);
        delay = Math.min(120_000, Math.max(30_000, delay * 2));
      }
      schedule(delay);
    };
    const visibility = () => { if (document.hidden) { if (timer.current) clearTimeout(timer.current); timer.current = null; abort.current?.abort(); } else { delay = 30_000; void check(); } };
    document.addEventListener("visibilitychange", visibility);
    void check();
    return () => { stopped = true; document.removeEventListener("visibilitychange", visibility); if (timer.current) clearTimeout(timer.current); abort.current?.abort(); };
  }, [router]);
  return <p className="sr-only" aria-live="polite">{degraded ? "Archive refresh is delayed. Retrying automatically." : ""}</p>;
}
