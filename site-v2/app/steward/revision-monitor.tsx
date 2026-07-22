"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";

export function RevisionMonitor() {
  const router = useRouter();
  const revision = useRef<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => {
    let stopped = false;
    let delay = 30_000;
    const schedule = (ms: number) => { if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(check, ms); };
    const check = async () => {
      if (stopped) return;
      if (document.hidden) { schedule(30_000); return; }
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
      } catch { delay = Math.min(120_000, Math.max(30_000, delay * 2)); }
      schedule(delay);
    };
    const visibility = () => { if (!document.hidden) { delay = 30_000; void check(); } };
    document.addEventListener("visibilitychange", visibility);
    void check();
    return () => { stopped = true; document.removeEventListener("visibilitychange", visibility); if (timer.current) clearTimeout(timer.current); abort.current?.abort(); };
  }, [router]);
  return null;
}
