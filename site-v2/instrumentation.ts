declare global {
  // eslint-disable-next-line no-var
  var __coquicStewardArchiveStarted: boolean | undefined;
}

export function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs" || globalThis.__coquicStewardArchiveStarted) return;
  globalThis.__coquicStewardArchiveStarted = true;
  void import("@/lib/steward-archive/repository").then(({ getArchiveRepository }) => {
    try { getArchiveRepository(); } catch { /* status routes expose unavailable state */ }
  }).catch(() => { /* status routes expose unavailable state */ });
}
