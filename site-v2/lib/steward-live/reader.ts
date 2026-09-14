import "server-only";

import { parseStewardLiveSnapshot, type StewardLiveSnapshot } from "./schema";

export type StewardLiveReadErrorCode = "misconfigured" | "timeout" | "unavailable" | "invalid";

export class StewardLiveReadError extends Error {
  readonly code: StewardLiveReadErrorCode;

  constructor(code: StewardLiveReadErrorCode) {
    super(`Steward live snapshot ${code}`);
    this.name = "StewardLiveReadError";
    this.code = code;
  }
}

export type StewardLiveReaderOptions = {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
};

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;

async function readBoundedBody(response: Response, maximum: number): Promise<string> {
  const declared = response.headers.get("content-length")?.trim();
  if (declared && /^\d+$/.test(declared) && Number(declared) > maximum) {
    throw new StewardLiveReadError("invalid");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new StewardLiveReadError("invalid");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maximum) {
        await reader.cancel().catch(() => undefined);
        throw new StewardLiveReadError("invalid");
      }
      chunks.push(item.value);
    }
  } catch (error) {
    if (error instanceof StewardLiveReadError) throw error;
    throw new StewardLiveReadError("invalid");
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new StewardLiveReadError("invalid");
  }
}

export function parseStewardLiveSnapshotUrl(env: Readonly<Record<string, string | undefined>> = process.env): string {
  const raw = env.COQUIC_STEWARD_LIVE_SNAPSHOT_URL?.trim();
  if (!raw || CONTROL_CHARACTER.test(raw) || raw.includes("\\")) throw new StewardLiveReadError("misconfigured");
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.hash) throw new Error();
    return url.href;
  } catch {
    throw new StewardLiveReadError("misconfigured");
  }
}

export async function readStewardLiveSnapshot(options: StewardLiveReaderOptions = {}): Promise<StewardLiveSnapshot> {
  const fetcher = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 3_000;
  const maxResponseBytes = options.maxResponseBytes ?? 64 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000 || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new StewardLiveReadError("misconfigured");
  }

  try {
    const response = await fetcher(parseStewardLiveSnapshotUrl(options.env), {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new StewardLiveReadError("unavailable");
    if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new StewardLiveReadError("invalid");
    const source = await readBoundedBody(response, maxResponseBytes);
    try {
      return parseStewardLiveSnapshot(source);
    } catch {
      throw new StewardLiveReadError("invalid");
    }
  } catch (error) {
    if (error instanceof StewardLiveReadError) throw error;
    if (error instanceof DOMException && error.name === "TimeoutError") throw new StewardLiveReadError("timeout");
    throw new StewardLiveReadError("unavailable");
  }
}
