import { readFileSync, readdirSync, statSync } from "node:fs";
import type { Dirent } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

export interface PrivateTranscriptItem {
  id: string;
  kind: "assistant" | "tool" | "file" | "todo";
  label: string;
  text?: string;
  command?: string;
  exitCode?: number | null;
  outputBytes?: number;
  changes?: Array<{ path: string; kind: string }>;
  todos?: Array<{ text: string; completed: boolean }>;
  timestamp?: string;
  durationMs?: number;
}

export interface PrivateTranscript {
  sourceBytes: number;
  items: PrivateTranscriptItem[];
  commandCount: number;
  timing: {
    startedAt: string;
    endedAt: string;
    totalDurationMs: number;
    messageIntervals: number;
  } | null;
  usage: {
    turns: Array<{
      ordinal: number;
      inputTokens: number;
      cachedInputTokens: number;
      outputTokens: number;
      reasoningOutputTokens: number;
    }>;
    inputTokens: number;
    cachedInputTokens: number;
    uncachedInputTokens: number;
    outputTokens: number;
    reasoningOutputTokens: number;
    totalTokens: number;
  } | null;
}

interface CachedTranscript {
  signature: string;
  transcript: PrivateTranscript;
  outputs: Map<string, string>;
}

const cache = new Map<string, CachedTranscript>();
const sessionPaths = new Map<string, string | null>();
const taskIdPattern = /^task-[a-zA-Z0-9-]+$/;
const itemIdPattern = /^[a-zA-Z0-9_-]+$/;
const threadIdPattern = /^[a-zA-Z0-9-]+$/;
const workerRunNamePattern = /^worker(?:-(?:validation-)?revision-[0-9]+)?$/;

type TranscriptScope = "attempt" | "plan";

function transcriptPath(taskId: string, index: number, scope: TranscriptScope = "attempt", runName?: string) {
  if (process.env.NODE_ENV !== "development" || !taskIdPattern.test(taskId) || !Number.isSafeInteger(index) || index < 0) return null;
  if (scope === "plan") {
    const root = resolve(process.cwd(), "..", ".coquic", "steward", "transcripts");
    return resolve(root, taskId, `implementation-plan-${index}`, "codex.jsonl");
  }
  if (runName && workerRunNamePattern.test(runName)) {
    const root = resolve(process.cwd(), "..", ".coquic", "steward", "transcripts");
    return resolve(root, taskId, runName, "codex.jsonl");
  }
  if (index !== 0) return null;
  const root = process.env.STEWARD_PRIVATE_TRANSCRIPTS_DIR
    ? resolve(process.env.STEWARD_PRIVATE_TRANSCRIPTS_DIR)
    : resolve(process.cwd(), "..", ".orca", "steward", "private");
  return resolve(root, taskId, "worker", "codex.jsonl");
}

function compactLabel(value: string, limit = 62) {
  const compact = value.replaceAll(/\s+/g, " ").trim();
  return compact.length > limit ? `${compact.slice(0, limit - 1)}…` : compact;
}

function repositoryPath(path: string, taskId: string) {
  const marker = `/worktrees/${taskId}/`;
  const markerIndex = path.indexOf(marker);
  return markerIndex === -1 ? path : path.slice(markerIndex + marker.length);
}

function tokenCounter(value: unknown) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function findSessionPath(threadId: string) {
  const known = sessionPaths.get(threadId);
  if (known !== undefined) return known;

  const root = process.env.CODEX_SESSIONS_DIR
    ? resolve(process.env.CODEX_SESSIONS_DIR)
    : resolve(homedir(), ".codex", "sessions");
  const suffix = `-${threadId}.jsonl`;
  const directories = [root];
  let found: string | null = null;

  while (directories.length && !found) {
    const directory = directories.pop()!;
    let entries: Dirent<string>[];
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) directories.push(path);
      else if (entry.isFile() && entry.name.endsWith(suffix)) {
        found = path;
        break;
      }
    }
  }

  sessionPaths.set(threadId, found);
  return found;
}

function sessionMessageTiming(threadId: string) {
  const path = findSessionPath(threadId);
  if (!path) return null;

  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch {
    return null;
  }

  let startedAt: string | null = null;
  const messages: Array<{ text: string; timestamp: string; durationMs: number }> = [];
  let previousTime: number | null = null;

  for (const line of source.split("\n")) {
    if (!line.trim()) continue;
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (record.type !== "event_msg" || typeof record.timestamp !== "string" || !record.payload || typeof record.payload !== "object") continue;
    const payload = record.payload as Record<string, unknown>;

    if (payload.type === "task_started" && !startedAt) {
      startedAt = record.timestamp;
      previousTime = Date.parse(record.timestamp);
      continue;
    }
    if (!startedAt) continue;
    if (payload.type === "task_complete") break;
    if (payload.type !== "agent_message" || typeof payload.message !== "string") continue;

    const timestamp = Date.parse(record.timestamp);
    if (!Number.isFinite(timestamp) || previousTime === null || timestamp < previousTime) return null;
    messages.push({ text: payload.message, timestamp: record.timestamp, durationMs: timestamp - previousTime });
    previousTime = timestamp;
  }

  return startedAt && messages.length ? { startedAt, messages } : null;
}

function parseTranscript(path: string, taskId: string): CachedTranscript | null {
  let source: string;
  let stat: ReturnType<typeof statSync>;
  try {
    stat = statSync(path);
    source = readFileSync(path, "utf8");
  } catch {
    return null;
  }

  const signature = `${stat.size}:${stat.mtimeMs}`;
  const cached = cache.get(path);
  if (cached?.signature === signature) return cached;

  const items: PrivateTranscriptItem[] = [];
  const outputs = new Map<string, string>();
  const usageTurns: NonNullable<PrivateTranscript["usage"]>["turns"] = [];
  let commandCount = 0;
  let threadId: string | null = null;

  for (const line of source.split("\n")) {
    if (!line.trim()) continue;
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    if (record.type === "thread.started" && typeof record.thread_id === "string" && threadIdPattern.test(record.thread_id)) {
      threadId = record.thread_id;
      continue;
    }

    if (record.type === "turn.completed" && record.usage && typeof record.usage === "object") {
      const value = record.usage as Record<string, unknown>;
      const inputTokens = tokenCounter(value.input_tokens);
      const cachedInputTokens = tokenCounter(value.cached_input_tokens);
      const outputTokens = tokenCounter(value.output_tokens);
      const reasoningOutputTokens = tokenCounter(value.reasoning_output_tokens);
      if (
        inputTokens !== null && cachedInputTokens !== null && outputTokens !== null && reasoningOutputTokens !== null
        && cachedInputTokens <= inputTokens && reasoningOutputTokens <= outputTokens
      ) {
        usageTurns.push({
          ordinal: usageTurns.length + 1,
          inputTokens,
          cachedInputTokens,
          outputTokens,
          reasoningOutputTokens,
        });
      }
      continue;
    }

    if (!record.item || typeof record.item !== "object") continue;
    const item = record.item as Record<string, unknown>;
    const id = typeof item.id === "string" && itemIdPattern.test(item.id) ? item.id : null;
    const itemType = typeof item.type === "string" ? item.type : "";

    if (record.type === "item.completed" && itemType === "agent_message" && id && typeof item.text === "string") {
      items.push({ id, kind: "assistant", label: compactLabel(item.text), text: item.text });
      continue;
    }

    if (record.type === "item.completed" && itemType === "command_execution" && id && typeof item.command === "string") {
      const output = typeof item.aggregated_output === "string" ? item.aggregated_output : "";
      outputs.set(id, output);
      commandCount += 1;
      items.push({
        id,
        kind: "tool",
        label: compactLabel(item.command.replace(/^\/bin\/bash\s+-lc\s+/, "")),
        command: item.command,
        exitCode: typeof item.exit_code === "number" ? item.exit_code : null,
        outputBytes: Buffer.byteLength(output),
      });
      continue;
    }

    if (record.type === "item.completed" && itemType === "file_change" && id && Array.isArray(item.changes)) {
      const changes = item.changes.flatMap((change) => {
        if (!change || typeof change !== "object") return [];
        const value = change as Record<string, unknown>;
        if (typeof value.path !== "string" || typeof value.kind !== "string") return [];
        return [{ path: repositoryPath(value.path, taskId), kind: value.kind }];
      });
      items.push({ id, kind: "file", label: `${changes.length} ${changes.length === 1 ? "file" : "files"} changed`, changes });
      continue;
    }

    if ((record.type === "item.started" || record.type === "item.updated" || record.type === "item.completed") && itemType === "todo_list" && id && Array.isArray(item.items)) {
      const todos = item.items.flatMap((todo) => {
        if (!todo || typeof todo !== "object") return [];
        const value = todo as Record<string, unknown>;
        return typeof value.text === "string" ? [{ text: value.text, completed: value.completed === true }] : [];
      });
      const state = record.type === "item.started" ? "Plan created" : record.type === "item.completed" ? "Plan completed" : "Plan updated";
      items.push({ id: `${id}-${items.length}`, kind: "todo", label: state, todos });
    }
  }

  const aggregate = usageTurns.reduce(
    (total, turn) => ({
      inputTokens: total.inputTokens + turn.inputTokens,
      cachedInputTokens: total.cachedInputTokens + turn.cachedInputTokens,
      outputTokens: total.outputTokens + turn.outputTokens,
      reasoningOutputTokens: total.reasoningOutputTokens + turn.reasoningOutputTokens,
    }),
    { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0, reasoningOutputTokens: 0 },
  );
  const usage: PrivateTranscript["usage"] = usageTurns.length ? {
    turns: usageTurns,
    ...aggregate,
    uncachedInputTokens: aggregate.inputTokens - aggregate.cachedInputTokens,
    totalTokens: aggregate.inputTokens + aggregate.outputTokens,
  } : null;
  const sessionTiming = threadId ? sessionMessageTiming(threadId) : null;
  const assistantItems = items.filter((item) => item.kind === "assistant");
  let timing: PrivateTranscript["timing"] = null;
  if (sessionTiming && assistantItems.length === sessionTiming.messages.length && assistantItems.every((item, index) => item.text === sessionTiming.messages[index].text)) {
    assistantItems.forEach((item, index) => {
      item.timestamp = sessionTiming.messages[index].timestamp;
      item.durationMs = sessionTiming.messages[index].durationMs;
    });
    const endedAt = sessionTiming.messages.at(-1)!.timestamp;
    timing = {
      startedAt: sessionTiming.startedAt,
      endedAt,
      totalDurationMs: Date.parse(endedAt) - Date.parse(sessionTiming.startedAt),
      messageIntervals: assistantItems.length,
    };
  }
  const result = {
    signature,
    transcript: { sourceBytes: stat.size, items, commandCount, timing, usage },
    outputs,
  };
  cache.set(path, result);
  return result;
}

export function getPrivateTranscript(taskId: string, attempt: number, runName?: string) {
  const path = transcriptPath(taskId, attempt, "attempt", runName);
  return path ? parseTranscript(path, taskId)?.transcript ?? null : null;
}

export function getPrivatePlanTranscript(taskId: string, run: number) {
  const path = transcriptPath(taskId, run, "plan");
  return path ? parseTranscript(path, taskId)?.transcript ?? null : null;
}

export function getPrivateTranscriptOutput(taskId: string, index: number, itemId: string, scope: TranscriptScope = "attempt", runName?: string) {
  if (!itemIdPattern.test(itemId)) return null;
  const path = transcriptPath(taskId, index, scope, runName);
  return path ? parseTranscript(path, taskId)?.outputs.get(itemId) ?? null : null;
}
