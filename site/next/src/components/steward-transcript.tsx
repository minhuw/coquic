"use client";

import { type ReactNode, useId, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  Activity,
  ChevronRight,
  Inbox,
  ImageIcon,
  ListChecks,
  MessageSquareText,
  ExternalLink,
  Send,
  UserRound,
  XCircle,
} from "lucide-react";
import { CodexTranscriptThread } from "./codex-transcript-thread";
import { parseCodexTranscriptText } from "@/lib/codex-transcript";
import { CodeBlock } from "./steward-code-block";

export type PublicCodexRunDiagnostics = {
  status: string;
  summary: string;
  exit_code: number | null;
  last_message_present: boolean;
  event_count: number;
  error_count: number;
  last_event_type: string;
  last_item_type: string;
  last_item_status: string;
  last_error: string;
  last_output: string;
  timed_out: boolean;
  thread_id?: string;
};

type TextBlock = {
  kind: "code" | "diff" | "image" | "text";
  language?: string;
  text: string;
};

type PlannerDecision = {
  consumed_item_ids: string[];
  tasks: PlannerScheduledTask[];
};

type PlannerScheduledTask = {
  dedupe_key?: string;
  evidence?: string[];
  kind?: string;
  metadata?: Record<string, unknown>;
  priority?: string;
  prompt?: string;
  risk?: string;
  title?: string;
  worker?: string;
};

type PlannerInput = {
  activeTasks: unknown[];
  inboxMessages: PlannerInboxMessage[];
  remoteIntegrationEnabled: boolean;
  repository: string;
};

type PlannerInboxMessage = {
  created_at?: string;
  id?: string;
  kind?: string;
  provider?: string;
  status?: string;
  summary?: string;
  title?: string;
  updated_at?: string;
};

export function TranscriptView({
  diagnostics,
  isLiveRun = false,
  prompt,
  taskId,
  text,
}: {
  diagnostics?: PublicCodexRunDiagnostics | null;
  isLiveRun?: boolean;
  prompt: string;
  taskId: string;
  text: string;
}) {
  if (!text) {
    return (
      <div className="chat-transcript" aria-label="Agent transcript">
        <SessionDiagnostics diagnostics={diagnostics} isLiveRun={isLiveRun} />
        <div className="empty-state">No transcript captured for the selected task.</div>
      </div>
    );
  }
  const promptParts = displayPromptParts(prompt);
  const records = parseCodexTranscriptText(text);
  if (!records.length) {
    return (
      <div className="chat-transcript" aria-label="Agent transcript">
        <SessionDiagnostics diagnostics={diagnostics} isLiveRun={isLiveRun} />
        {promptParts.boilerplate && <CollapsedPrompt text={promptParts.boilerplate} />}
        {promptParts.visible && (
          <ChatBubble hideLabel={isPlannerInputPrompt(promptParts.visible)} label="Task prompt" role="user">
            <TextBlocks taskId={taskId} text={promptParts.visible} />
          </ChatBubble>
        )}
        {metadataOnlyTranscript(text) ? (
          <div className="empty-state">No displayable agent output has been captured yet.</div>
        ) : (
          <ChatBubble label="Transcript text" role="assistant">
            <TextBlocks taskId={taskId} text={text} />
          </ChatBubble>
        )}
      </div>
    );
  }
  return (
    <div className="chat-transcript" aria-label="Agent transcript">
      <SessionDiagnostics diagnostics={diagnostics} isLiveRun={isLiveRun} />
      {promptParts.boilerplate && <CollapsedPrompt text={promptParts.boilerplate} />}
      {promptParts.visible && (
        <ChatBubble hideLabel={isPlannerInputPrompt(promptParts.visible)} label="Task prompt" role="user">
          <TextBlocks taskId={taskId} text={promptParts.visible} />
        </ChatBubble>
      )}
      <CodexTranscriptThread records={records} />
    </div>
  );
}

function SessionDiagnostics({
  diagnostics,
  isLiveRun,
}: {
  diagnostics?: PublicCodexRunDiagnostics | null;
  isLiveRun: boolean;
}) {
  if (!diagnostics || diagnostics.status === "ok") return null;
  if (diagnostics.status === "missing_last_message") {
    return isLiveRun ? <SessionRunningNotice /> : null;
  }
  const tail = diagnostics.last_item_type || diagnostics.last_event_type;
  return (
    <ToolCard
      icon={<XCircle size={16} />}
      meta={diagnostics.status.replaceAll("_", " ")}
      title="Session diagnostics"
      tone="danger"
    >
      <div className="session-diagnostics">
        <p>
          {diagnostics.summary || "Codex session did not finish cleanly."}
        </p>
        <dl>
          {diagnostics.exit_code !== null && <DiagFact label="Exit" value={String(diagnostics.exit_code)} />}
          <DiagFact label="Events" value={String(diagnostics.event_count)} />
          <DiagFact label="Errors" value={String(diagnostics.error_count)} />
          {tail && <DiagFact label="Last event" value={tail} />}
          <DiagFact
            label="Last message"
            value={diagnostics.last_message_present ? "written" : "missing"}
          />
          {diagnostics.thread_id && <DiagFact label="Thread" value={diagnostics.thread_id} />}
        </dl>
        {diagnostics.last_error && <CodeBlock compact text={diagnostics.last_error} title="Last error" />}
        {!diagnostics.last_error && diagnostics.last_output && (
          <CodeBlock compact text={diagnostics.last_output} title="Last output" />
        )}
      </div>
    </ToolCard>
  );
}

function SessionRunningNotice() {
  return (
    <div className="session-running" role="status">
      <Activity size={14} />
      <span>Session running; final message pending.</span>
    </div>
  );
}

function DiagFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function displayPromptParts(prompt: string): { boilerplate: string; visible: string } {
  if (!isPlannerBoilerplatePrompt(prompt)) return { boilerplate: "", visible: prompt };
  const inputIndex = prompt.indexOf("Planning input JSON:");
  return {
    boilerplate: inputIndex >= 0 ? prompt.slice(0, inputIndex).trim() : prompt.trim(),
    visible: inputIndex >= 0 ? prompt.slice(inputIndex).trim() : "",
  };
}

function isPlannerBoilerplatePrompt(prompt: string) {
  const normalized = prompt.replace(/\s+/g, " ").trim().toLowerCase();
  const markers = [
    "coquic steward's planning brain",
    "decide which maintenance tasks should exist",
    "review active_tasks before proposing anything",
    "return only json matching the requested schema",
    "evidence ids you may cite",
  ];
  return markers.filter((marker) => normalized.includes(marker)).length >= 3;
}

function isPlannerInputPrompt(prompt: string) {
  return prompt.trimStart().startsWith("Planning input JSON:");
}

function CollapsedPrompt({ text }: { text: string }) {
  return (
    <details className="collapsed-prompt">
      <summary>Planner instructions</summary>
      <TextBlocks taskId="" text={text} />
    </details>
  );
}

function ChatBubble({
  children,
  hideLabel = false,
  label,
  role,
}: {
  children: ReactNode;
  hideLabel?: boolean;
  label: string;
  role: "assistant" | "user";
}) {
  return (
    <article className={`chat-bubble ${role}`}>
      <div className="chat-avatar">
        {role === "user" ? <UserRound size={16} /> : <MessageSquareText size={16} />}
      </div>
      <div className="chat-body">
        {!hideLabel && <div className="chat-label">{label}</div>}
        {children}
      </div>
    </article>
  );
}

function ToolCard({
  children,
  icon,
  meta,
  title,
  tone,
}: {
  children: ReactNode;
  icon: ReactNode;
  meta: string;
  title: string;
  tone: "danger" | "neutral" | "ok" | "pending";
}) {
  const bodyId = useId();
  const [open, setOpen] = useState(tone === "danger" || tone === "pending");
  const toggle = () => setOpen((current) => !current);
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    toggle();
  };

  return (
    <article className={`tool-card ${tone} ${open ? "open" : ""}`}>
      <div
        aria-controls={bodyId}
        aria-expanded={open}
        className="tool-head"
        onClick={toggle}
        onKeyDown={onKeyDown}
        role="button"
        tabIndex={0}
      >
        <div className="tool-icon">{icon}</div>
        <div>
          <h3>{title}</h3>
          <span>{meta}</span>
          {!open && <em>Click to inspect output</em>}
        </div>
        <ChevronRight className="tool-chevron" size={15} />
      </div>
      {open && <div className="tool-body" id={bodyId}>{children}</div>}
    </article>
  );
}

function TextBlocks({ mode = "message", taskId, text }: { mode?: "message" | "tool"; taskId: string; text: string }) {
  const plannerDecision = mode === "message" ? parsePlannerDecision(text) : null;
  if (plannerDecision) return <PlannerDecisionCard decision={plannerDecision} />;
  const blocks = splitTextBlocks(text);
  return (
    <>
      {blocks.map((block, index) => {
        if (block.kind === "diff") return <DiffBlock key={index} text={block.text} />;
        if (block.kind === "image") return <ImageBlock key={index} path={block.text} taskId={taskId} />;
        if (block.kind === "code") {
          return (
            <CodeBlock
              className="chat-code"
              compact
              key={index}
              language={block.language}
              text={block.text}
            />
          );
        }
        if (mode === "tool") {
          return (
            <CodeBlock
              className="tool-output"
              compact
              key={index}
              text={block.text}
              title="Output"
            />
          );
        }
        const plannerInput = parsePlannerInput(block.text);
        if (plannerInput) return <PlannerInputCard input={plannerInput} key={index} />;
        return (
          <p className="chat-text" key={index}>
            <EscapedText text={block.text} />
          </p>
        );
      })}
    </>
  );
}

function EscapedText({ text }: { text: string }) {
  return <>{text}</>;
}

function PlannerInputCard({ input }: { input: PlannerInput }) {
  return (
    <section className="planner-input-card" aria-label="Planner input context">
      <div className="planner-input-head">
        <div>
          <span className="planner-decision-kicker">Pending inbox</span>
          <div className="planner-decision-counts">
            <span><Inbox size={14} /> {input.inboxMessages.length} inbox</span>
            <span><ListChecks size={14} /> {input.activeTasks.length} active</span>
          </div>
        </div>
      </div>
      {input.inboxMessages.length > 0 && (
        <section className="planner-inbox-section" aria-label="Pending planner inbox">
          <div className="planner-inbox-list">
            {input.inboxMessages.map((message, index) => (
              <PlannerInboxSignalCard
                key={`${message.id || message.title || "message"}-${index}`}
                message={message}
                repository={input.repository}
              />
            ))}
          </div>
        </section>
      )}
    </section>
  );
}

function PlannerInboxSignalCard({
  message,
  repository,
}: {
  message: PlannerInboxMessage;
  repository: string;
}) {
  const codacy = message.summary ? codacySignal(message.summary, repository) : null;
  const timestamp = message.created_at || message.updated_at;
  return (
    <article className={`signal-card ${message.status || "pending"}`}>
      <div className="signal-card-select">
        <div className="signal-card-main">
          <div className="signal-card-head">
            <span className="provider-pill">{message.provider || message.kind || "signal"}</span>
            {timestamp && <time className="mono muted" dateTime={timestamp}>{shortDate(timestamp)}</time>}
          </div>
          <h3>{message.title || message.kind || "Inbox message"}</h3>
          <PlannerInboxSummary codacy={codacy} message={message} />
        </div>
      </div>
      <div className="signal-card-actions">
        {message.id && <code>{message.id}</code>}
        {codacy?.url && (
          <a className="button-link signal-link" href={codacy.url} rel="noreferrer" target="_blank">
            <ExternalLink size={13} />
            <span>Open Codacy</span>
          </a>
        )}
      </div>
    </article>
  );
}

function PlannerInboxSummary({
  codacy,
  message,
}: {
  codacy: ReturnType<typeof codacySignal> | null;
  message: PlannerInboxMessage;
}) {
  if (!message.summary || summaryMatchesTitle(message.summary, message.title)) return null;
  if (codacy) {
    return (
      <div className="signal-summary codacy">
        <div className="signal-count">
          <b>{codacy.count}</b>
          <span>open finding{codacy.count === 1 ? "" : "s"}</span>
        </div>
      </div>
    );
  }
  return <p>{message.summary}</p>;
}

function PlannerDecisionCard({ decision }: { decision: PlannerDecision }) {
  return (
    <section className="planner-decision-card" aria-label="Planner scheduling decision">
      <div className="planner-decision-head">
        <div>
          <span className="planner-decision-kicker">Scheduling decision</span>
          <h3>{decision.tasks.length ? `${decision.tasks.length} task${decision.tasks.length === 1 ? "" : "s"} queued` : "No tasks queued"}</h3>
        </div>
        <div className="planner-decision-counts">
          <span><Inbox size={14} /> {decision.consumed_item_ids.length} consumed</span>
          <span><Send size={14} /> {decision.tasks.length} scheduled</span>
        </div>
      </div>
      <div className="planner-task-list">
        {decision.tasks.map((task, index) => (
          <PlannerScheduledTaskCard
            consumedItemIds={decision.consumed_item_ids}
            key={`${task.dedupe_key || task.title || "task"}-${index}`}
            task={task}
          />
        ))}
      </div>
    </section>
  );
}

function PlannerScheduledTaskCard({
  consumedItemIds,
  task,
}: {
  consumedItemIds: string[];
  task: PlannerScheduledTask;
}) {
  const visibleEvidence = (task.evidence || []).filter(
    (item) => item !== task.dedupe_key && !consumedItemIds.includes(item),
  );
  return (
    <article className="planner-task-card">
      <div className="planner-task-head">
        <div>
          <span>{task.kind || "task"}</span>
          <h4>{task.title || "Untitled task"}</h4>
        </div>
        <div className="planner-task-chips">
          {task.priority && <span className="priority">{task.priority}</span>}
          {task.risk && <span>{task.risk}</span>}
        </div>
      </div>
      <dl className="planner-task-meta">
        {task.worker && (
          <div>
            <dt>Worker</dt>
            <dd>{task.worker}</dd>
          </div>
        )}
        {task.dedupe_key && (
          <div>
            <dt>Dedupe</dt>
            <dd>{task.dedupe_key}</dd>
          </div>
        )}
      </dl>
      {visibleEvidence.length > 0 && (
        <div className="planner-evidence-row">
          {visibleEvidence.map((item) => (
            <code key={item}>{item}</code>
          ))}
        </div>
      )}
      {task.prompt && <p>{task.prompt}</p>}
    </article>
  );
}

function summaryMatchesTitle(summary: string, title: string | undefined) {
  const normalizedSummary = normalizeSummaryText(summary);
  if (!normalizedSummary) return true;
  const normalizedTitle = normalizeSummaryText(title || "");
  return normalizedTitle === normalizedSummary;
}

function codacySignal(summary: string, repository: string) {
  const match = /(?:^|\b)Codacy\s+issuesCount=(\d+)/i.exec(summary);
  if (!match) return null;
  return {
    count: Number.parseInt(match[1], 10),
    url: repository ? `https://app.codacy.com/gh/${repository}/issues/current` : null,
  };
}

function normalizeSummaryText(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/^[\w-]+:\s*/, "")
    .replace(/\s+/g, " ");
}

function shortDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function DiffBlock({ text }: { text: string }) {
  return <CodeBlock className="chat-diff" compact language="diff" text={text} title="Diff" />;
}

function ImageBlock({ path, taskId }: { path: string; taskId: string }) {
  const remote = /^https?:\/\//i.test(path);
  const src = remote
    ? path
    : path;
  return (
    <figure className="chat-image">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img alt={displayPath(path)} src={src} />
      <figcaption>
        <ImageIcon size={14} />
        <span>{displayPath(path)}</span>
      </figcaption>
    </figure>
  );
}

function splitTextBlocks(text: string): TextBlock[] {
  const blocks: TextBlock[] = [];
  const fence = /```([^\n]*)\n([\s\S]*?)```/g;
  let cursor = 0;
  for (const match of text.matchAll(fence)) {
    if (match.index > cursor) appendTextLike(blocks, text.slice(cursor, match.index));
    const language = match[1].trim().toLowerCase();
    const content = match[2].replace(/\n$/, "");
    blocks.push({
      kind: language.includes("diff") || looksLikeDiff(content) ? "diff" : "code",
      language,
      text: content,
    });
    cursor = match.index + match[0].length;
  }
  appendTextLike(blocks, text.slice(cursor));
  return blocks;
}

function appendTextLike(blocks: TextBlock[], text: string) {
  for (const paragraph of text.split(/\n{2,}/)) {
    const trimmed = paragraph.trim();
    if (!trimmed) continue;
    const markdownImage = trimmed.match(/^!\[[^\]]*]\(([^)]+)\)$/);
    if (markdownImage) {
      blocks.push({ kind: "image", text: markdownImage[1] });
      continue;
    }
    if (looksLikeDiff(trimmed)) blocks.push({ kind: "diff", text: trimmed });
    else if (isImageReference(trimmed)) blocks.push({ kind: "image", text: trimmed });
    else blocks.push({ kind: "text", text: trimmed });
  }
}

function metadataOnlyTranscript(text: string) {
  const metadataTypes = new Set([
    "thread.started",
    "turn.started",
    "turn.completed",
  ]);
  let sawLine = false;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    sawLine = true;
    const event = parseJson(line);
    if (!event?.type || !metadataTypes.has(event.type)) return false;
  }
  return sawLine;
}

function parseJson(line: string): { type?: string } | null {
  try {
    const value = JSON.parse(line) as unknown;
    return value && typeof value === "object" ? (value as { type?: string }) : null;
  } catch {
    return null;
  }
}

function parsePlannerDecision(text: string): PlannerDecision | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const consumedItems = Array.isArray(record.consumed_item_ids)
    ? record.consumed_item_ids
    : record.consumed_message_ids;
  if (!Array.isArray(consumedItems) || !Array.isArray(record.tasks)) return null;
  return {
    consumed_item_ids: consumedItems.filter((item): item is string => typeof item === "string"),
    tasks: record.tasks
      .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
      .map((item) => ({
        dedupe_key: stringValue(item.dedupe_key),
        evidence: Array.isArray(item.evidence) ? item.evidence.filter((entry): entry is string => typeof entry === "string") : [],
        kind: stringValue(item.kind),
        metadata: objectValue(item.metadata),
        priority: stringValue(item.priority),
        prompt: stringValue(item.prompt),
        risk: stringValue(item.risk),
        title: stringValue(item.title),
        worker: stringValue(item.worker),
      })),
  };
}

function parsePlannerInput(text: string): PlannerInput | null {
  const prefix = "Planning input JSON:";
  const trimmed = text.trimStart();
  if (!trimmed.startsWith(prefix)) return null;
  let value: unknown;
  try {
    value = JSON.parse(trimmed.slice(prefix.length).trim());
  } catch {
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  return {
    activeTasks: Array.isArray(record.active_tasks) ? record.active_tasks : [],
    inboxMessages: Array.isArray(record.signal_items)
      ? record.signal_items
          .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
          .map((item) => ({
            id: stringValue(item.id),
            kind: stringValue(item.kind),
            provider: stringValue(item.provider),
            status: stringValue(item.status),
            summary: stringValue(item.summary),
            title: stringValue(item.title),
            updated_at: stringValue(item.updated_at),
          }))
      : [],
    remoteIntegrationEnabled: Boolean(record.remote_integration_enabled),
    repository: stringValue(record.repository) || "",
  };
}

function stringValue(value: unknown) {
  return typeof value === "string" ? value : undefined;
}

function objectValue(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function looksLikeDiff(text: string) {
  return /^diff --git /m.test(text) || /^@@ /m.test(text) || /^--- .*\n\+\+\+ /m.test(text);
}

function isImageReference(text: string) {
  return /^(https?:\/\/\S+|[./~\w-][^\s]*)\.(png|jpe?g|gif|webp|svg)$/i.test(text);
}

function displayPath(path: string) {
  const home = "/home/minhu/";
  if (path.startsWith(home)) return `~/${path.slice(home.length)}`;
  return path;
}
