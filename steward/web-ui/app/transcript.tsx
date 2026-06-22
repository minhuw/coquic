"use client";

import { useId, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  ChevronRight,
  Code2,
  FilePenLine,
  Inbox,
  ImageIcon,
  ListChecks,
  MessageSquareText,
  ExternalLink,
  Send,
  Search,
  TerminalSquare,
  UserRound,
  Wrench,
  XCircle,
} from "lucide-react";
import type { CodexRunDiagnostics } from "./types";

type TranscriptItem =
  | SessionMarkerItem
  | AgentMessageItem
  | ReasoningItem
  | CommandItem
  | FileChangeItem
  | TodoListItem
  | WebSearchItem
  | ToolCallItem
  | ErrorItem
  | GenericItem;

type SessionMarkerItem = {
  id: string;
  kind: "session";
  label: string;
  value: string;
};

type AgentMessageItem = {
  id: string;
  kind: "agent";
  text: string;
};

type ReasoningItem = {
  id: string;
  kind: "reasoning";
  text: string;
};

type CommandItem = {
  id: string;
  kind: "command";
  command: string;
  output: string;
  status: string;
  exitCode: number | null;
};

type FileChangeItem = {
  id: string;
  kind: "file_change";
  status: string;
  changes: Array<{ path: string; kind: string }>;
};

type TodoListItem = {
  id: string;
  kind: "todo_list";
  items: Array<{ text: string; completed: boolean }>;
};

type WebSearchItem = {
  id: string;
  kind: "web_search";
  query: string;
  action: string;
};

type ToolCallItem = {
  id: string;
  kind: "tool_call";
  label: string;
  text: string;
  status: string;
};

type ErrorItem = {
  id: string;
  kind: "error";
  message: string;
};

type GenericItem = {
  id: string;
  kind: "generic";
  label: string;
  text: string;
};

type CodexEvent = {
  type?: string;
  thread_id?: string;
  text?: string;
  message?: string;
  item?: CodexItem;
};

type CodexItem = {
  id?: string;
  type?: string;
  text?: string;
  command?: string;
  aggregated_output?: string;
  status?: string;
  exit_code?: number | null;
  message?: string;
  query?: string;
  action?: { type?: string };
  name?: string;
  tool_name?: string;
  arguments?: unknown;
  result?: unknown;
  output?: string;
  changes?: Array<{ path?: string; kind?: string }>;
  items?: Array<{ text?: string; completed?: boolean }>;
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
  diagnostics?: CodexRunDiagnostics | null;
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
  const items = parseTranscript(text);
  if (!items.length) {
    return (
      <div className="chat-transcript" aria-label="Agent transcript">
        <SessionDiagnostics diagnostics={diagnostics} isLiveRun={isLiveRun} />
        {promptParts.boilerplate && <CollapsedPrompt text={promptParts.boilerplate} />}
        {promptParts.visible && (
          <ChatBubble hideLabel={isPlannerInputPrompt(promptParts.visible)} label="Task prompt" role="user">
            <TextBlocks taskId={taskId} text={promptParts.visible} />
          </ChatBubble>
        )}
        <ChatBubble label="Transcript text" role="assistant">
          <TextBlocks taskId={taskId} text={text} />
        </ChatBubble>
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
      {items.map((item, index) => (
        <TranscriptCard item={item} key={`${item.id}-${index}`} taskId={taskId} />
      ))}
    </div>
  );
}

function SessionDiagnostics({
  diagnostics,
  isLiveRun,
}: {
  diagnostics?: CodexRunDiagnostics | null;
  isLiveRun: boolean;
}) {
  if (!diagnostics || diagnostics.status === "ok") return null;
  const finalMessagePending = isLiveRun && diagnostics.status === "missing_last_message";
  const tail = diagnostics.last_item_type || diagnostics.last_event_type;
  return (
    <ToolCard
      icon={finalMessagePending ? <Activity size={16} /> : <XCircle size={16} />}
      meta={finalMessagePending ? "final message pending" : diagnostics.status.replaceAll("_", " ")}
      title={finalMessagePending ? "Session running" : "Session diagnostics"}
      tone={diagnostics.status === "missing_last_message" ? "pending" : "danger"}
    >
      <div className="session-diagnostics">
        <p>
          {finalMessagePending
            ? "Codex is still running. The final structured message will appear after the session exits."
            : diagnostics.summary || "Codex session did not finish cleanly."}
        </p>
        <dl>
          {diagnostics.exit_code !== null && <DiagFact label="Exit" value={String(diagnostics.exit_code)} />}
          <DiagFact label="Events" value={String(diagnostics.event_count)} />
          <DiagFact label="Errors" value={String(diagnostics.error_count)} />
          {tail && <DiagFact label="Last event" value={tail} />}
          <DiagFact
            label="Last message"
            value={diagnostics.last_message_present ? "written" : finalMessagePending ? "pending" : "missing"}
          />
          {diagnostics.thread_id && <DiagFact label="Thread" value={diagnostics.thread_id} />}
        </dl>
        {diagnostics.last_error && <pre>{diagnostics.last_error}</pre>}
        {!diagnostics.last_error && diagnostics.last_output && <pre>{diagnostics.last_output}</pre>}
      </div>
    </ToolCard>
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

function TranscriptCard({ item, taskId }: { item: TranscriptItem; taskId: string }) {
  if (item.kind === "session") return <TranscriptDivider label={item.label} value={item.value} />;
  if (item.kind === "agent") {
    return (
      <ChatBubble label="Assistant" role="assistant">
        <TextBlocks taskId={taskId} text={item.text} />
      </ChatBubble>
    );
  }
  if (item.kind === "reasoning") {
    return (
      <ToolCard
        icon={<Bot size={16} />}
        meta="reasoning"
        title="Reasoning"
        tone="neutral"
      >
        <TextBlocks taskId={taskId} text={item.text || "No reasoning text captured."} />
      </ToolCard>
    );
  }
  if (item.kind === "command") {
    const failed = item.status === "failed" || (item.exitCode ?? 0) !== 0;
    return (
      <ToolCard
        icon={<TerminalSquare size={16} />}
        meta={item.exitCode === null ? item.status : `exit ${item.exitCode} · ${item.status}`}
        title={shortCommand(item.command)}
        tone={failed ? "danger" : item.status === "in_progress" ? "pending" : "ok"}
      >
        <pre className="tool-command">{item.command}</pre>
        {item.output ? (
          <TextBlocks mode="tool" taskId={taskId} text={item.output} />
        ) : (
          <div className="tool-empty">No output.</div>
        )}
      </ToolCard>
    );
  }
  if (item.kind === "file_change") {
    return (
      <ToolCard icon={<FilePenLine size={16} />} meta={item.status} title="File change" tone="pending">
        {item.changes.length ? (
          <ul className="file-list">
            {item.changes.map((change, index) => (
              <li key={`${change.path}-${index}`}>
                <span>{change.kind}</span>
                <code>{displayPath(change.path)}</code>
              </li>
            ))}
          </ul>
        ) : (
          <div className="tool-empty">No file paths captured.</div>
        )}
      </ToolCard>
    );
  }
  if (item.kind === "todo_list") {
    return (
      <ToolCard icon={<ListChecks size={16} />} meta={`${item.items.length} items`} title="Task plan" tone="neutral">
        <ul className="todo-list">
          {item.items.map((todo, index) => (
            <li className={todo.completed ? "done" : ""} key={`${todo.text}-${index}`}>
              {todo.completed ? <CheckCircle2 size={15} /> : <span className="todo-dot" />}
              <span>{todo.text}</span>
            </li>
          ))}
        </ul>
      </ToolCard>
    );
  }
  if (item.kind === "web_search") {
    return (
      <ToolCard icon={<Search size={16} />} meta={item.action || "search"} title="Web search" tone="neutral">
        <code>{item.query || "(empty query)"}</code>
      </ToolCard>
    );
  }
  if (item.kind === "tool_call") {
    return (
      <ToolCard icon={<Wrench size={16} />} meta={item.status || "tool"} title={item.label} tone="neutral">
        <TextBlocks mode="tool" taskId={taskId} text={item.text || "No tool payload captured."} />
      </ToolCard>
    );
  }
  if (item.kind === "error") {
    return (
      <ToolCard icon={<XCircle size={16} />} meta="error" title="Runtime notice" tone="danger">
        <TextBlocks taskId={taskId} text={item.message} />
      </ToolCard>
    );
  }
  return (
    <ToolCard icon={<Code2 size={16} />} meta={item.label} title="Transcript event" tone="neutral">
      <TextBlocks taskId={taskId} text={item.text} />
    </ToolCard>
  );
}

function TranscriptDivider({ label, value }: { label: string; value: string }) {
  return (
    <div className="transcript-divider">
      <span>{label}</span>
      {value && <code>{value}</code>}
    </div>
  );
}

function ChatBubble({
  children,
  hideLabel = false,
  label,
  role,
}: {
  children: React.ReactNode;
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
  children: React.ReactNode;
  icon: React.ReactNode;
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
        if (block.kind === "code") return <pre className="chat-code" key={index}>{block.text}</pre>;
        if (mode === "tool") return <pre className="tool-output" key={index}>{block.text}</pre>;
        const plannerInput = parsePlannerInput(block.text);
        if (plannerInput) return <PlannerInputCard input={plannerInput} key={index} />;
        return <p className="chat-text" key={index}>{block.text}</p>;
      })}
    </>
  );
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
  return (
    <pre className="chat-diff">
      {text.split("\n").map((line, index) => (
        <span className={diffClass(line)} key={index}>{line}{"\n"}</span>
      ))}
    </pre>
  );
}

function ImageBlock({ path, taskId }: { path: string; taskId: string }) {
  const remote = /^https?:\/\//i.test(path);
  const src = remote
    ? path
    : `/api/tasks/${encodeURIComponent(taskId)}/assets?path=${encodeURIComponent(path)}`;
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

function parseTranscript(text: string): TranscriptItem[] {
  const items: TranscriptItem[] = [];
  const latestById = new Map<string, number>();
  let turn = 0;
  for (const [index, line] of text.split("\n").entries()) {
    if (!line.trim()) continue;
    const event = parseJson(line);
    if (event?.type === "thread.started") {
      const marker = {
        id: `thread-${index}`,
        kind: "session",
        label: "Worker session",
        value: event.thread_id || "",
      } satisfies SessionMarkerItem;
      items.push(marker);
      continue;
    }
    if (event?.type === "turn.started") {
      turn += 1;
      items.push({
        id: `turn-${index}`,
        kind: "session",
        label: `Turn ${turn}`,
        value: "",
      });
      continue;
    }
    const item = event?.item;
    const parsed = item ? parseItem(item, index) : parseTopLevel(event, line, index);
    if (!parsed) continue;
    const existing = latestById.get(parsed.id);
    if (existing === undefined) {
      latestById.set(parsed.id, items.length);
      items.push(parsed);
    } else {
      items[existing] = parsed;
    }
  }
  return trimSingleTurnDividers(items);
}

function trimSingleTurnDividers(items: TranscriptItem[]) {
  const sessionItems = items.filter((item) => item.kind === "session");
  const hasOnlyOneWorkerSession =
    sessionItems.filter((item) => item.label === "Worker session").length === 1;
  const hasOnlyOneTurn = sessionItems.filter((item) => item.label.startsWith("Turn ")).length === 1;
  if (sessionItems.length !== 2 || !hasOnlyOneWorkerSession || !hasOnlyOneTurn) return items;
  return items.filter((item) => item.kind !== "session");
}

function parseItem(item: CodexItem, index: number): TranscriptItem | null {
  const id = item.id || `item-${index}`;
  if (item.type === "agent_message") return { id, kind: "agent", text: item.text || "" };
  if (item.type === "reasoning") {
    return {
      id,
      kind: "reasoning",
      text: item.text || item.message || "",
    };
  }
  if (item.type === "command_execution") {
    return {
      id,
      kind: "command",
      command: item.command || "",
      output: item.aggregated_output || "",
      status: item.status || "unknown",
      exitCode: item.exit_code ?? null,
    };
  }
  if (item.type === "file_change") {
    return {
      id,
      kind: "file_change",
      status: item.status || "unknown",
      changes: (item.changes || []).map((change) => ({
        path: change.path || "",
        kind: change.kind || "change",
      })),
    };
  }
  if (item.type === "todo_list") {
    return {
      id,
      kind: "todo_list",
      items: (item.items || []).map((todo) => ({
        text: todo.text || "",
        completed: Boolean(todo.completed),
      })),
    };
  }
  if (item.type === "web_search") {
    return {
      id,
      kind: "web_search",
      query: item.query || "",
      action: item.action?.type || "",
    };
  }
  if (item.type === "mcp_tool_call" || item.type === "tool_call" || item.type === "function_call") {
    return {
      id,
      kind: "tool_call",
      label: item.name || item.tool_name || item.type,
      status: item.status || "completed",
      text: toolPayloadText(item),
    };
  }
  if (item.type === "error") return { id, kind: "error", message: item.message || "" };
  return {
    id,
    kind: "generic",
    label: item.type || "item",
    text: JSON.stringify(item, null, 2),
  };
}

function parseTopLevel(event: CodexEvent | null, raw: string, index: number): TranscriptItem | null {
  if (!event) return { id: `raw-${index}`, kind: "generic", label: "text", text: raw };
  if (event.type === "stderr") {
    return { id: `stderr-${index}`, kind: "error", message: event.text || event.message || raw };
  }
  if (event.type === "thread.started" || event.type === "turn.started" || event.type === "turn.completed") return null;
  return {
    id: `event-${index}`,
    kind: "generic",
    label: event.type || "event",
    text: event.message || event.text || JSON.stringify(event, null, 2),
  };
}

function splitTextBlocks(text: string): Array<{ kind: "code" | "diff" | "image" | "text"; text: string }> {
  const blocks: Array<{ kind: "code" | "diff" | "image" | "text"; text: string }> = [];
  const fence = /```([^\n]*)\n([\s\S]*?)```/g;
  let cursor = 0;
  for (const match of text.matchAll(fence)) {
    if (match.index > cursor) appendTextLike(blocks, text.slice(cursor, match.index));
    const language = match[1].trim().toLowerCase();
    const content = match[2].replace(/\n$/, "");
    blocks.push({ kind: language.includes("diff") || looksLikeDiff(content) ? "diff" : "code", text: content });
    cursor = match.index + match[0].length;
  }
  appendTextLike(blocks, text.slice(cursor));
  return blocks;
}

function appendTextLike(
  blocks: Array<{ kind: "code" | "diff" | "image" | "text"; text: string }>,
  text: string,
) {
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

function parseJson(line: string): CodexEvent | null {
  try {
    const value = JSON.parse(line) as unknown;
    return value && typeof value === "object" ? (value as CodexEvent) : null;
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
    inboxMessages: Array.isArray(record.inbox_messages)
      ? record.inbox_messages
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

function diffClass(line: string) {
  let className = "diff-line";
  if (line.startsWith("+") && !line.startsWith("+++")) className += " added";
  if (line.startsWith("-") && !line.startsWith("---")) className += " removed";
  if (line.startsWith("@@")) className += " hunk";
  return className;
}

function shortCommand(command: string) {
  if (!command) return "Command";
  return command.length > 110 ? `${command.slice(0, 107)}...` : command;
}

function displayPath(path: string) {
  const home = "/home/minhu/";
  if (path.startsWith(home)) return `~/${path.slice(home.length)}`;
  return path;
}

function toolPayloadText(item: CodexItem) {
  const payload = {
    arguments: item.arguments,
    result: item.result,
    output: item.output,
    text: item.text,
    message: item.message,
  };
  const compact = Object.fromEntries(
    Object.entries(payload).filter(([, value]) => value !== undefined && value !== ""),
  );
  return Object.keys(compact).length ? JSON.stringify(compact, null, 2) : "";
}
