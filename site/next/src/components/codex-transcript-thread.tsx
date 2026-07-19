'use client';

import { Bot, CheckCircle2, Code2, FilePenLine, ListChecks, MessageSquareText, Search, Sparkles, TerminalSquare, UserRound, Wrench, XCircle } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { cn } from '@/lib/utils';
import {
  conversationKind,
  groupConversationRecords,
  normalizedRole,
  toolDisplayName,
  toolPayloadLabel,
  type ConversationKind,
  type TranscriptConversationItem,
  type TranscriptRecord,
  type TranscriptRole,
  type TranscriptToolGroup,
} from '@/lib/codex-transcript';
import { EvidenceDisclosure } from './evidence/disclosure';
import { EvidenceMessage } from './evidence/message';
import type { EvidenceTone } from './evidence/message';
import { CodeBlock } from './evidence/code-block';
import styles from './codex-transcript-thread.module.css';

export function CodexTranscriptThread({
  empty,
  records,
}: {
  empty?: string;
  records: TranscriptRecord[];
}) {
  const conversationRecords = records.filter(isRenderableRecord);
  const conversationItems = groupConversationRecords(conversationRecords);
  if (!conversationItems.length) {
    return <div className={styles.root} data-transcript-thread="true"><div className={styles.empty}>{empty ?? 'No displayable transcript records.'}</div></div>;
  }
  return (
    <div className={styles.root} data-transcript-thread="true">
      {conversationItems.map((item) => (
        <TranscriptItem key={item.key} item={item} />
      ))}
    </div>
  );
}

export function transcriptDisplayCount(records: TranscriptRecord[]) {
  return groupConversationRecords(records.filter(isRenderableRecord)).length;
}

function TranscriptItem({ item }: { item: TranscriptConversationItem }) {
  if (item.type === 'tool') return <TranscriptToolCard group={item} />;
  return <TranscriptMessage record={item.record} />;
}

function TranscriptMessage({ record }: { record: TranscriptRecord }) {
  const role = normalizedRole(record);
  const kind = conversationKind(record);
  if (kind === 'reasoning') {
    return (
      <EvidenceDisclosure icon={<Sparkles size={16} />} metadata={lineMeta(record)} label="Reasoning" tone="neutral">
        <MarkdownText text={record.text} />
        {record.textTruncated ? <TranscriptNote /> : null}
      </EvidenceDisclosure>
    );
  }
  if (kind === 'event') {
    return (
      <EvidenceDisclosure icon={<XCircle size={16} />} metadata={lineMeta(record)} label={messageLabel(role, kind, record)} tone={record.payloadType === 'error' ? 'danger' : 'neutral'}>
        <MarkdownText text={record.text} />
        {record.textTruncated ? <TranscriptNote /> : null}
      </EvidenceDisclosure>
    );
  }
  return (
    <EvidenceMessage icon={role === 'user' ? <UserRound size={16} /> : <MessageSquareText size={16} />} label={messageLabel(role, kind, record)} role={role}>
      <MarkdownText text={record.text} />
      {record.textTruncated ? <TranscriptNote /> : null}
    </EvidenceMessage>
  );
}

function TranscriptToolCard({ group }: { group: TranscriptToolGroup }) {
  const primaryRecord = group.call ?? group.result;
  if (!primaryRecord) return null;
  if (primaryRecord.payloadType === 'file_change') return <FileChangeCard record={primaryRecord} />;
  if (primaryRecord.payloadType === 'todo_list') return <TodoListCard record={primaryRecord} />;
  if (primaryRecord.payloadType === 'web_search_call') return <WebSearchCard record={primaryRecord} />;
  const toolName = toolDisplayName(primaryRecord);
  const payloadLabel = toolPayloadLabel(primaryRecord.payloadType);
  const meta = [toolGroupState(group), payloadLabel, toolLineLabel(group)].filter(Boolean).join(' / ');
  return (
    <EvidenceDisclosure icon={toolIcon(primaryRecord)} metadata={meta} label={toolName} tone={toolTone(group)}>
      <div className={styles.toolSections}>
        {group.call ? <ToolSection format={toolCallFormat(group.call)} label="Call" record={group.call} /> : null}
        {group.result ? (
          <ToolSection format="markdown" label="Result" record={group.result} />
        ) : (
          <div className={styles.emptyTool}>Result is not loaded in the current preview page.</div>
        )}
      </div>
      {group.call?.textTruncated || group.result?.textTruncated ? <TranscriptNote /> : null}
    </EvidenceDisclosure>
  );
}

function FileChangeCard({ record }: { record: TranscriptRecord }) {
  const parsed = parseJsonRecord(record.text) as { changes?: Array<{ kind?: string; path?: string }>; status?: string } | null;
  const changes = Array.isArray(parsed?.changes) ? parsed.changes : [];
  return (
    <EvidenceDisclosure icon={<FilePenLine size={16} />} metadata={parsed?.status || lineMeta(record)} label="File change" tone="warning">
      {changes.length ? (
        <ul className={styles.fileList}>
          {changes.map((change, index) => (
            <li key={`${change.path || 'file'}-${index}`}>
              <span>{change.kind || 'change'}</span>
              <code>{change.path || '(unknown path)'}</code>
            </li>
          ))}
        </ul>
      ) : (
        <MarkdownText text={record.text} />
      )}
      {record.textTruncated ? <TranscriptNote /> : null}
    </EvidenceDisclosure>
  );
}

function TodoListCard({ record }: { record: TranscriptRecord }) {
  const parsed = parseJsonRecord(record.text) as { items?: Array<{ completed?: boolean; text?: string }> } | null;
  const items = Array.isArray(parsed?.items) ? parsed.items : [];
  return (
    <EvidenceDisclosure icon={<ListChecks size={16} />} metadata={`${items.length} items`} label="Task plan" tone="neutral">
      {items.length ? (
        <ul className={styles.todoList}>
          {items.map((todo, index) => (
            <li className={cn(todo.completed && styles.done)} key={`${todo.text || 'todo'}-${index}`}>
              {todo.completed ? <CheckCircle2 size={15} /> : <span className={styles.todoDot} />}
              <span>{todo.text || '(empty item)'}</span>
            </li>
          ))}
        </ul>
      ) : (
        <MarkdownText text={record.text} />
      )}
      {record.textTruncated ? <TranscriptNote /> : null}
    </EvidenceDisclosure>
  );
}

function WebSearchCard({ record }: { record: TranscriptRecord }) {
  return (
    <EvidenceDisclosure icon={<Search size={16} />} metadata={lineMeta(record)} label="Web search" tone="neutral">
      <code className={styles.inlineCode}>{record.text || '(empty query)'}</code>
      {record.textTruncated ? <TranscriptNote /> : null}
    </EvidenceDisclosure>
  );
}

function ToolSection({ format, label, record }: { format: 'bash' | 'json' | 'markdown' | 'text'; label: string; record: TranscriptRecord }) {
  if (format === 'markdown') {
    return (
      <section className={styles.section}>
        <div className={styles.sectionHead}>
          <span>{label}</span>
          <code>line {formatInteger(record.line)}</code>
        </div>
        <div className={styles.toolMarkdown}>
          <MarkdownText text={record.text} />
        </div>
      </section>
    );
  }
  return (
    <section className={styles.section}>
      <CodeBlock
        compact
        language={format === 'text' ? undefined : format}
        showLineNumbers={false}
        text={record.text}
        title={`${label} / line ${formatInteger(record.line)}`}
      />
    </section>
  );
}

function MarkdownText({ text }: { text: string }) {
  return (
    <div className={styles.markdown}>
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  );
}

function TranscriptNote() {
  return <small className={styles.note}>Preview truncated. Download the JSONL member for the full record.</small>;
}

function isRenderableRecord(record: TranscriptRecord) {
  return Boolean(record.text.trim());
}

function messageLabel(role: TranscriptRole, kind: ConversationKind, record: TranscriptRecord) {
  if (kind === 'reasoning') return 'Reasoning';
  if (kind === 'event') return record.payloadType === 'error' ? 'Runtime notice' : 'Transcript event';
  return role === 'assistant' ? 'Assistant' : 'User';
}

function lineMeta(record: TranscriptRecord) {
  return record.timestamp ? `line ${formatInteger(record.line)} / ${formatDateTime(record.timestamp)}` : `line ${formatInteger(record.line)}`;
}

function toolLineLabel(group: TranscriptToolGroup) {
  const callLine = group.call?.line;
  const resultLine = group.result?.line;
  const timestamp = group.call?.timestamp || group.result?.timestamp;
  const range = callLine && resultLine && callLine !== resultLine ? `lines ${formatInteger(callLine)}-${formatInteger(resultLine)}` : `line ${formatInteger(callLine ?? resultLine ?? 0)}`;
  return `${range}${timestamp ? ` / ${formatDateTime(timestamp)}` : ''}`;
}

function toolGroupState(group: TranscriptToolGroup) {
  if (group.call && group.result) return 'call + result';
  if (group.call) return 'call only';
  return 'result only';
}

function toolTone(group: TranscriptToolGroup): EvidenceTone {
  if (group.result?.payloadType === 'error' || group.call?.payloadType === 'error') return 'danger';
  if (!group.result) return 'warning';
  return 'success';
}

function toolIcon(record: TranscriptRecord) {
  if (record.payloadType.includes('command')) return <TerminalSquare size={16} />;
  if (record.payloadType.includes('function') || record.payloadType.includes('tool')) return <Wrench size={16} />;
  if (record.payloadType === 'web_search_call') return <Bot size={16} />;
  return <Code2 size={16} />;
}

function parseJsonRecord(text: string) {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function toolCallFormat(record: TranscriptRecord): 'bash' | 'json' | 'text' {
  if (record.payloadType === 'command_execution') return 'bash';
  if (record.text.trim().startsWith('{') || record.text.trim().startsWith('[')) return 'json';
  return 'text';
}

function formatInteger(value: number) {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatDateTime(value: string) {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  }).format(date);
}
