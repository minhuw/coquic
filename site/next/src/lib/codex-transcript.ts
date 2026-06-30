export type TranscriptRole = 'user' | 'assistant';

export interface TranscriptRecord {
  line: number;
  timestamp: string;
  type: string;
  role: string;
  payloadType: string;
  text: string;
  eventKind: string;
  toolName: string;
  toolCallId: string;
  textTruncated: boolean;
}

export type ConversationKind = 'message' | 'reasoning' | 'tool_call' | 'tool_result' | 'event';

export type TranscriptToolGroup = {
  type: 'tool';
  key: string;
  call?: TranscriptRecord;
  result?: TranscriptRecord;
};

export type TranscriptConversationItem =
  | {
      type: 'record';
      key: string;
      record: TranscriptRecord;
    }
  | TranscriptToolGroup;

type CodexTranscriptParseOptions = {
  maxParseLineBytes?: number;
  maxRecordTextLength?: number;
};

type CodexPayload = {
  action?: unknown;
  arguments?: unknown;
  call_id?: unknown;
  content?: unknown;
  id?: unknown;
  input?: unknown;
  message?: unknown;
  name?: unknown;
  output?: unknown;
  query?: unknown;
  role?: unknown;
  status?: unknown;
  summary?: unknown;
  text?: unknown;
  type?: unknown;
};

type CodexItem = {
  action?: { type?: unknown };
  aggregated_output?: unknown;
  arguments?: unknown;
  call_id?: unknown;
  changes?: unknown;
  command?: unknown;
  exit_code?: unknown;
  id?: unknown;
  input?: unknown;
  items?: unknown;
  message?: unknown;
  name?: unknown;
  output?: unknown;
  query?: unknown;
  result?: unknown;
  status?: unknown;
  text?: unknown;
  tool_name?: unknown;
  type?: unknown;
};

const defaultMaxParseLineBytes = 2 * 1024 * 1024;
const defaultMaxRecordTextLength = 60_000;

export function parseCodexTranscriptText(text: string, options: CodexTranscriptParseOptions = {}) {
  const records: TranscriptRecord[] = [];
  for (const [index, line] of text.split('\n').entries()) {
    records.push(...parseCodexTranscriptLine(line, index + 1, options));
  }
  return records;
}

export function parseCodexTranscriptLine(line: string, lineNumber: number, options: CodexTranscriptParseOptions = {}) {
  if (!line.trim()) return [];
  if (byteLength(line) > (options.maxParseLineBytes ?? defaultMaxParseLineBytes)) {
    const placeholder = largeLinePlaceholder(line, lineNumber);
    return placeholder ? [placeholder] : [];
  }

  try {
    const raw = JSON.parse(line) as unknown;
    return recordsFromCodexEvent(raw, lineNumber, options);
  } catch {
    return [];
  }
}

export function isConversationRecord(record: TranscriptRecord) {
  if (!record.text.trim()) return false;
  if (record.type === 'sample') return true;
  if (record.type === 'event_msg' && record.payloadType === 'agent_reasoning') return true;
  if (record.type !== 'response_item' && record.type !== 'item' && record.type !== 'event') return false;
  return [
    'agent_message',
    'agent_reasoning',
    'command_execution',
    'command_execution_output',
    'custom_tool_call',
    'custom_tool_call_output',
    'error',
    'file_change',
    'function_call',
    'function_call_output',
    'generic',
    'mcp_tool_call',
    'mcp_tool_call_output',
    'message',
    'reasoning',
    'tool_call',
    'tool_call_output',
    'todo_list',
    'web_search_call',
  ].includes(record.payloadType);
}

export function groupConversationRecords(records: TranscriptRecord[]): TranscriptConversationItem[] {
  const items: TranscriptConversationItem[] = [];
  const toolGroupsByCallId = new Map<string, TranscriptToolGroup>();

  for (const record of records) {
    const kind = conversationKind(record);
    if (kind !== 'tool_call' && kind !== 'tool_result') {
      items.push({ type: 'record', key: `record-${record.line}-${items.length}`, record });
      continue;
    }

    const callId = record.toolCallId.trim();
    if (!callId) {
      items.push({
        type: 'tool',
        key: `tool-${kind}-${record.line}-${items.length}`,
        call: kind === 'tool_call' ? record : undefined,
        result: kind === 'tool_result' ? record : undefined,
      });
      continue;
    }

    const existingGroup = toolGroupsByCallId.get(callId);
    if (existingGroup) {
      if (kind === 'tool_call') {
        existingGroup.call = record;
      } else {
        existingGroup.result = record;
      }
      continue;
    }

    const group: TranscriptToolGroup = {
      type: 'tool',
      key: `tool-${callId}-${record.line}`,
      call: kind === 'tool_call' ? record : undefined,
      result: kind === 'tool_result' ? record : undefined,
    };
    toolGroupsByCallId.set(callId, group);
    items.push(group);
  }

  return items;
}

export function conversationKind(record: TranscriptRecord): ConversationKind {
  if (record.payloadType === 'agent_reasoning' || record.payloadType === 'reasoning') return 'reasoning';
  if (
    record.payloadType === 'command_execution' ||
    record.payloadType === 'custom_tool_call' ||
    record.payloadType === 'file_change' ||
    record.payloadType === 'function_call' ||
    record.payloadType === 'mcp_tool_call' ||
    record.payloadType === 'tool_call' ||
    record.payloadType === 'todo_list' ||
    record.payloadType === 'web_search_call'
  ) {
    return 'tool_call';
  }
  if (
    record.payloadType === 'command_execution_output' ||
    record.payloadType === 'custom_tool_call_output' ||
    record.payloadType === 'function_call_output' ||
    record.payloadType === 'mcp_tool_call_output' ||
    record.payloadType === 'tool_call_output'
  ) {
    return 'tool_result';
  }
  if (record.type === 'event_msg' || record.type === 'event' || record.payloadType === 'error' || record.payloadType === 'generic') return 'event';
  return 'message';
}

export function normalizedRole(record: TranscriptRecord): TranscriptRole {
  if (
    record.role === 'assistant' ||
    record.payloadType === 'agent_message' ||
    record.payloadType === 'agent_reasoning' ||
    record.payloadType === 'command_execution' ||
    record.payloadType === 'command_execution_output' ||
    record.payloadType === 'custom_tool_call' ||
    record.payloadType === 'custom_tool_call_output' ||
    record.payloadType === 'file_change' ||
    record.payloadType === 'function_call' ||
    record.payloadType === 'function_call_output' ||
    record.payloadType === 'mcp_tool_call' ||
    record.payloadType === 'mcp_tool_call_output' ||
    record.payloadType === 'reasoning' ||
    record.payloadType === 'tool_call' ||
    record.payloadType === 'tool_call_output' ||
    record.payloadType === 'todo_list' ||
    record.payloadType === 'web_search_call'
  ) {
    return 'assistant';
  }
  return 'user';
}

export function toolDisplayName(record: TranscriptRecord) {
  if (record.toolName) return record.toolName;
  if (record.payloadType === 'command_execution' || record.payloadType === 'command_execution_output') return 'command';
  if (record.payloadType === 'web_search_call') return 'web_search';
  if (record.payloadType === 'file_change') return 'file_change';
  if (record.payloadType === 'todo_list') return 'todo_list';
  if (record.payloadType.includes('custom_tool')) return 'custom_tool';
  if (record.payloadType.includes('mcp_tool')) return 'mcp_tool';
  if (record.payloadType.includes('function_call')) return 'function_call';
  return record.toolCallId || record.payloadType || 'tool';
}

export function toolPayloadLabel(payloadType: string) {
  if (payloadType === 'command_execution' || payloadType === 'command_execution_output') return 'command';
  if (payloadType === 'web_search_call') return 'web search';
  if (payloadType === 'file_change') return 'file change';
  if (payloadType === 'custom_tool_call' || payloadType === 'custom_tool_call_output') return 'custom';
  if (payloadType === 'mcp_tool_call' || payloadType === 'mcp_tool_call_output') return 'mcp';
  if (payloadType === 'function_call' || payloadType === 'function_call_output') return 'function';
  if (payloadType === 'todo_list') return 'todo';
  return '';
}

function recordsFromCodexEvent(raw: unknown, lineNumber: number, options: CodexTranscriptParseOptions) {
  if (!raw || typeof raw !== 'object') return [];
  const event = raw as { item?: unknown; payload?: CodexPayload; timestamp?: unknown; type?: unknown };
  if (event.payload) return responsePayloadRecords(raw, lineNumber, options);
  if (event.item && typeof event.item === 'object') {
    return itemRecords(event.item as CodexItem, raw, lineNumber, options);
  }
  if (event.type === 'stderr') {
    return compactRecords([
      makeRecord({
        line: lineNumber,
        raw,
        payloadType: 'error',
        text: stringValue((raw as { text?: unknown; message?: unknown }).text ?? (raw as { message?: unknown }).message),
        type: 'event',
      }),
    ], options);
  }
  return [];
}

function responsePayloadRecords(raw: unknown, lineNumber: number, options: CodexTranscriptParseOptions) {
  const event = raw as { payload?: CodexPayload; timestamp?: unknown; type?: unknown };
  const payload = event.payload;
  const base = makeRecord({
    line: lineNumber,
    payloadType: stringValue(payload?.type),
    raw,
    role: stringValue(payload?.role),
    toolCallId: stringValue(payload?.call_id ?? payload?.id),
    toolName: stringValue(payload?.name),
    type: stringValue(event.type),
  });
  const text = extractPayloadText(raw);
  if (!text.trim()) return [];
  return compactRecords([{ ...base, text }], options);
}

function itemRecords(item: CodexItem, raw: unknown, lineNumber: number, options: CodexTranscriptParseOptions) {
  const itemType = stringValue(item.type);
  const itemId = stringValue(item.id) || `item-${lineNumber}`;
  const base = {
    line: lineNumber,
    raw,
    toolCallId: stringValue(item.call_id) || itemId,
    type: 'item',
  };

  if (itemType === 'agent_message') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'message',
        role: 'assistant',
        text: stringValue(item.text),
        toolCallId: '',
      }),
    ], options);
  }
  if (itemType === 'reasoning') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'reasoning',
        role: 'assistant',
        text: stringValue(item.text ?? item.message),
        toolCallId: '',
      }),
    ], options);
  }
  if (itemType === 'command_execution') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'command_execution',
        role: 'assistant',
        text: stringValue(item.command),
        toolName: 'command',
      }),
      makeRecord({
        ...base,
        payloadType: 'command_execution_output',
        role: 'assistant',
        text: stringValue(item.aggregated_output),
        toolName: 'command',
      }),
    ], options);
  }
  if (itemType === 'function_call' || itemType === 'tool_call' || itemType === 'mcp_tool_call') {
    const toolName = stringValue(item.name ?? item.tool_name) || itemType;
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: itemType,
        role: 'assistant',
        text: normalizeToolInput(item.arguments ?? item.input),
        toolName,
      }),
      makeRecord({
        ...base,
        payloadType: `${itemType}_output`,
        role: 'assistant',
        text: normalizeItemOutput(item.result ?? item.output),
        toolName,
      }),
    ], options);
  }
  if (itemType === 'file_change') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'file_change',
        role: 'assistant',
        text: JSON.stringify({ status: stringValue(item.status), changes: item.changes ?? [] }, null, 2),
        toolName: 'file_change',
      }),
    ], options);
  }
  if (itemType === 'todo_list') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'todo_list',
        role: 'assistant',
        text: JSON.stringify({ items: item.items ?? [] }, null, 2),
        toolName: 'todo_list',
      }),
    ], options);
  }
  if (itemType === 'web_search' || itemType === 'web_search_call') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'web_search_call',
        role: 'assistant',
        text: webSearchText(item.query, item.action),
        toolName: 'web_search',
      }),
    ], options);
  }
  if (itemType === 'error') {
    return compactRecords([
      makeRecord({
        ...base,
        payloadType: 'error',
        text: stringValue(item.message),
        toolCallId: '',
      }),
    ], options);
  }
  return compactRecords([
    makeRecord({
      ...base,
      payloadType: 'generic',
      text: JSON.stringify(item, null, 2),
      toolCallId: '',
    }),
  ], options);
}

function makeRecord({
  line,
  payloadType,
  raw,
  role = '',
  text = '',
  toolCallId = '',
  toolName = '',
  type,
}: {
  line: number;
  payloadType: string;
  raw: unknown;
  role?: string;
  text?: string;
  toolCallId?: string;
  toolName?: string;
  type: string;
}): TranscriptRecord {
  return {
    line,
    timestamp: stringValue(raw && typeof raw === 'object' ? (raw as { timestamp?: unknown }).timestamp : undefined),
    type,
    role,
    payloadType,
    text,
    eventKind: payloadType ? `${type}:${payloadType}` : type,
    toolName,
    toolCallId,
    textTruncated: false,
  };
}

function compactRecords(records: TranscriptRecord[], options: CodexTranscriptParseOptions) {
  return records
    .filter((record) => isConversationRecord(record) && record.text.trim())
    .map((record) => {
      const truncated = truncateText(record.text, options.maxRecordTextLength ?? defaultMaxRecordTextLength);
      return {
        ...record,
        text: truncated.text,
        textTruncated: truncated.truncated,
      };
    });
}

function largeLinePlaceholder(line: string, lineNumber: number): TranscriptRecord | null {
  if (!isLikelyConversationLine(line)) return null;
  const type = line.includes('"type":"event_msg"') ? 'event_msg' : line.includes('"item"') ? 'item' : 'response_item';
  const payloadType =
    [
      'agent_message',
      'agent_reasoning',
      'command_execution',
      'custom_tool_call',
      'custom_tool_call_output',
      'function_call',
      'function_call_output',
      'message',
      'reasoning',
      'tool_call',
      'web_search_call',
    ].find((candidate) => line.includes(`"type":"${candidate}"`)) ?? 'large_record';
  return {
    line: lineNumber,
    timestamp: stringValue(line.match(/"timestamp"\s*:\s*"([^"]+)"/)?.[1]),
    type,
    role: '',
    payloadType,
    text: 'This transcript event is too large for the browser preview. Download the JSONL member to inspect the full record.',
    eventKind: `${type}:${payloadType}`,
    toolName: stringValue(line.match(/"name"\s*:\s*"([^"]+)"/)?.[1]),
    toolCallId: stringValue(line.match(/"call_id"\s*:\s*"([^"]+)"/)?.[1] ?? line.match(/"id"\s*:\s*"([^"]+)"/)?.[1]),
    textTruncated: true,
  };
}

function isLikelyConversationLine(line: string) {
  return [
    '"item"',
    '"type":"response_item"',
    '"type":"event_msg"',
    '"type":"agent_message"',
    '"type":"command_execution"',
    '"type":"function_call"',
    '"type":"message"',
    '"type":"reasoning"',
    '"type":"tool_call"',
  ].some((needle) => line.includes(needle));
}

function extractPayloadText(raw: unknown) {
  const payload = raw && typeof raw === 'object' ? (raw as { payload?: CodexPayload }).payload : undefined;
  const content = payload?.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (!part || typeof part !== 'object') return '';
        return stringValue((part as { text?: unknown; message?: unknown; content?: unknown }).text ?? (part as { message?: unknown }).message ?? (part as { content?: unknown }).content);
      })
      .filter(Boolean)
      .join('\n\n');
  }
  const summary = payload?.summary;
  if (Array.isArray(summary)) {
    return summary
      .map((part) => {
        if (typeof part === 'string') return part;
        if (!part || typeof part !== 'object') return '';
        return stringValue((part as { text?: unknown }).text);
      })
      .filter(Boolean)
      .join('\n\n');
  }
  const output = normalizeToolOutput(payload?.output);
  if (output) return output;
  const input = normalizeToolInput(payload?.arguments ?? payload?.input);
  if (input) return input;
  const webQuery = webSearchText(payload?.query, payload?.action);
  if (webQuery) return webQuery;
  if (payload?.text) return stringValue(payload.text);
  return stringValue(payload?.message);
}

function normalizeToolInput(value: unknown) {
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  if (value && typeof value === 'object') return JSON.stringify(value, null, 2);
  return stringValue(value);
}

function normalizeToolOutput(value: unknown) {
  if (value && typeof value === 'object') return JSON.stringify(value, null, 2);
  if (typeof value !== 'string') return stringValue(value);
  if (!value.trim().startsWith('{')) return value;
  try {
    const parsed = JSON.parse(value) as { output?: unknown };
    return typeof parsed.output === 'string' ? parsed.output : value;
  } catch {
    return value;
  }
}

function webSearchText(query: unknown, action: unknown) {
  const directQuery = stringValue(query);
  if (directQuery) return directQuery;
  if (!action || typeof action !== 'object') return '';
  const actionQuery = stringValue((action as { query?: unknown }).query);
  if (actionQuery) return actionQuery;
  return normalizeToolInput(action);
}

function normalizeItemOutput(value: unknown) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return JSON.stringify(value, null, 2);
  return stringValue(value);
}

function truncateText(text: string, maxLength: number) {
  if (text.length <= maxLength) return { text, truncated: false };
  return {
    text: `${text.slice(0, maxLength).trimEnd()}\n\n[Preview truncated. Download the JSONL member to inspect the full record.]`,
    truncated: true,
  };
}

function byteLength(value: string) {
  return new TextEncoder().encode(value).length;
}

function stringValue(value: unknown) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}
