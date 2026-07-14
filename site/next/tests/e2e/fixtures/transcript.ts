import type {
  TranscriptManifest,
  TranscriptSearchResponse,
  TranscriptSession,
  TranscriptSessionDetail,
} from '../../../app/transcript/transcript-dataset';
import type { TranscriptRecord } from '../../../src/lib/codex-transcript';

export const transcriptManifest: TranscriptManifest = {
  generatedAt: '2026-06-30T12:00:00.000Z',
  archive: 'codex-history-coquic-transcripts-only-20260630.zip',
  archiveUrl: '/dataset/codex-history-coquic-transcripts-only-20260630.zip',
  archiveBytes: 2_048_000,
  transcriptCount: 28,
  totalBytes: 5_000_000,
  totalLines: 400,
  totalMessages: 240,
  totalUserMessages: 100,
  totalAssistantMessages: 140,
  totalToolCalls: 84,
  totalTokens: 125_400,
  dateRange: { start: '2026-05-01T08:00:00.000Z', end: '2026-06-30T12:00:00.000Z' },
  sources: [{ name: 'Codex CLI', href: 'https://github.com/openai/codex', note: 'Exported from public CoQUIC development sessions.' }],
};

export function transcriptSession(index = 1, overrides: Partial<TranscriptSession> = {}): TranscriptSession {
  const id = `public-session-${index}`;
  return {
    id,
    filename: `${id}.jsonl`,
    archiveMember: `transcripts/${id}.jsonl`,
    bytes: 4096 + index,
    compressedBytes: 2048 + index,
    modifiedAt: '2026-06-30T12:00:00.000Z',
    startedAt: `2026-06-${String(Math.max(1, 30 - index)).padStart(2, '0')}T10:00:00.000Z`,
    sessionId: `session-uuid-${index}`,
    cwd: `/worktree/with/a/long/path/${index}`,
    originator: 'codex_cli_rs',
    source: 'cli',
    cliVersion: '0.100.0',
    modelProvider: 'openai',
    model: 'gpt-5',
    lines: 120,
    messageCount: 20,
    userMessages: 8,
    assistantMessages: 12,
    developerMessages: 0,
    eventCount: 5,
    toolCalls: 6,
    compactedCount: 0,
    title: `Transcript session ${index} with a deliberately descriptive label`,
    preview: `Session ${index} preview with enough content to exercise wrapping without changing row geometry.`,
    samples: [],
    ...overrides,
  };
}

export const transcriptSessions = Array.from({ length: 25 }, (_, index) => transcriptSession(index + 1));

export function transcriptSearchResponse(overrides: Partial<TranscriptSearchResponse> = {}): TranscriptSearchResponse {
  return {
    manifest: transcriptManifest,
    query: '',
    from: '',
    to: '',
    page: 1,
    pageSize: 25,
    total: 28,
    totalPages: 2,
    sessions: transcriptSessions,
    ...overrides,
  };
}

export const transcriptRecords: TranscriptRecord[] = [
  {
    line: 1,
    timestamp: '2026-06-30T10:00:00.000Z',
    type: 'message',
    role: 'user',
    payloadType: 'message',
    text: 'Inspect the transcript route.',
    eventKind: 'message',
    toolName: '',
    toolCallId: '',
    textTruncated: false,
  },
  {
    line: 2,
    timestamp: '2026-06-30T10:00:01.000Z',
    type: 'message',
    role: 'assistant',
    payloadType: 'message',
    text: 'The first record page is ready.',
    eventKind: 'message',
    toolName: '',
    toolCallId: '',
    textTruncated: false,
  },
];

export function transcriptDetailResponse(overrides: Partial<TranscriptSessionDetail> = {}): TranscriptSessionDetail {
  return {
    sessionId: transcriptSessions[0].id,
    archiveMember: transcriptSessions[0].archiveMember,
    bytes: transcriptSessions[0].bytes,
    totalLines: 120,
    records: transcriptRecords,
    hasMore: true,
    nextCursor: 2,
    scannedLines: 2,
    scanLimited: false,
    limit: 80,
    ...overrides,
  };
}

export const transcriptEmptySearch = transcriptSearchResponse({
  manifest: { ...transcriptManifest, transcriptCount: 0, totalTokens: 0, totalToolCalls: 0, dateRange: undefined },
  total: 0,
  totalPages: 1,
  sessions: [],
});

export const transcriptMissingArchiveSearch = transcriptSearchResponse({
  manifest: { ...transcriptManifest, archiveBytes: 0, archiveUrl: '' },
});
