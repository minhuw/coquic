import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const nextRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(nextRoot, '..', '..');
const archiveName = 'codex-history-coquic-transcripts-only-20260630.zip';
const archivePath = path.join(repoRoot, archiveName);
const publicDatasetDir = path.join(nextRoot, 'public', 'dataset');
const publicArchivePath = path.join(publicDatasetDir, archiveName);
const generatedTranscriptsDir = path.join(nextRoot, '.generated', 'transcripts');
const manifestPath = path.join(generatedTranscriptsDir, 'manifest.json');
const sqlitePath = path.join(generatedTranscriptsDir, 'transcripts.sqlite');

if (!existsSync(archivePath)) {
  rmSync(publicDatasetDir, { recursive: true, force: true });
  rmSync(generatedTranscriptsDir, { recursive: true, force: true });
  console.warn(`transcript dataset archive not found: ${archivePath}`);
  process.exit(0);
}

rmSync(publicDatasetDir, { recursive: true, force: true });
mkdirSync(publicDatasetDir, { recursive: true });
mkdirSync(generatedTranscriptsDir, { recursive: true });
copyFileSync(archivePath, publicArchivePath);
chmodSync(publicArchivePath, 0o644);

const entries = await listZipEntries(archivePath);
const sessions = [];

for (const entry of entries) {
  if (!entry.name.endsWith('.jsonl')) continue;
  sessions.push(await summarizeEntry(entry));
}

sessions.sort((a, b) => b.startedAt.localeCompare(a.startedAt) || b.bytes - a.bytes);

const manifest = {
  generatedAt: new Date().toISOString(),
  archive: archiveName,
  archiveUrl: `/dataset/${archiveName}`,
  archiveBytes: statSync(archivePath).size,
  transcriptCount: sessions.length,
  totalBytes: sessions.reduce((total, session) => total + session.bytes, 0),
  totalLines: sessions.reduce((total, session) => total + session.lines, 0),
  totalMessages: sessions.reduce((total, session) => total + session.messageCount, 0),
  totalUserMessages: sessions.reduce((total, session) => total + session.userMessages, 0),
  totalAssistantMessages: sessions.reduce((total, session) => total + session.assistantMessages, 0),
  totalToolCalls: sessions.reduce((total, session) => total + session.toolCalls, 0),
  totalTokens: sessions.reduce((total, session) => total + session.totalTokens, 0),
  dateRange: {
    start: sessions.reduce((start, session) => (start && start < session.startedAt ? start : session.startedAt), ''),
    end: sessions.reduce((end, session) => (end && end > session.startedAt ? end : session.startedAt), ''),
  },
  sources: [
    {
      name: 'ChatScope React Chat UI Kit',
      href: 'https://github.com/chatscope/chat-ui-kit-react',
      note: 'General React message-list components researched as a design reference.',
    },
    {
      name: 'React Chat Elements',
      href: 'https://www.npmjs.com/package/react-chat-elements',
      note: 'General React chat components researched as a design reference.',
    },
    {
      name: 'Stream Chat React',
      href: 'https://getstream.io/chat/docs/sdk/react/',
      note: 'SDK-oriented chat UI researched as a design reference.',
    },
  ],
  sessions,
};

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
chmodSync(manifestPath, 0o644);
await buildSqliteDatabase(sqlitePath, manifest);
chmodSync(sqlitePath, 0o644);

async function summarizeEntry(entry) {
  const summary = {
    id: entry.id,
    filename: entry.name,
    slug: entry.name.replace(/\.jsonl$/, ''),
    bytes: entry.bytes,
    compressedBytes: entry.compressedBytes,
    modifiedAt: entry.modifiedAt,
    host: entry.host,
    startedAt: entry.startedAt,
    sessionId: entry.id,
    cwd: '',
    originator: '',
    source: '',
    cliVersion: '',
    modelProvider: '',
    model: '',
    lines: 0,
    messageCount: 0,
    userMessages: 0,
    assistantMessages: 0,
    developerMessages: 0,
    eventCount: 0,
    toolCalls: 0,
    compactedCount: 0,
    totalTokens: 0,
    title: '',
    preview: '',
    archiveMember: entry.name,
    samples: [],
  };
  const fallbackSamples = [];
  let fallbackUserMessages = 0;
  let fallbackAssistantMessages = 0;
  let estimatedTokens = 0;
  let hasObservedTokenUsage = false;

  await streamZipEntry(archivePath, entry.name, async (line) => {
    if (!line.trim()) return;
    summary.lines += 1;
    estimatedTokens += estimateTokens(line);

    let record;
    try {
      record = JSON.parse(line);
    } catch {
      return;
    }

    if (record.type === 'session_meta') {
      applySessionMeta(summary, record.payload);
      return;
    }

    if (record.type === 'event_msg') {
      summary.eventCount += 1;
      const eventType = record.payload?.type;
      if (eventType === 'token_count') {
        const tokens = totalTokensIncludingCachedInput(record.payload?.info?.total_token_usage);
        if (tokens > 0) {
          hasObservedTokenUsage = true;
          summary.totalTokens = Math.max(summary.totalTokens, tokens);
        }
      }
      if (eventType === 'user_message' || eventType === 'agent_message') {
        const role = eventType === 'agent_message' ? 'assistant' : 'user';
        const text = normalizeText(record.payload?.message);
        const displayText = displayMessageText(text);
        if (text) {
          if (role === 'user') fallbackUserMessages += 1;
          if (role === 'assistant') fallbackAssistantMessages += 1;
          if (displayText && fallbackSamples.length < 7) {
            fallbackSamples.push({
              role,
              timestamp: normalizeTimestamp(record.timestamp) || summary.startedAt,
              phase: record.payload?.phase || '',
              text: truncate(displayText, 900),
            });
          }
          if (!summary.title && role === 'user') summary.title = deriveTitle(text);
          if (!summary.preview && role === 'user' && displayText) summary.preview = truncate(displayText, 220);
        }
      }
      return;
    }

    if (record.type === 'compacted') {
      summary.compactedCount += 1;
      return;
    }

    if (record.type !== 'response_item') return;
    const payload = record.payload ?? {};
    if (payload.type === 'function_call') {
      summary.toolCalls += 1;
      return;
    }
    if (payload.type !== 'message') return;

    const role = payload.role ?? 'unknown';
    if (role === 'developer') {
      summary.developerMessages += 1;
      return;
    }
    if (role !== 'user' && role !== 'assistant') return;

    addMessage(summary, role, extractText(payload.content), record.timestamp, payload.phase);
  });

  if (!hasObservedTokenUsage) {
    summary.totalTokens = estimatedTokens;
  }
  if (summary.samples.length === 0 && fallbackSamples.length > 0) {
    summary.samples = fallbackSamples;
    summary.userMessages = fallbackUserMessages;
    summary.assistantMessages = fallbackAssistantMessages;
  }
  summary.messageCount = summary.userMessages + summary.assistantMessages;
  if (!summary.title) {
    summary.title = titleFromFilename(summary.filename);
  }
  if (!summary.preview) {
    summary.preview = 'Session metadata only.';
  }

  return summary;
}

function applySessionMeta(summary, payload = {}) {
  summary.sessionId = metadataText(payload.id || payload.session_id || summary.sessionId);
  summary.cwd = metadataText(payload.cwd);
  summary.originator = metadataText(payload.originator);
  summary.source = metadataText(payload.source);
  summary.cliVersion = metadataText(payload.cli_version);
  summary.modelProvider = metadataText(payload.model_provider);
  summary.model = metadataText(payload.model || summary.model);
  summary.startedAt = normalizeTimestamp(payload.timestamp) || summary.startedAt;
}

function addMessage(summary, role, rawText, timestamp, phase) {
  const text = normalizeText(rawText);
  if (!text) return;
  const displayText = displayMessageText(text);

  if (role === 'user') {
    summary.userMessages += 1;
    const title = deriveTitle(text);
    if (!summary.title && title) summary.title = title;
    if (!summary.preview && isDisplayableMessage(displayText)) summary.preview = truncate(displayText, 220);
  } else if (role === 'assistant') {
    summary.assistantMessages += 1;
  }

  summary.messageCount += 1;
  if (!isDisplayableMessage(displayText)) return;
  if (summary.samples.length >= 7) return;
  summary.samples.push({
    role,
    timestamp: normalizeTimestamp(timestamp) || summary.startedAt,
    phase: phase || '',
    text: truncate(displayText, 900),
  });
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .map((part) => {
      if (!part || typeof part !== 'object') return '';
      return part.text || part.message || part.content || '';
    })
    .filter(Boolean)
    .join('\n\n');
}

function stripPromptEnvelope(text) {
  let output = text.trim();
  if (output.startsWith('# AGENTS.md instructions')) {
    output = output.replace(/^# AGENTS\.md instructions for [\s\S]*?<\/INSTRUCTIONS>\s*/m, '').trim();
  }
  return output
    .replace(/^<environment_context>[\s\S]*?<\/environment_context>\s*/m, '')
    .replace(/^<permissions instructions>[\s\S]*?<\/permissions instructions>\s*/m, '')
    .trim();
}

function displayMessageText(text) {
  const stripped = stripPromptEnvelope(text);
  if (!isDisplayableMessage(stripped)) return '';

  const taskPrompt = stripped.match(/^Task prompt:\s*\n+([\s\S]+)/m)?.[1] ?? '';
  if (taskPrompt) return taskPrompt.trim();

  const taskLine = stripped.match(/^Task:\s*(.+)$/m)?.[1]?.trim();
  if (taskLine) return taskLine;

  if (stripped.startsWith('You are running under CoQUIC Steward.')) return '';

  return stripped;
}

function deriveTitle(text) {
  const stripped = stripPromptEnvelope(text);
  if (!isDisplayableMessage(stripped)) return '';

  const taskLine = stripped.match(/^Task:\s*(.+)$/m)?.[1]?.trim();
  if (taskLine) return truncate(taskLine, 92);

  const taskPrompt = stripped.match(/^Task prompt:\s*\n+([\s\S]+)/m)?.[1] ?? '';
  const taskPromptLine = firstUsefulLine(taskPrompt);
  if (taskPromptLine) return truncate(taskPromptLine, 92);

  return truncate(firstUsefulLine(stripped) || stripped, 92);
}

function firstUsefulLine(text) {
  return (
    text
    .split('\n')
    .map((line) => line.trim())
    .find((line) => {
      if (!line || line.startsWith('<') || line.startsWith('#')) return false;
      if (line.endsWith(':') && line.length < 44) return false;
      return ![
        'You are CoQUIC Steward',
        'You are running under CoQUIC Steward.',
        'Your job is',
        'Review active_tasks',
        'Create only necessary tasks',
        'Every task must',
        'When remote integration',
        'The worker receives only',
        'Worker:',
        'Task ID:',
        'Required worktree:',
        'GitHub repository:',
        'Enabled signals:',
        'Worker purpose:',
      ].some((prefix) => line.startsWith(prefix));
    }) || ''
  );
}

function isDisplayableMessage(text) {
  if (!text) return false;
  return ![
    'Last updated:',
    'These repository instructions apply',
    'Act as a pragmatic coding agent',
    'You are CoQUIC Steward',
    "You are CoQUIC Steward's planning brain.",
    'Preserve unrelated user work.',
    '<environment_context>',
    '<permissions instructions>',
  ].some((prefix) => text.startsWith(prefix));
}

function titleFromFilename(filename) {
  const match = filename.match(/^session__(.+?)__(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})__/);
  if (!match) return filename.replace(/\.jsonl$/, '');
  const [, host, day, hour, minute] = match;
  return `${host} session, ${day} ${hour}:${minute} UTC`;
}

function normalizeText(value) {
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/[ \f\v]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function metadataText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function truncate(text, maxLength) {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

function estimateTokens(text) {
  if (!text) return 0;
  return Math.max(1, Math.ceil(text.length / 4));
}

function totalTokensIncludingCachedInput(usage) {
  if (!usage || typeof usage !== 'object') return 0;
  const totalTokens = numericUsageValue(usage.total_tokens);
  const inputTokens = numericUsageValue(usage.input_tokens);
  const outputTokens = numericUsageValue(usage.output_tokens);
  const cachedInputTokens = numericUsageValue(usage.cached_input_tokens);
  const baseTokens = totalTokens || inputTokens + outputTokens;
  return baseTokens + cachedInputTokens;
}

function numericUsageValue(value) {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

function normalizeTimestamp(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString();
}

async function buildSqliteDatabase(databasePath, manifest) {
  rmSync(databasePath, { force: true });
  const sqlite = await import('node:sqlite');
  const db = new sqlite.DatabaseSync(databasePath);

  try {
    db.exec(`
      PRAGMA journal_mode = OFF;
      PRAGMA synchronous = OFF;
      PRAGMA temp_store = MEMORY;

      CREATE TABLE metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        archive_member TEXT NOT NULL,
        bytes INTEGER NOT NULL,
        compressed_bytes INTEGER NOT NULL,
        modified_at TEXT NOT NULL,
        host TEXT NOT NULL,
        started_at TEXT NOT NULL,
        session_id TEXT NOT NULL,
        cwd TEXT NOT NULL,
        originator TEXT NOT NULL,
        source TEXT NOT NULL,
        cli_version TEXT NOT NULL,
        model_provider TEXT NOT NULL,
        model TEXT NOT NULL,
        lines INTEGER NOT NULL,
        message_count INTEGER NOT NULL,
        user_messages INTEGER NOT NULL,
        assistant_messages INTEGER NOT NULL,
        developer_messages INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        tool_calls INTEGER NOT NULL,
        compacted_count INTEGER NOT NULL,
        total_tokens INTEGER NOT NULL,
        title TEXT NOT NULL,
        preview TEXT NOT NULL,
        samples_json TEXT NOT NULL
      );

      CREATE INDEX sessions_started_at_idx ON sessions(started_at DESC);
      CREATE INDEX sessions_host_idx ON sessions(host);
      CREATE INDEX sessions_title_idx ON sessions(title);
      CREATE INDEX sessions_session_id_idx ON sessions(session_id);
    `);

    const insertMetadata = db.prepare('INSERT INTO metadata (key, value) VALUES (?, ?)');
    const insertSession = db.prepare(`
      INSERT INTO sessions (
        id,
        filename,
        archive_member,
        bytes,
        compressed_bytes,
        modified_at,
        host,
        started_at,
        session_id,
        cwd,
        originator,
        source,
        cli_version,
        model_provider,
        model,
        lines,
        message_count,
        user_messages,
        assistant_messages,
        developer_messages,
        event_count,
        tool_calls,
        compacted_count,
        total_tokens,
        title,
        preview,
        samples_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    db.exec('BEGIN');
    insertMetadata.run('manifest', JSON.stringify({ ...manifest, sessions: undefined }));
    insertMetadata.run('generatedAt', manifest.generatedAt);
    insertMetadata.run('archive', manifest.archive);
    insertMetadata.run('archiveUrl', manifest.archiveUrl);
    for (const session of manifest.sessions) {
      insertSession.run(
        session.id,
        session.filename,
        session.archiveMember,
        session.bytes,
        session.compressedBytes,
        session.modifiedAt,
        session.host,
        session.startedAt,
        session.sessionId,
        session.cwd,
        session.originator,
        session.source,
        session.cliVersion,
        session.modelProvider,
        session.model,
        session.lines,
        session.messageCount,
        session.userMessages,
        session.assistantMessages,
        session.developerMessages,
        session.eventCount,
        session.toolCalls,
        session.compactedCount,
        session.totalTokens,
        session.title,
        session.preview,
        JSON.stringify(session.samples),
      );

    }
    db.exec('COMMIT');
    db.exec('PRAGMA optimize');
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // The failing statement may have happened outside the transaction.
    }
    throw error;
  } finally {
    db.close();
  }
}

async function listZipEntries(zipPath) {
  const output = await run('unzip', ['-Z', '-1', zipPath]);
  const names = output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const rows = await run('unzip', ['-v', zipPath]);
  const details = new Map();

  for (const row of rows.split('\n')) {
    const match = row.match(/^\s*(\d+)\s+\S+\s+\d+\s+(\d+)%\s+(\d+)-(\d+)-(\d+)\s+(\d+):(\d+)\s+\S+\s+(.+\.jsonl)$/);
    if (!match) continue;
    const [, bytes, compression, year, month, day, hour, minute, name] = match;
    const compressedBytes = Math.max(0, Math.round(Number(bytes) * (1 - Number(compression) / 100)));
    details.set(name, {
      bytes: Number(bytes),
      compressedBytes,
      modifiedAt: `${year}-${month}-${day}T${hour}:${minute}:00.000Z`,
    });
  }

  return names.map((name) => {
    const parsed = parseSessionName(name);
    const detail = details.get(name) ?? {};
    return {
      name,
      id: parsed.id,
      host: parsed.host,
      startedAt: parsed.startedAt,
      bytes: detail.bytes ?? 0,
      compressedBytes: detail.compressedBytes ?? 0,
      modifiedAt: detail.modifiedAt ?? parsed.startedAt,
    };
  });
}

function parseSessionName(name) {
  const match = name.match(/^session__(.+?)__(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})__(.+)\.jsonl$/);
  if (!match) {
    return { id: name.replace(/\.jsonl$/, ''), host: 'unknown', startedAt: '' };
  }
  const [, host, date, hour, minute, second, id] = match;
  return {
    id,
    host,
    startedAt: `${date}T${hour}:${minute}:${second}.000Z`,
  };
}

async function streamZipEntry(zipPath, entryName, onLine) {
  const unzip = spawn('unzip', ['-p', zipPath, entryName], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const lines = readline.createInterface({ input: unzip.stdout, crlfDelay: Infinity });

  for await (const line of lines) {
    await onLine(line);
  }

  const exitCode = await new Promise((resolve, reject) => {
    unzip.on('error', reject);
    unzip.on('close', resolve);
  });
  if (exitCode !== 0) {
    throw new Error(`unzip -p failed for ${entryName} with exit code ${exitCode}`);
  }
}

async function run(command, args) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`${command} ${args.join(' ')} failed with exit code ${code}: ${stderr}`));
      }
    });
  });
}
