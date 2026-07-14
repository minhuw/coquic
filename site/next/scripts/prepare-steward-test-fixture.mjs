import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const outputRoot = '/tmp/coquic-steward-playwright';
const monitorFixture = path.join(
  repositoryRoot,
  'steward/schema/fixtures/public-monitor-v3/integration.json',
);
const detailFixture = path.join(
  repositoryRoot,
  'steward/schema/fixtures/public-task-v2/feature.json',
);

await rm(outputRoot, { recursive: true, force: true });
await mkdir(path.join(outputRoot, 'public/steward/data/tasks'), { recursive: true });
const monitorSource = await readFile(monitorFixture);
const monitor = JSON.parse(monitorSource.toString('utf8'));
const nowMs = Date.now();
const generatedAtMs = Date.parse(monitor.generated_at);
if (!Number.isFinite(generatedAtMs)) {
  throw new Error('Steward monitor fixture has an invalid generated_at timestamp');
}
const timestampOffsetMs = nowMs - 5_000 - generatedAtMs;
const isoTimestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function shiftTimestamps(value) {
  if (Array.isArray(value)) {
    value.forEach(shiftTimestamps);
    return;
  }
  if (value === null || typeof value !== 'object') return;

  for (const [key, child] of Object.entries(value)) {
    if (
      typeof child === 'string'
      && (key === 'timestamp' || key.endsWith('_at'))
      && isoTimestampPattern.test(child)
    ) {
      const timestampMs = Date.parse(child);
      if (Number.isFinite(timestampMs)) {
        value[key] = new Date(timestampMs + timestampOffsetMs).toISOString();
      }
      continue;
    }
    shiftTimestamps(child);
  }
}

shiftTimestamps(monitor);
await writeFile(
  path.join(outputRoot, 'public/steward/status.json'),
  JSON.stringify(monitor),
);
const monitorSourceAfter = await readFile(monitorFixture);
if (!monitorSource.equals(monitorSourceAfter)) {
  throw new Error('Steward monitor source fixture changed while preparing test data');
}
const detail = JSON.parse(await readFile(detailFixture, 'utf8'));
detail.attempts[0].patch = {
  availability: 'available',
  mode: 'redacted',
  text: 'diff --git a/monitor.ts b/monitor.ts\n@@ -1 +1 @@\n-old\n+new\n',
  size: 65,
  truncated: false,
  tail_bytes: 65,
};
await writeFile(
  path.join(outputRoot, 'public/steward/data/tasks/task-20260713115945-a1b2c3d4.json'),
  JSON.stringify(detail),
);
