import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const configuredOutputRoot = process.env.COQUIC_PLAYWRIGHT_FIXTURE_ROOT;
const outputRoot = configuredOutputRoot === undefined
  ? defaultFixtureRoot()
  : configuredOutputRoot.trim();
const safeOutputRoot = await validateFixtureRoot(outputRoot);
const monitorFixture = path.join(
  repositoryRoot,
  'steward/schema/fixtures/public-monitor-v3/integration.json',
);
const detailFixture = path.join(
  repositoryRoot,
  'steward/schema/fixtures/public-task-v2/feature.json',
);

const stagingRoot = await mkdtemp(path.join(
  path.dirname(safeOutputRoot),
  '.coquic-steward-playwright-stage-',
));
let fixtureInstalled = false;

try {
  await mkdir(path.join(stagingRoot, 'public/steward/data/tasks'), { recursive: true });
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
    path.join(stagingRoot, 'public/steward/status.json'),
    JSON.stringify(monitor),
  );
  const monitorSourceAfter = await readFile(monitorFixture);
  if (!monitorSource.equals(monitorSourceAfter)) {
    throw new Error('Steward monitor source fixture changed while preparing test data');
  }
  const detailSource = await readFile(detailFixture);
  const detail = JSON.parse(detailSource.toString('utf8'));
  detail.attempts[0].patch = {
    availability: 'available',
    mode: 'redacted',
    text: 'diff --git a/monitor.ts b/monitor.ts\n@@ -1 +1 @@\n-old\n+new\n',
    size: 65,
    truncated: false,
    tail_bytes: 65,
  };
  await writeFile(
    path.join(stagingRoot, 'public/steward/data/tasks/task-20260713115945-a1b2c3d4.json'),
    JSON.stringify(detail),
  );
  const detailSourceAfter = await readFile(detailFixture);
  if (!detailSource.equals(detailSourceAfter)) {
    throw new Error('Steward detail source fixture changed while preparing test data');
  }

  await installFixtureRoot(stagingRoot, safeOutputRoot);
  fixtureInstalled = true;
} finally {
  if (!fixtureInstalled) await rm(stagingRoot, { recursive: true, force: true });
}

function defaultFixtureRoot() {
  const checkoutId = createHash('sha256').update(process.cwd()).digest('hex').slice(0, 12);
  return path.join(os.tmpdir(), `coquic-steward-playwright-${checkoutId}`);
}

async function validateFixtureRoot(candidate) {
  if (!candidate) throw new Error('COQUIC_PLAYWRIGHT_FIXTURE_ROOT must not be empty');

  const temporaryRoot = path.resolve(os.tmpdir());
  const temporaryRoots = [temporaryRoot];
  if (path.sep === '/' && temporaryRoot.startsWith('/tmp/')) temporaryRoots.push('/tmp');
  const resolvedCandidate = path.resolve(candidate);
  const selectedTemporaryRoot = temporaryRoots.find(
    (root) => path.dirname(resolvedCandidate) === root,
  );
  if (temporaryRoots.includes(resolvedCandidate) || selectedTemporaryRoot === undefined) {
    throw new Error(`COQUIC_PLAYWRIGHT_FIXTURE_ROOT must be a direct child of the temporary directory; received ${candidate}`);
  }
  const canonicalTemporaryRoot = await realpath(selectedTemporaryRoot);
  return path.join(canonicalTemporaryRoot, path.basename(resolvedCandidate));
}

async function installFixtureRoot(source, destination) {
  const retiredRoot = path.join(
    path.dirname(destination),
    `.coquic-steward-playwright-retired-${randomUUID()}`,
  );
  let retiredExistingFixture = false;

  try {
    await rename(destination, retiredRoot);
    retiredExistingFixture = true;
  } catch (error) {
    if (!error || typeof error !== 'object' || error.code !== 'ENOENT') throw error;
  }

  try {
    await rename(source, destination);
  } finally {
    if (retiredExistingFixture) {
      try {
        await rm(retiredRoot, { recursive: true, force: true });
      } catch (cleanupError) {
        throw new Error(`Failed to remove retired Playwright fixture ${retiredRoot}`, {
          cause: cleanupError,
        });
      }
    }
  }
}
