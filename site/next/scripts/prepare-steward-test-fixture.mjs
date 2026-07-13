import { cp, mkdir, rm } from 'node:fs/promises';
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
await cp(monitorFixture, path.join(outputRoot, 'public/steward/status.json'));
await cp(
  detailFixture,
  path.join(outputRoot, 'public/steward/data/tasks/task-20260713115945-a1b2c3d4.json'),
);
