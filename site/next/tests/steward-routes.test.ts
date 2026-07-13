import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { GET as getTaskData } from '@app/steward/data/tasks/[taskId]/route';
import { GET as getArtifact } from '@app/steward/data/tasks/[taskId]/runs/[runName]/codex.jsonl/route';
import { GET as getStatus } from '@app/steward/status/route';
import { GET as getStatusAlias } from '@app/steward/status.json/route';
import {
  parsePublicStewardStatus,
  readPublicStewardStatus,
} from '@app/steward/status/status-route';

import { producerFixture, producerFixtureText } from './fixtures';

const roots: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

async function siteRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'coquic-site-monitor-'));
  roots.push(root);
  await mkdir(path.join(root, 'public', 'steward'), { recursive: true });
  return root;
}

describe('public Steward status route', () => {
  it('parses a producer fixture without starting a local web server', () => {
    const result = parsePublicStewardStatus(producerFixtureText('active'));

    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.data).toEqual(producerFixture('active'));
  });

  it.each([
    ['missing', async (root: string) => root],
    ['unreadable', async (root: string) => {
      await mkdir(path.join(root, 'public', 'steward', 'status.json'));
      return root;
    }],
    ['malformed', async (root: string) => {
      await writeFile(path.join(root, 'public', 'steward', 'status.json'), '{', 'utf8');
      return root;
    }],
    ['incompatible', async (root: string) => {
      const document = producerFixture('idle') as Record<string, unknown>;
      document.schema_version = 2;
      await writeFile(path.join(root, 'public', 'steward', 'status.json'), JSON.stringify(document), 'utf8');
      return root;
    }],
    ['invalid', async (root: string) => {
      const document = producerFixture('idle') as Record<string, unknown>;
      delete document.runtime;
      await writeFile(path.join(root, 'public', 'steward', 'status.json'), JSON.stringify(document), 'utf8');
      return root;
    }],
  ] as const)('reports %s status files', async (reason, setup) => {
    const root = await siteRoot();
    await setup(root);

    await expect(readPublicStewardStatus(root)).resolves.toEqual({ status: 'unavailable', reason });
  });

  it('returns a no-store v3 response with explicit data headers', async () => {
    const root = await siteRoot();
    await writeFile(path.join(root, 'public', 'steward', 'status.json'), producerFixtureText('idle'), 'utf8');
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const response = await getStatus();
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect((await response.json()).schema_version).toBe(3);
  });

  it('redirects the legacy status file to the canonical route', async () => {
    const response = await getStatusAlias();

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('/steward/status');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('returns 503 with the reason when the publication is unavailable', async () => {
    const root = await siteRoot();
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const response = await getStatus();
    expect(response.status).toBe(503);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({ status: 'unavailable', reason: 'missing' });
  });
});

describe('public Steward data routes', () => {
  it('loads a task detail artifact and preserves its JSON bytes', async () => {
    const root = await siteRoot();
    const task = producerFixture('active').tasks[0];
    if (!task) throw new Error('active producer fixture has no task');
    const taskDirectory = path.join(root, 'public', 'steward', 'data', 'tasks');
    await mkdir(taskDirectory, { recursive: true });
    const expected = producerFixtureText('active');
    await writeFile(path.join(taskDirectory, `${task.id}.json`), expected, 'utf8');
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const response = await getTaskData(new Request('http://site.test/steward/data/tasks/task.json'), {
      params: Promise.resolve({ taskId: `${task.id}.json` }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    await expect(response.text()).resolves.toBe(expected);

    const replacement = '{"schema_version":3}\n';
    await writeFile(path.join(taskDirectory, `${task.id}.json`), replacement, 'utf8');
    const refreshed = await getTaskData(new Request('http://site.test'), {
      params: Promise.resolve({ taskId: `${task.id}.json` }),
    });
    await expect(refreshed.text()).resolves.toBe(replacement);
  });

  it('rejects unsafe task ids and missing task files', async () => {
    const root = await siteRoot();
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const unsafe = await getTaskData(new Request('http://site.test'), {
      params: Promise.resolve({ taskId: '../../status.json' }),
    });
    const missing = await getTaskData(new Request('http://site.test'), {
      params: Promise.resolve({ taskId: 'task-20260713115945-a1b2c3d4' }),
    });
    expect(unsafe.status).toBe(404);
    expect(missing.status).toBe(404);
    expect(await unsafe.text()).toBe(await missing.text());
    expect(unsafe.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(missing.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('loads text-only codex JSONL artifacts and rejects unsafe run names', async () => {
    const root = await siteRoot();
    const taskId = 'task-20260713115945-a1b2c3d4';
    const artifactDirectory = path.join(root, 'public', 'steward', 'data', 'tasks', taskId, 'runs', 'worker-1');
    await mkdir(artifactDirectory, { recursive: true });
    const expected = '{"type":"item.completed"}\n';
    await writeFile(path.join(artifactDirectory, 'codex.jsonl'), expected, 'utf8');
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const response = await getArtifact(new Request('http://site.test'), {
      params: Promise.resolve({ taskId, runName: 'worker-1' }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toBe('application/x-ndjson; charset=utf-8');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    await expect(response.text()).resolves.toBe(expected);

    const unsafe = await getArtifact(new Request('http://site.test'), {
      params: Promise.resolve({ taskId, runName: '../../status' }),
    });
    expect(unsafe.status).toBe(404);
  });

  it('returns 404 for an invalid task id before touching the filesystem', async () => {
    const response = await getArtifact(new Request('http://site.test'), {
      params: Promise.resolve({ taskId: 'index.json', runName: 'worker-1' }),
    });
    expect(response.status).toBe(404);
  });
});
