import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { loadMonitorFixture, loadMonitorFixtureText } from './fixtures';
import {
  decodePublicStewardJson,
  decodePublicStewardMonitor,
} from '@/lib/steward-schema';
import {
  classifyStewardFreshness,
  stewardPollIntervalMs,
} from '@/lib/steward-freshness';
import { paginateStewardItems } from '@/lib/steward-pagination';
import {
  parsePublicStewardStatus,
  readPublicStewardStatus,
} from '../app/steward/status/status-route';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('public monitor schema decoding', () => {
  it('accepts every producer v3 fixture', () => {
    for (const name of ['active', 'blocked', 'empty', 'failed', 'idle', 'integration', 'stale']) {
      const decoded = decodePublicStewardMonitor(loadMonitorFixture(name));
      expect(decoded).toEqual({ ok: true, data: expect.any(Object) });
    }
  });

  it('rejects malformed, incompatible, and structurally incomplete snapshots', () => {
    expect(decodePublicStewardJson('{')).toEqual({ ok: false, reason: 'malformed' });
    expect(decodePublicStewardMonitor({ schema_version: 2 })).toEqual({ ok: false, reason: 'incompatible' });

    const incomplete = loadMonitorFixture('idle');
    delete incomplete.tasks_truncated;
    expect(decodePublicStewardMonitor(incomplete)).toEqual({ ok: false, reason: 'invalid' });

    const malformedSignals = loadMonitorFixture('idle');
    malformedSignals.signals = { items: [], fetches: [] };
    expect(decodePublicStewardMonitor(malformedSignals)).toEqual({ ok: false, reason: 'invalid' });
  });
});

describe('monitor freshness', () => {
  it('classifies live, delayed, stale, offline, and incompatible data', () => {
    const now = Date.parse('2026-07-13T12:00:00Z');
    expect(classifyStewardFreshness(loadMonitorFixture('active') as never, now)).toBe('live');
    expect(classifyStewardFreshness(loadMonitorFixture('stale') as never, now)).toBe('stale');
    expect(classifyStewardFreshness(loadMonitorFixture('idle') as never, now + 75_000)).toBe('delayed');
    expect(classifyStewardFreshness(null, now)).toBe('offline');
    expect(classifyStewardFreshness({ compatibility_state: 'incompatible' }, now)).toBe('incompatible');
    expect(classifyStewardFreshness(loadMonitorFixture('active') as never, now, true)).toBe('stale');
  });

  it('polls active daemons faster and stale mirrors less often', () => {
    const now = Date.parse('2026-07-13T12:00:00Z');
    expect(stewardPollIntervalMs(loadMonitorFixture('active') as never, now)).toBe(10_000);
    expect(stewardPollIntervalMs(loadMonitorFixture('stale') as never, now)).toBe(45_000);
    expect(stewardPollIntervalMs(null, now)).toBe(45_000);
  });
});

describe('monitor route and bounded views', () => {
  it('maps route failures and valid status files to explicit results', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'steward-status-'));
    temporaryDirectories.push(root);
    const statusDirectory = path.join(root, 'public', 'steward');
    await mkdir(statusDirectory, { recursive: true });

    expect(await readPublicStewardStatus(root)).toEqual({ status: 'unavailable', reason: 'missing' });
    await writeFile(path.join(statusDirectory, 'status.json'), '{', 'utf8');
    expect(await readPublicStewardStatus(root)).toEqual({ status: 'unavailable', reason: 'malformed' });
    await writeFile(path.join(statusDirectory, 'status.json'), loadMonitorFixtureText('integration'), 'utf8');
    const result = await readPublicStewardStatus(root);
    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.data.planner_runs).toHaveLength(1);
  });

  it('keeps pagination bounded and clamps invalid pages', () => {
    const items = Array.from({ length: 21 }, (_, index) => index);
    expect(paginateStewardItems(items, 2, 10)).toMatchObject({ page: 2, pageCount: 3, start: 10, pageItems: items.slice(10, 20) });
    expect(paginateStewardItems(items, 99, 10).page).toBe(3);
    expect(paginateStewardItems([], 0, 10)).toMatchObject({ page: 1, pageCount: 1, pageItems: [] });
  });

  it('exposes planner artifact bounds from the shared producer fixture', () => {
    const monitor = loadMonitorFixture('integration');
    const plannerRuns = monitor.planner_runs as Array<Record<string, unknown>>;
    const artifacts = plannerRuns[0].artifacts as Record<string, Record<string, unknown>>;
    expect(artifacts.transcript.availability).toBe('available');
    expect(artifacts.transcript.truncated).toBe(false);
    expect(String(artifacts.transcript.text)).not.toContain('/home/');
  });
});
