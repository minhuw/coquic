import { describe, expect, it } from 'vitest';

import {
  classifyStewardFreshness,
  stewardFreshnessLabel,
  stewardPollIntervalMs,
} from '@/lib/steward-freshness';

import { producerFixture } from './fixtures';

const NOW = Date.parse('2026-07-13T12:00:00Z');

describe('Steward freshness classification', () => {
  it.each([
    ['active', 'live'],
    ['blocked', 'live'],
    ['empty', 'live'],
    ['failed', 'live'],
    ['idle', 'live'],
    ['integration', 'live'],
    ['stale', 'stale'],
  ] as const)('classifies the producer %s fixture as %s', (name, expected) => {
    expect(classifyStewardFreshness(producerFixture(name), NOW)).toBe(expected);
  });

  it('distinguishes offline, incompatible, and failed fetch states', () => {
    expect(classifyStewardFreshness(null, NOW)).toBe('offline');

    const incompatible = producerFixture('idle');
    incompatible.compatibility_state = 'incompatible';
    expect(classifyStewardFreshness(incompatible, NOW)).toBe('incompatible');

    expect(classifyStewardFreshness(producerFixture('idle'), NOW, true)).toBe('stale');
    expect(stewardFreshnessLabel('incompatible')).toBe('Incompatible');
  });

  it('uses the heartbeat interval boundaries for delayed and stale states', () => {
    const monitor = producerFixture('idle');
    const heartbeat = Date.parse(monitor.runtime.heartbeat_at);
    const interval = monitor.runtime.heartbeat_interval_seconds * 1000;

    expect(classifyStewardFreshness(monitor, heartbeat + interval * 2)).toBe('live');
    expect(classifyStewardFreshness(monitor, heartbeat + interval * 2 + 1)).toBe('delayed');
    expect(classifyStewardFreshness(monitor, heartbeat + interval * 4)).toBe('delayed');
    expect(classifyStewardFreshness(monitor, heartbeat + interval * 4 + 1)).toBe('stale');
  });

  it('polls active monitors faster and backs off stale/offline monitors', () => {
    const active = producerFixture('active');
    const idle = producerFixture('idle');
    const stale = producerFixture('stale');

    expect(stewardPollIntervalMs(active, NOW)).toBe(10_000);
    expect(stewardPollIntervalMs(idle, NOW)).toBe(30_000);
    expect(stewardPollIntervalMs(stale, NOW)).toBe(45_000);
    expect(stewardPollIntervalMs(null, NOW)).toBe(45_000);
  });
});
