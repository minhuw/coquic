import { describe, expect, it } from 'vitest';

import {
  decodePublicStewardJson,
  decodePublicStewardMonitor,
  PUBLIC_STEWARD_SCHEMA_VERSION,
} from '@/lib/steward-schema';

import { PRODUCER_FIXTURE_NAMES, producerFixture, producerFixtureText } from './fixtures';

describe('public Steward schema v3 decoder', () => {
  it.each(PRODUCER_FIXTURE_NAMES)('accepts the producer %s snapshot', (name) => {
    const decoded = decodePublicStewardJson(producerFixtureText(name));

    expect(decoded).toEqual({ ok: true, data: producerFixture(name) });
    if (decoded.ok) expect(decoded.data.schema_version).toBe(PUBLIC_STEWARD_SCHEMA_VERSION);
  });

  it('distinguishes malformed, incompatible, and structurally invalid payloads', () => {
    expect(decodePublicStewardJson('{')).toEqual({ ok: false, reason: 'malformed' });
    expect(decodePublicStewardMonitor(null)).toEqual({ ok: false, reason: 'malformed' });

    const incompatible = producerFixture('idle');
    incompatible.schema_version = 2 as never;
    expect(decodePublicStewardMonitor(incompatible)).toEqual({ ok: false, reason: 'incompatible' });

    const missingRuntime = producerFixture('idle') as Record<string, unknown>;
    delete missingRuntime.runtime;
    expect(decodePublicStewardMonitor(missingRuntime)).toEqual({ ok: false, reason: 'invalid' });

    const invalidRuntime = producerFixture('idle');
    invalidRuntime.runtime = [] as never;
    expect(decodePublicStewardMonitor(invalidRuntime)).toEqual({ ok: false, reason: 'invalid' });
  });

  it('allows additive fields while keeping the v3 contract versioned', () => {
    const additive = producerFixture('active') as Record<string, unknown>;
    additive.future_field = { retained: true };
    const decoded = decodePublicStewardMonitor(additive);

    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect((decoded.data as Record<string, unknown>).future_field).toEqual({ retained: true });
  });
});
