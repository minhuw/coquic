import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

// The runner is an executable ESM module and intentionally has no emitted declaration file.
// @ts-expect-error -- the test exercises the source-owned JavaScript runner directly.
import { baselinePath, checkBaseline, compareFindings, normalizeFindings } from '../scripts/check-stylelint-baseline.mjs';

type Finding = { file: string; rule: string; text: string };

const finding = (text: string): Finding => ({
  file: 'app/styles/example.css',
  rule: 'no-unknown',
  text,
});

describe('Stylelint baseline comparison', () => {
  it('rejects one extra finding', () => {
    const comparison = compareFindings([finding('existing'), finding('new')], [finding('existing')]);
    expect(comparison.newFindings).toEqual([finding('new')]);
    expect(comparison.missingFindings).toEqual([]);
  });

  it('rejects one stale baseline entry', () => {
    const comparison = compareFindings([finding('existing')], [finding('existing'), finding('stale')]);
    expect(comparison.newFindings).toEqual([]);
    expect(comparison.missingFindings).toEqual([finding('stale')]);
  });

  it('compares findings as an order-independent multiset', () => {
    const actual = [finding('second'), finding('first'), finding('first')];
    const expected = [finding('first'), finding('second'), finding('first')];
    expect(compareFindings(actual, expected)).toEqual({ newFindings: [], missingFindings: [] });
    expect(normalizeFindings(actual)).toEqual(normalizeFindings(expected));
  });

  it('accepts the exact checked-in inventory', async () => {
    const baseline = JSON.parse(await readFile(baselinePath, 'utf8')) as Finding[];
    expect(baseline).toHaveLength(358);
    const result = await checkBaseline();
    expect(result.newFindings).toEqual([]);
    expect(result.missingFindings).toEqual([]);
    expect(result.actual).toEqual(normalizeFindings(baseline));
  });
});
