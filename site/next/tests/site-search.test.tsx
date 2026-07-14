import { describe, expect, it } from 'vitest';

import { createSearchEngine, groupResults, searchItems } from '@/components/site-search-dialog';
import { siteSearchItems } from '@/lib/search-index';

describe('site search registry and ranking', () => {
  const engine = createSearchEngine(siteSearchItems);

  it('contains every navigable destination, including Dataset and Steward', () => {
    expect(siteSearchItems.map((item) => item.href)).toEqual(expect.arrayContaining(['/docs', '/workbench', '/qa', '/transcript', '/steward', '/blog', '/performance', '/interop', '/coverage', '/duvet']));
  });

  it('returns stable empty-query suggestions and factual no-match results', () => {
    expect(searchItems(engine, '').map((item) => item.id)).toEqual(['route-docs', 'route-workbench', 'route-qa', 'route-dataset', 'route-steward']);
    expect(searchItems(engine, 'zzzzqv blorpt')).toEqual([]);
  });

  it('ranks title matches first and groups without changing group order', () => {
    const results = searchItems(engine, 'coverage');
    expect(results[0]).toMatchObject({ id: 'route-coverage', title: 'Coverage Report' });
    expect(groupResults(results).map(([name]) => name)).toEqual(['Destinations']);
    expect(groupResults(searchItems(engine, 'api')).map(([name]) => name)).toContain('Documentation');
  });
});
