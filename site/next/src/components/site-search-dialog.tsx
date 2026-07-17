'use client';

import Link from 'next/link';
import { ArrowRight, BarChart3, BookOpen, FileText, Gauge, Newspaper, Search, Terminal, X } from 'lucide-react';
import MiniSearch from 'minisearch';
import { useEffect, useMemo, useRef, useState } from 'react';

import { siteSearchItems, type SiteSearchItem, type SiteSearchKind } from '@/lib/search-index';
import styles from './site-search.module.css';
import { Button } from './ui/button';
import { DialogClose, DialogContent, DialogTitle } from './ui/dialog';

const emptyQueryIds = ['route-docs', 'route-workbench', 'route-qa', 'route-dataset', 'route-steward'];
const maxResults = 12;

export function SiteSearchDialog() {
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const engine = useMemo(() => createSearchEngine(siteSearchItems), []);
  const results = useMemo(() => searchItems(engine, query), [engine, query]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  useEffect(() => {
    const active = resultsRef.current?.querySelector<HTMLElement>(`[data-result-index="${activeIndex}"]`);
    active?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((current) => results.length ? (current + 1) % results.length : 0);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((current) => results.length ? (current - 1 + results.length) % results.length : 0);
    } else if (event.key === 'Enter' && results[activeIndex]) {
      event.preventDefault();
      document.querySelector<HTMLElement>(`[data-result-index="${activeIndex}"]`)?.click();
    }
  }

  return (
    <DialogContent className={styles.dialog} aria-describedby="site-search-status" data-slot="site-search-dialog">
      <DialogTitle className="sr-only">Site search</DialogTitle>
      <div className={styles.field} data-slot="site-search-field">
        <Search aria-hidden="true" />
        <input ref={inputRef} aria-activedescendant={results[activeIndex] ? `site-search-result-${results[activeIndex].id}` : undefined} aria-controls="site-search-results" aria-label="Search CoQUIC" autoComplete="off" onChange={(event) => setQuery(event.target.value)} onKeyDown={onKeyDown} placeholder="Search docs, dashboards, workbench scenarios..." type="search" value={query} />
        {query ? <Button className={styles.clear} variant="ghost" size="icon" type="button" aria-label="Clear search" onClick={() => setQuery('')} data-shell-control="search-clear"><X aria-hidden="true" /></Button> : null}
        <DialogClose className={styles.close} aria-label="Close search"><X aria-hidden="true" /></DialogClose>
      </div>
      <div className={styles.status} id="site-search-status" role="status" aria-live="polite">{query ? `${results.length} result${results.length === 1 ? '' : 's'}` : 'Suggested destinations'}</div>
      <div ref={resultsRef} className={styles.results} id="site-search-results" role="region" aria-label="Search results" tabIndex={0}>
        {results.length ? groupResults(results).map(([group, items]) => <section key={group} className={styles.group} aria-label={group}><h3>{group}</h3>{items.map((item) => <SearchResult key={item.id} item={item} active={results[activeIndex]?.id === item.id} index={results.indexOf(item)} query={query} />)}</section>) : <div className={styles.empty}><strong>No matches</strong><span>No indexed CoQUIC destination matches this query.</span></div>}
      </div>
    </DialogContent>
  );
}

function SearchResult({ item, active, index, query }: { item: SiteSearchItem; active: boolean; index: number; query: string }) {
  const Icon = iconForKind(item.kind);
  return <Link id={`site-search-result-${item.id}`} className={styles.result} data-result-index={index} data-active={active ? 'true' : undefined} href={item.href}><span className={styles.resultIcon} aria-hidden="true"><Icon /></span><span className={styles.resultCopy}><strong>{item.title}</strong><small>{item.section}</small><em>{snippetForItem(item, query)}</em></span><ArrowRight className={styles.resultArrow} aria-hidden="true" /></Link>;
}

export function searchItems(engine: MiniSearch<SiteSearchItem & { item: SiteSearchItem }>, query: string) {
  const normalized = normalize(query);
  if (!normalized) return emptyQueryIds.map((id) => siteSearchItems.find((item) => item.id === id)).filter((item): item is SiteSearchItem => Boolean(item));
  return engine.search(normalized, { prefix: (term) => term.length >= 3, fuzzy: (term) => term.length >= 5 ? 0.18 : false, boost: { title: 8, headings: 5, keywords: 4, section: 3, description: 2, body: 1 } }).filter((result) => result.score >= 1 && hasQueryToken(result.item, normalized)).slice(0, maxResults).map((result) => result.item);
}

function hasQueryToken(item: SiteSearchItem, query: string) {
  const searchable = [item.title, item.section, item.description, ...item.keywords, ...(item.headings || []), item.body || ''].join(' ').toLowerCase();
  return query.split(' ').some((token) => token.length >= 3 && searchable.includes(token));
}

export function groupResults(items: SiteSearchItem[]) {
  const groups = new Map<string, SiteSearchItem[]>();
  for (const item of items) {
    const group = item.kind === 'docs' ? 'Documentation' : item.kind === 'blog' ? 'Project' : item.kind === 'scenario' ? 'Workbench' : 'Destinations';
    groups.set(group, [...(groups.get(group) || []), item]);
  }
  return [...groups];
}

function normalize(value: string) { return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
export function createSearchEngine(items: SiteSearchItem[]) { const engine = new MiniSearch<SiteSearchItem & { item: SiteSearchItem }>({ fields: ['title', 'section', 'description', 'keywords', 'headings', 'body'], storeFields: ['item'] }); engine.addAll(items.map((item) => ({ ...item, item }))); return engine; }
function snippetForItem(item: SiteSearchItem, query: string) { const body = item.body?.replace(/\s+/g, ' ').trim(); const token = normalize(query).split(' ').find((part) => part.length >= 3); if (!body || !token) return item.description; const index = body.toLowerCase().indexOf(token); return index < 0 ? item.description : `${index > 72 ? '...' : ''}${body.slice(Math.max(0, index - 72), index + 152).trim()}${index + 152 < body.length ? '...' : ''}`; }
function iconForKind(kind: SiteSearchKind) { switch (kind) { case 'docs': return BookOpen; case 'blog': return Newspaper; case 'tool': return Terminal; case 'dashboard': return BarChart3; case 'scenario': return Gauge; default: return FileText; } }
