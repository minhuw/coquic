'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ArrowRight, BarChart3, BookOpen, FileText, Gauge, Search, Terminal, X } from 'lucide-react';
import MiniSearch from 'minisearch';
import { useEffect, useMemo, useRef, useState } from 'react';

import { siteSearchItems, type SiteSearchItem, type SiteSearchKind } from '@/lib/search-index';

const suggestedIds = ['route-qa', 'route-workbench', 'route-docs', 'route-performance', 'route-interop', 'route-coverage'];
const maxResults = 8;
const searchEngine = createSearchEngine(siteSearchItems);

export function SiteSearch() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  const results = useMemo(() => searchItems(query), [query]);

  useEffect(() => {
    function handleGlobalKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen(true);
      }
    }

    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => document.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  useEffect(() => {
    if (!open) {
      return;
    }

    setActiveIndex(0);
    window.setTimeout(() => inputRef.current?.focus(), 0);

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    }

    document.addEventListener('keydown', closeOnEscape);
    return () => document.removeEventListener('keydown', closeOnEscape);
  }, [open]);

  useEffect(() => {
    setActiveIndex((current) => Math.min(current, Math.max(results.length - 1, 0)));
  }, [results.length]);

  function closeSearch() {
    setOpen(false);
  }

  function navigateTo(item: SiteSearchItem) {
    closeSearch();
    router.push(item.href);
  }

  function handleInputKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((current) => (results.length ? (current + 1) % results.length : 0));
      return;
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((current) => (results.length ? (current - 1 + results.length) % results.length : 0));
      return;
    }

    if (event.key === 'Enter' && results[activeIndex]) {
      event.preventDefault();
      navigateTo(results[activeIndex]);
    }
  }

  return (
    <span className="site-search">
      <button className="site-search-trigger" type="button" aria-haspopup="dialog" onClick={() => setOpen(true)}>
        <Search aria-hidden="true" />
        <span className="site-search-trigger-label">Search</span>
        <kbd>Ctrl K</kbd>
      </button>

      {open ? (
        <div className="site-search-backdrop" role="presentation" onClick={closeSearch} onMouseDown={closeSearch}>
          <section
            aria-label="Site search"
            aria-modal="true"
            className="site-search-dialog"
            role="dialog"
            onClick={(event) => event.stopPropagation()}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="site-search-field">
              <Search aria-hidden="true" />
              <input
                ref={inputRef}
                aria-controls="site-search-results"
                aria-label="Search CoQUIC"
                autoComplete="off"
                id="site-search-input"
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={handleInputKeyDown}
                placeholder="Search docs, dashboards, workbench scenarios..."
                type="search"
                value={query}
              />
              <button className="site-search-close" type="button" aria-label="Close search" onClick={closeSearch}>
                <X aria-hidden="true" />
              </button>
            </div>

            <div className="site-search-results" id="site-search-results" role="listbox" aria-label="Search results">
              {results.length ? (
                results.map((item, index) => (
                  <SearchResult
                    active={index === activeIndex}
                    item={item}
                    key={item.id}
                    onClick={() => {
                      closeSearch();
                    }}
                    query={query}
                  />
                ))
              ) : (
                <div className="site-search-empty">
                  <strong>No matches</strong>
                  <span>Try ACK, Retry, Workbench, Coverage, API, or HTTP/3.</span>
                </div>
              )}
            </div>
          </section>
        </div>
      ) : null}
    </span>
  );
}

function SearchResult({
  active,
  item,
  onClick,
  query,
}: {
  active: boolean;
  item: SiteSearchItem;
  onClick: () => void;
  query: string;
}) {
  const Icon = iconForKind(item.kind);
  const snippet = snippetForItem(item, query);

  return (
    <Link
      aria-selected={active}
      className="site-search-result"
      href={item.href}
      onClick={onClick}
      role="option"
      tabIndex={-1}
    >
      <span className="site-search-result-icon" aria-hidden="true">
        <Icon />
      </span>
      <span className="site-search-result-copy">
        <span>
          <strong>{item.title}</strong>
          <small>{item.section}</small>
        </span>
        <em>{snippet}</em>
      </span>
      <ArrowRight className="site-search-result-arrow" aria-hidden="true" />
    </Link>
  );
}

function searchItems(query: string): SiteSearchItem[] {
  const normalized = normalize(query);
  if (!normalized) {
    return suggestedIds
      .map((id) => siteSearchItems.find((item) => item.id === id))
      .filter((item): item is SiteSearchItem => Boolean(item));
  }

  return searchEngine
    .search(normalized, {
      prefix: (term) => term.length >= 3,
      fuzzy: (term) => (term.length >= 5 ? 0.18 : false),
      boost: {
        title: 8,
        headings: 5,
        keywords: 4,
        section: 3,
        description: 2,
        body: 1,
      },
    })
    .slice(0, maxResults)
    .map((result) => result.item);
}

function normalize(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function createSearchEngine(items: SiteSearchItem[]) {
  const engine = new MiniSearch<SiteSearchItem & { item: SiteSearchItem }>({
    fields: ['title', 'section', 'description', 'keywords', 'headings', 'body'],
    storeFields: ['item'],
  });
  engine.addAll(items.map((item) => ({ ...item, item })));
  return engine;
}

function snippetForItem(item: SiteSearchItem, query: string) {
  const normalized = normalize(query);
  const body = item.body?.replace(/\s+/g, ' ').trim();
  if (!normalized || !body) return item.description;

  const token = normalized.split(' ').find((part) => part.length >= 3);
  if (!token) return item.description;

  const index = body.toLowerCase().indexOf(token);
  if (index < 0) return item.description;

  const start = Math.max(0, index - 72);
  const end = Math.min(body.length, index + 152);
  const prefix = start > 0 ? '...' : '';
  const suffix = end < body.length ? '...' : '';
  return `${prefix}${body.slice(start, end).trim()}${suffix}`;
}

function iconForKind(kind: SiteSearchKind) {
  switch (kind) {
    case 'docs':
      return BookOpen;
    case 'tool':
      return Terminal;
    case 'dashboard':
      return BarChart3;
    case 'scenario':
      return Gauge;
    case 'page':
      return FileText;
  }
}
