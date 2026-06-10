'use client';

import Link from 'next/link';
import { ChevronDown, Contact } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { CoquicLogoIcon, GitHubIcon } from './icons';
import { SiteSearch } from './site-search';
import { ThemeToggle } from './theme-toggle';

export type DemoRoute = 'home' | 'workbench' | 'performance' | 'docs' | 'interop' | 'coverage' | 'duvet' | 'qa';

const views: { href: string; label: string; route: DemoRoute }[] = [
  { href: '/qa', label: 'Ask', route: 'qa' },
  { href: '/docs', label: 'Docs', route: 'docs' },
  { href: '/workbench', label: 'Workbench', route: 'workbench' },
  { href: '/performance', label: 'LAN', route: 'performance' },
  { href: '/interop', label: 'Interop', route: 'interop' },
  { href: '/coverage', label: 'Coverage', route: 'coverage' },
  { href: '/duvet', label: 'Duvet', route: 'duvet' },
];

const primaryViews = views.filter((view) => view.route === 'docs' || view.route === 'workbench' || view.route === 'qa');
const benchmarkViews = views.filter((view) => view.route === 'performance');
const developmentViews = views.filter((view) => view.route === 'interop' || view.route === 'coverage' || view.route === 'duvet');
type NavMenuId = 'benchmark' | 'development';

interface DemoNavProps {
  active: DemoRoute;
}

export function DemoNav({ active }: DemoNavProps) {
  const navRef = useRef<HTMLElement>(null);
  const linksRef = useRef<HTMLSpanElement>(null);
  const [openMenu, setOpenMenu] = useState<NavMenuId | null>(null);
  const benchmarkActive = benchmarkViews.some((view) => view.route === active);
  const developmentActive = developmentViews.some((view) => view.route === active);

  useEffect(() => {
    const activeItem = linksRef.current?.querySelector<HTMLElement>('[data-nav-active="true"]');
    if (!activeItem || !window.matchMedia('(max-width: 680px)').matches) {
      return;
    }
    activeItem.scrollIntoView({ block: 'nearest', inline: 'center' });
  }, [active]);

  useEffect(() => {
    if (!openMenu) {
      return;
    }

    function closeOnOutsidePointer(event: PointerEvent) {
      if (navRef.current?.contains(event.target as Node)) {
        return;
      }
      setOpenMenu(null);
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpenMenu(null);
      }
    }

    document.addEventListener('pointerdown', closeOnOutsidePointer);
    document.addEventListener('keydown', closeOnEscape);

    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [openMenu]);

  function toggleMenu(menu: NavMenuId) {
    setOpenMenu((current) => (current === menu ? null : menu));
  }

  function closeMenuForHoverPointer(event: React.MouseEvent<HTMLElement>) {
    if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
      setOpenMenu(null);
    }
  }

  function handleTriggerKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, menu: NavMenuId) {
    if (event.key === 'Escape') {
      setOpenMenu(null);
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      toggleMenu(menu);
    }
  }

  return (
    <nav
      ref={navRef}
      className="top-nav"
      aria-label="Demo views"
      onMouseLeave={closeMenuForHoverPointer}
    >
      <Link className="top-nav-home" href="/" aria-label="Home" aria-current={active === 'home' ? 'page' : undefined}>
        <CoquicLogoIcon className="size-8" aria-hidden="true" />
      </Link>
      <SiteSearch />
      <span className="top-nav-links" ref={linksRef}>
        {primaryViews.map((view) => (
          <Link
            key={view.href}
            className={`nav-link nav-link-${view.route}${active === view.route ? ' nav-link-active' : ''}`}
            href={view.href}
            aria-current={active === view.route ? 'page' : undefined}
            aria-label={view.label}
            data-nav-active={active === view.route ? 'true' : undefined}
          >
            {view.label}
          </Link>
        ))}
        <span
          className={`nav-menu nav-menu-benchmark${benchmarkActive ? ' nav-menu-active' : ''}`}
          data-active={benchmarkActive ? 'true' : undefined}
          data-nav-active={benchmarkActive ? 'true' : undefined}
          data-open={openMenu === 'benchmark' ? 'true' : undefined}
        >
          <button
            className="nav-link nav-menu-trigger"
            type="button"
            aria-current={benchmarkActive ? 'page' : undefined}
            aria-expanded={openMenu === 'benchmark'}
            onClick={() => {
              toggleMenu('benchmark');
            }}
            onKeyDown={(event) => {
              handleTriggerKeyDown(event, 'benchmark');
            }}
          >
            <span>Benchmark</span>
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="nav-menu-content">
            {benchmarkViews.map((view) => (
              <Link
                key={view.href}
                className="nav-menu-link"
                href={view.href}
                aria-current={active === view.route ? 'page' : undefined}
                onClick={() => {
                  setOpenMenu(null);
                }}
              >
                {view.label}
              </Link>
            ))}
          </span>
        </span>
        <span
          className={`nav-menu nav-menu-development${developmentActive ? ' nav-menu-active' : ''}`}
          data-active={developmentActive ? 'true' : undefined}
          data-nav-active={developmentActive ? 'true' : undefined}
          data-open={openMenu === 'development' ? 'true' : undefined}
        >
          <button
            className="nav-link nav-menu-trigger"
            type="button"
            aria-current={developmentActive ? 'page' : undefined}
            aria-expanded={openMenu === 'development'}
            onClick={() => {
              toggleMenu('development');
            }}
            onKeyDown={(event) => {
              handleTriggerKeyDown(event, 'development');
            }}
          >
            <span>Development</span>
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="nav-menu-content">
            {developmentViews.map((view) => (
              <Link
                key={view.href}
                className="nav-menu-link"
                href={view.href}
                aria-current={active === view.route ? 'page' : undefined}
                onClick={() => {
                  setOpenMenu(null);
                }}
              >
                {view.label}
              </Link>
            ))}
          </span>
        </span>
        <span className="nav-icon-actions">
          <ThemeToggle />
          <a
            className="repo-link"
            href="https://www.minhuw.dev"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Minhu Wang contact page"
          >
            <Contact aria-hidden="true" className="size-[19px]" />
          </a>
          <a
            className="repo-link"
            href="https://github.com/minhuw/coquic"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="CoQUIC on GitHub"
          >
            <GitHubIcon className="size-6" />
          </a>
        </span>
      </span>
      <span className="mobile-nav-menu-content" data-open={openMenu === 'benchmark' ? 'true' : undefined}>
        {benchmarkViews.map((view) => (
          <Link
            key={view.href}
            className="nav-menu-link"
            href={view.href}
            aria-current={active === view.route ? 'page' : undefined}
            onClick={() => {
              setOpenMenu(null);
            }}
          >
            {view.label}
          </Link>
        ))}
      </span>
      <span className="mobile-nav-menu-content" data-open={openMenu === 'development' ? 'true' : undefined}>
        {developmentViews.map((view) => (
          <Link
            key={view.href}
            className="nav-menu-link"
            href={view.href}
            aria-current={active === view.route ? 'page' : undefined}
            onClick={() => {
              setOpenMenu(null);
            }}
          >
            {view.label}
          </Link>
        ))}
      </span>
    </nav>
  );
}

export { views as demoViews };
