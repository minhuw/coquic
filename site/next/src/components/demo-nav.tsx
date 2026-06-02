'use client';

import Image from 'next/image';
import Link from 'next/link';
import { ChevronDown } from 'lucide-react';
import { useState } from 'react';

import { GitHubIcon } from './icons';

export type DemoRoute = 'home' | 'workbench' | 'performance' | 'docs' | 'interop' | 'coverage' | 'qa';

const views: Array<{ href: string; label: string; route: DemoRoute }> = [
  { href: '/qa', label: 'Ask', route: 'qa' },
  { href: '/docs', label: 'Docs', route: 'docs' },
  { href: '/workbench', label: 'Workbench', route: 'workbench' },
  { href: '/performance', label: 'LAN', route: 'performance' },
  { href: '/interop', label: 'Interop', route: 'interop' },
  { href: '/coverage', label: 'Coverage', route: 'coverage' },
];

const primaryViews = views.filter((view) => view.route === 'docs' || view.route === 'workbench' || view.route === 'qa');
const benchmarkViews = views.filter((view) => view.route === 'performance');
const developmentViews = views.filter((view) => view.route === 'interop' || view.route === 'coverage');
type NavMenuId = 'benchmark' | 'development';

type DemoNavProps = {
  active: DemoRoute;
};

export function DemoNav({ active }: DemoNavProps) {
  const [openMenu, setOpenMenu] = useState<NavMenuId | null>(null);
  const benchmarkActive = benchmarkViews.some((view) => view.route === active);
  const developmentActive = developmentViews.some((view) => view.route === active);

  function toggleMenu(menu: NavMenuId) {
    setOpenMenu((current) => (current === menu ? null : menu));
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
    <nav className="top-nav" aria-label="Demo views" onMouseLeave={() => setOpenMenu(null)}>
      <Link className="top-nav-home" href="/" aria-label="Home" aria-current={active === 'home' ? 'page' : undefined}>
        <Image src="/coquic-logo.svg" width={32} height={32} alt="" aria-hidden="true" priority={active === 'home'} />
      </Link>
      <span className="top-nav-links">
        {primaryViews.map((view) => (
          <Link key={view.href} className="nav-link" href={view.href} aria-current={active === view.route ? 'page' : undefined}>
            {view.label}
          </Link>
        ))}
        <span className="nav-menu" data-open={openMenu === 'benchmark' ? 'true' : undefined}>
          <button
            className="nav-link nav-menu-trigger"
            type="button"
            aria-current={benchmarkActive ? 'page' : undefined}
            aria-expanded={openMenu === 'benchmark'}
            onClick={() => toggleMenu('benchmark')}
            onKeyDown={(event) => handleTriggerKeyDown(event, 'benchmark')}
          >
            <span>Benchmark</span>
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="nav-menu-content">
            {benchmarkViews.map((view) => (
              <Link key={view.href} className="nav-menu-link" href={view.href} aria-current={active === view.route ? 'page' : undefined}>
                {view.label}
              </Link>
            ))}
          </span>
        </span>
        <span className="nav-menu" data-open={openMenu === 'development' ? 'true' : undefined}>
          <button
            className="nav-link nav-menu-trigger"
            type="button"
            aria-current={developmentActive ? 'page' : undefined}
            aria-expanded={openMenu === 'development'}
            onClick={() => toggleMenu('development')}
            onKeyDown={(event) => handleTriggerKeyDown(event, 'development')}
          >
            <span>Development</span>
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="nav-menu-content">
            {developmentViews.map((view) => (
              <Link key={view.href} className="nav-menu-link" href={view.href} aria-current={active === view.route ? 'page' : undefined}>
                {view.label}
              </Link>
            ))}
          </span>
        </span>
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
    </nav>
  );
}

export { views as demoViews };
