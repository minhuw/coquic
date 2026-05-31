import Image from 'next/image';
import Link from 'next/link';
import { ChevronDown } from 'lucide-react';

import { GitHubIcon } from './icons';

export type DemoRoute = 'home' | 'workbench' | 'performance' | 'interop' | 'coverage';

const views: Array<{ href: string; label: string; route: DemoRoute }> = [
  { href: '/workbench', label: 'Workbench', route: 'workbench' },
  { href: '/performance', label: 'Performance', route: 'performance' },
  { href: '/interop', label: 'Interop', route: 'interop' },
  { href: '/coverage', label: 'Coverage', route: 'coverage' },
];

const primaryViews = views.filter((view) => view.route === 'workbench' || view.route === 'performance');
const developmentViews = views.filter((view) => view.route === 'interop' || view.route === 'coverage');

type DemoNavProps = {
  active: DemoRoute;
};

export function DemoNav({ active }: DemoNavProps) {
  const developmentActive = developmentViews.some((view) => view.route === active);

  return (
    <nav className="top-nav" aria-label="Demo views">
      <Link className="top-nav-home" href="/" aria-label="Home" aria-current={active === 'home' ? 'page' : undefined}>
        <Image src="/coquic-logo.svg" width={32} height={32} alt="" aria-hidden="true" priority={active === 'home'} />
      </Link>
      <span className="top-nav-links">
        {primaryViews.map((view) => (
          <Link key={view.href} className="nav-link" href={view.href} aria-current={active === view.route ? 'page' : undefined}>
            {view.label}
          </Link>
        ))}
        <details className="nav-menu">
          <summary className="nav-link nav-menu-trigger" aria-current={developmentActive ? 'page' : undefined}>
            <span>Development</span>
            <ChevronDown aria-hidden="true" />
          </summary>
          <span className="nav-menu-content">
            {developmentViews.map((view) => (
              <Link key={view.href} className="nav-menu-link" href={view.href} aria-current={active === view.route ? 'page' : undefined}>
                {view.label}
              </Link>
            ))}
          </span>
        </details>
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
