'use client';

import Link from 'next/link';
import { ChevronDown, Contact, Menu, X } from 'lucide-react';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

import { CoquicLogoIcon, GitHubIcon } from './icons';
import { SiteSearch } from './site-search';
import { ThemeToggle } from './theme-toggle';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogTrigger } from './ui/dialog';

export type DemoRoute = 'home' | 'workbench' | 'performance' | 'docs' | 'blog' | 'dataset' | 'interop' | 'coverage' | 'duvet' | 'steward' | 'qa';

export const views: { href: string; label: string; route: DemoRoute }[] = [
  { href: '/docs', label: 'Docs', route: 'docs' },
  { href: '/workbench', label: 'Workbench', route: 'workbench' },
  { href: '/qa', label: 'Ask', route: 'qa' },
  { href: '/transcript', label: 'Dataset', route: 'dataset' },
  { href: '/performance', label: 'Performance', route: 'performance' },
  { href: '/interop', label: 'Interop', route: 'interop' },
  { href: '/coverage', label: 'Coverage', route: 'coverage' },
  { href: '/duvet', label: 'Duvet', route: 'duvet' },
  { href: '/blog', label: 'Blog', route: 'blog' },
  { href: '/steward', label: 'Steward', route: 'steward' },
];

const evidenceViews = views.filter((view) => ['performance', 'interop', 'coverage', 'duvet'].includes(view.route));
const projectViews = views.filter((view) => ['blog', 'steward'].includes(view.route));
type NavMenuId = 'evidence' | 'project';

function routeForPath(pathname: string): DemoRoute {
  if (pathname === '/') return 'home';
  if (pathname.startsWith('/docs')) return 'docs';
  if (pathname.startsWith('/workbench')) return 'workbench';
  if (pathname.startsWith('/qa')) return 'qa';
  if (pathname.startsWith('/transcript')) return 'dataset';
  if (pathname.startsWith('/blog')) return 'blog';
  if (pathname.startsWith('/steward')) return 'steward';
  if (pathname === '/performance' || pathname === '/perf-comparison') return 'performance';
  if (pathname === '/interop' || pathname === '/interop-results') return 'interop';
  if (pathname === '/coverage' || pathname === '/coverage-results') return 'coverage';
  if (pathname.startsWith('/duvet')) return 'duvet';
  return 'home';
}

export function DemoNav() {
  const pathname = usePathname() || '/';
  const active = routeForPath(pathname);
  const [openMenu, setOpenMenu] = useState<NavMenuId | null>(null);
  const activeEvidence = evidenceViews.some((view) => view.route === active);
  const activeProject = projectViews.some((view) => view.route === active);

  return (
    <nav className="top-nav" aria-label="Demo views">
      <Link className="top-nav-home" href="/" aria-label="Home" aria-current={active === 'home' ? 'page' : undefined}>
        <CoquicLogoIcon className="size-7" aria-hidden="true" />
      </Link>
      <div className="desktop-nav-content">
        <span className="top-nav-links">
          {views.slice(0, 4).map((view) => <NavLink key={view.href} view={view} active={active} />)}
          <Disclosure id="evidence" label="Evidence" active={active} isActive={activeEvidence} openMenu={openMenu} setOpenMenu={setOpenMenu} views={evidenceViews} />
          <Disclosure id="project" label="Project" active={active} isActive={activeProject} openMenu={openMenu} setOpenMenu={setOpenMenu} views={projectViews} />
        </span>
        <span className="nav-icon-actions">
          <SiteSearch />
          <ThemeToggle />
          <a className="repo-link" href="https://github.com/minhuw/coquic" target="_blank" rel="noopener noreferrer" aria-label="CoQUIC on GitHub"><GitHubIcon className="size-5" /></a>
        </span>
      </div>
      <div className="mobile-nav-actions">
        <SiteSearch enableShortcut={false} />
        <ThemeToggle />
        <Dialog>
          <DialogTrigger asChild><button className="shell-icon-button mobile-menu-trigger" type="button" aria-label="Open menu"><Menu aria-hidden="true" /></button></DialogTrigger>
          <DialogContent className="mobile-nav-drawer" aria-describedby={undefined}>
            <div className="mobile-drawer-header">
              <DialogTitle>CoQUIC navigation</DialogTitle>
              <DialogClose className="shell-icon-button" aria-label="Close menu"><X aria-hidden="true" /></DialogClose>
            </div>
            <div className="mobile-drawer-links">
              {views.map((view) => <NavLink key={view.href} view={view} active={active} drawer />)}
              <a className="mobile-drawer-link" href="https://github.com/minhuw/coquic" target="_blank" rel="noopener noreferrer"><GitHubIcon /> GitHub</a>
              <a className="mobile-drawer-link" href="https://www.minhuw.dev" target="_blank" rel="noopener noreferrer"><Contact /> Contact</a>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </nav>
  );
}

function NavLink({ view, active, drawer = false, menu = false, onSelect }: { view: (typeof views)[number]; active: DemoRoute; drawer?: boolean; menu?: boolean; onSelect?: () => void }) {
  return <Link className={drawer ? 'mobile-drawer-link' : menu ? 'nav-menu-link' : 'nav-link'} href={view.href} aria-current={active === view.route ? 'page' : undefined} onClick={onSelect}>{view.label}</Link>;
}

function Disclosure({ id, label, active, isActive, openMenu, setOpenMenu, views: menuViews }: { id: NavMenuId; label: string; active: DemoRoute; isActive: boolean; openMenu: NavMenuId | null; setOpenMenu: (id: NavMenuId | null) => void; views: typeof views }) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const open = openMenu === id;
  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent) {
        if (event.key !== 'Escape') return;
      } else if (event.target instanceof Node && triggerRef.current?.parentElement?.contains(event.target)) {
        return;
      }
      setOpenMenu(null);
      requestAnimationFrame(() => triggerRef.current?.focus());
    };
    document.addEventListener('pointerdown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('pointerdown', close);
      document.removeEventListener('keydown', close);
    };
  }, [open, setOpenMenu]);

  const closeMenu = () => {
    setOpenMenu(null);
    triggerRef.current?.focus();
  };

  return (
    <span className={`nav-menu${isActive ? ' nav-menu-active' : ''}`} data-open={open ? 'true' : undefined}>
      <button ref={triggerRef} className="nav-link nav-menu-trigger" type="button" aria-expanded={open} aria-current={isActive ? 'page' : undefined} onClick={() => open ? closeMenu() : setOpenMenu(id)}>
        {label}<ChevronDown aria-hidden="true" />
      </button>
      <span className="nav-menu-content">
        {menuViews.map((view) => <NavLink key={view.href} view={view} active={active} menu onSelect={closeMenu} />)}
      </span>
    </span>
  );
}

export { routeForPath };
