'use client';

import Link from 'next/link';
import { ChevronDown, Contact, Menu, X } from 'lucide-react';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

import { CoquicLogoIcon, GitHubIcon } from './icons';
import styles from './demo-nav.module.css';
import { SiteSearch } from './site-search';
import { ThemeToggle } from './theme-toggle';
import { Button } from './ui/button';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogTrigger } from './ui/dialog';

export type DemoRoute = 'home' | 'workbench' | 'performance' | 'docs' | 'blog' | 'dataset' | 'interop' | 'coverage' | 'duvet' | 'steward' | 'qa';

export const views: { href: string; label: string; route: DemoRoute }[] = [
  { href: '/qa', label: 'Ask', route: 'qa' },
  { href: '/docs', label: 'Docs', route: 'docs' },
  { href: '/blog', label: 'Blog', route: 'blog' },
  { href: '/transcript', label: 'Dataset', route: 'dataset' },
  { href: '/workbench', label: 'Workbench', route: 'workbench' },
  { href: '/performance', label: 'LAN', route: 'performance' },
  { href: '/interop', label: 'Interop', route: 'interop' },
  { href: '/coverage', label: 'Coverage', route: 'coverage' },
  { href: '/duvet', label: 'Duvet', route: 'duvet' },
  { href: '/steward', label: 'Steward', route: 'steward' },
];

const primaryViews = views.filter((view) => ['qa', 'docs', 'blog', 'dataset', 'workbench'].includes(view.route));
const benchmarkViews = views.filter((view) => view.route === 'performance');
const developmentViews = views.filter((view) => ['interop', 'coverage', 'duvet', 'steward'].includes(view.route));
type NavMenuId = 'benchmark' | 'development';

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
  const activeBenchmark = benchmarkViews.some((view) => view.route === active);
  const activeDevelopment = developmentViews.some((view) => view.route === active);

  return (
    <nav className={styles.nav} aria-label="Demo views" data-slot="shell-nav">
      <Link className={styles.home} href="/" aria-label="Home" aria-current={active === 'home' ? 'page' : undefined} data-slot="nav-home">
        <CoquicLogoIcon className="size-8" aria-hidden="true" />
      </Link>
      <div className={styles.desktopContent} data-shell-desktop>
        <span className={styles.navLinks} data-shell-primary-nav>
          {primaryViews.map((view) => <NavLink key={view.href} view={view} active={active} />)}
          <Disclosure id="benchmark" label="Benchmark" active={active} isActive={activeBenchmark} openMenu={openMenu} setOpenMenu={setOpenMenu} views={benchmarkViews} />
          <Disclosure id="development" label="Development" active={active} isActive={activeDevelopment} openMenu={openMenu} setOpenMenu={setOpenMenu} views={developmentViews} />
        </span>
        <span className={styles.navIconActions} data-slot="nav-actions">
          <SiteSearch />
          <ThemeToggle />
          <a className={styles.iconLink} href="https://www.minhuw.dev" target="_blank" rel="noopener noreferrer" aria-label="Minhu Wang contact page"><Contact aria-hidden="true" /></a>
          <a className={styles.iconLink} href="https://github.com/minhuw/coquic" target="_blank" rel="noopener noreferrer" aria-label="CoQUIC on GitHub"><GitHubIcon /></a>
        </span>
      </div>
      <div className={styles.mobileActions} data-shell-mobile>
        <SiteSearch enableShortcut={false} />
        <ThemeToggle />
        <Dialog>
          <DialogTrigger asChild><Button className={styles.iconButton} variant="ghost" size="icon" type="button" aria-label="Open menu" data-shell-control="mobile-menu-trigger"><Menu aria-hidden="true" /></Button></DialogTrigger>
          <DialogContent className={styles.drawer} aria-describedby={undefined}>
            <div className={styles.drawerHeader}>
              <DialogTitle>CoQUIC navigation</DialogTitle>
              <DialogClose className={styles.iconButton} aria-label="Close menu"><X aria-hidden="true" /></DialogClose>
            </div>
            <div className={styles.drawerLinks} data-slot="mobile-nav-links">
              {views.map((view) => <NavLink key={view.href} view={view} active={active} drawer />)}
              <a className={styles.drawerLink} href="https://github.com/minhuw/coquic" target="_blank" rel="noopener noreferrer"><GitHubIcon /> GitHub</a>
              <a className={styles.drawerLink} href="https://www.minhuw.dev" target="_blank" rel="noopener noreferrer"><Contact /> Contact</a>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </nav>
  );
}

function NavLink({ view, active, drawer = false, menu = false, onSelect }: { view: (typeof views)[number]; active: DemoRoute; drawer?: boolean; menu?: boolean; onSelect?: () => void }) {
  return <Link className={drawer ? styles.drawerLink : menu ? styles.menuLink : styles.link} href={view.href} aria-current={active === view.route ? 'page' : undefined} onClick={onSelect} data-slot={drawer ? 'mobile-nav-link' : menu ? 'nav-menu-link' : 'nav-link'}>{view.label}</Link>;
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
    <span className={`${styles.menu}${isActive ? ` ${styles.menuActive}` : ''}`} data-open={open ? 'true' : undefined} data-slot="nav-menu">
      <Button ref={triggerRef} className={`${styles.link} ${styles.menuTrigger}`} variant="ghost" type="button" aria-expanded={open} aria-current={isActive ? 'page' : undefined} onClick={() => open ? closeMenu() : setOpenMenu(id)} data-shell-control="nav-menu-trigger">
        {label}<ChevronDown aria-hidden="true" />
      </Button>
      <span className={styles.menuContent} data-slot="nav-menu-content">
        {menuViews.map((view) => <NavLink key={view.href} view={view} active={active} menu onSelect={closeMenu} />)}
      </span>
    </span>
  );
}

export { routeForPath };
