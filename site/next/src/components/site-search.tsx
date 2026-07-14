'use client';

import dynamic from 'next/dynamic';
import { Search } from 'lucide-react';
import { useEffect, useState } from 'react';

import { Dialog, DialogTrigger } from './ui/dialog';

const SiteSearchDialog = dynamic(() => import('./site-search-dialog').then((module) => module.SiteSearchDialog), { ssr: false });

export function SiteSearch({ enableShortcut = true }: { enableShortcut?: boolean }) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!enableShortcut) return;
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener('keydown', onShortcut);
    return () => document.removeEventListener('keydown', onShortcut);
  }, [enableShortcut]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button className="site-search-trigger" type="button" aria-label="Search" aria-haspopup="dialog">
          <Search aria-hidden="true" />
          <span className="site-search-trigger-label">Search</span>
          <kbd>Ctrl K</kbd>
        </button>
      </DialogTrigger>
      {open ? <SiteSearchDialog /> : null}
    </Dialog>
  );
}
