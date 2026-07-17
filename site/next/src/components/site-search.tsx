'use client';

import dynamic from 'next/dynamic';
import { Search } from 'lucide-react';
import { useEffect, useState } from 'react';

import styles from './site-search.module.css';
import { Button } from './ui/button';
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
        <Button className={styles.trigger} variant="ghost" type="button" aria-label="Search" aria-haspopup="dialog" data-shell-control="site-search-trigger">
          <Search aria-hidden="true" />
          <span className={styles.triggerLabel}>Search</span>
          <kbd className={styles.triggerKbd}>Ctrl K</kbd>
        </Button>
      </DialogTrigger>
      {open ? <SiteSearchDialog /> : null}
    </Dialog>
  );
}
