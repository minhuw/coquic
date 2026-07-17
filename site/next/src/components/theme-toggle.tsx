'use client';

import { Moon, Sun } from 'lucide-react';
import { useEffect, useState } from 'react';

import styles from './theme-toggle.module.css';

type Theme = 'light' | 'dark';

function preferredTheme(): Theme {
  if (typeof window === 'undefined') return 'light';
  const stored = window.localStorage.getItem('coquic-theme');
  if (stored === 'light' || stored === 'dark') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme: Theme, persist: boolean) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  if (persist) window.localStorage.setItem('coquic-theme', theme);
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('light');

  useEffect(() => {
    setTheme(preferredTheme());
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => {
      if (!window.localStorage.getItem('coquic-theme')) {
        const next = media.matches ? 'dark' : 'light';
        setTheme(next);
        applyTheme(next, false);
      }
    };
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    applyTheme(next, true);
  }

  const dark = theme === 'dark';

  return (
    <button
      // Retained for the visual foundation selector; presentation is module-owned.
      className={`theme-toggle ${styles.toggle}`}
      type="button"
      aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-pressed={dark}
      data-slot="theme-toggle"
      onClick={toggleTheme}
      title={dark ? 'Light mode' : 'Dark mode'}
    >
      {dark ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
    </button>
  );
}
