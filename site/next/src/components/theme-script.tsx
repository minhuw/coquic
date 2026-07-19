'use client';

import { useServerInsertedHTML } from 'next/navigation';
import { useRef } from 'react';

const themeScript = `
(() => {
  try {
    const stored = window.localStorage.getItem('coquic-theme');
    const theme = stored === 'light' || stored === 'dark'
      ? stored
      : window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener('change', () => {
      if (window.localStorage.getItem('coquic-theme')) return;
      const next = media.matches ? 'dark' : 'light';
      document.documentElement.dataset.theme = next;
      document.documentElement.style.colorScheme = next;
    });
  } catch {
    document.documentElement.dataset.theme = 'light';
    document.documentElement.style.colorScheme = 'light';
  }
})();
`;

export function ThemeScript() {
  const inserted = useRef(false);
  useServerInsertedHTML(() => {
    if (inserted.current) return null;
    inserted.current = true;
    return <script id="coquic-theme" dangerouslySetInnerHTML={{ __html: themeScript }} />;
  });
  return null;
}
