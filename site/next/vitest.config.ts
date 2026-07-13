import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const siteRoot = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.join(siteRoot, 'src'),
      '@app': path.join(siteRoot, 'app'),
    },
  },
  test: {
    clearMocks: true,
    environment: 'jsdom',
    include: ['tests/**/*.test.{ts,tsx}'],
    restoreMocks: true,
    setupFiles: ['./tests/setup.ts'],
  },
});
