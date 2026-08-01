import { defineConfig } from '@playwright/test';

const previewBaseURL = process.env.PLAYWRIGHT_BASE_URL;
const fixturePort = process.env.COQUIC_PLAYWRIGHT_PORT ?? '3002';
const baseURL = previewBaseURL ?? `http://127.0.0.1:${fixturePort}`;

export default defineConfig({
  testDir: './tests',
  outputDir: './test-results',
  reporter: 'list',
  ...(previewBaseURL ? {} : {
    webServer: {
      command: 'nix develop -c npm run test:steward -- --playwright-fixture',
      url: baseURL,
      reuseExistingServer: false,
      timeout: 120_000,
    },
  }),
  use: {
    baseURL,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
