
import os from 'node:os';

import { defineConfig, devices } from '@playwright/test';

const defaultPort = 3101;

type PlaywrightEnvironment = {
  [name: string]: string | undefined;
  CI?: string;
  COQUIC_PLAYWRIGHT_PORT?: string;
  COQUIC_PLAYWRIGHT_REUSE_SERVER?: string;
};

function parsePort(value: string) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new Error(`COQUIC_PLAYWRIGHT_PORT must be an integer between 1 and 65535; received ${value}`);
  }
  return parsed;
}

export function createPlaywrightConfig(
  environment: PlaywrightEnvironment = process.env,
) {
  const configuredPort = environment.COQUIC_PLAYWRIGHT_PORT?.trim() || String(defaultPort);
  const port = parsePort(configuredPort);
  const baseURL = `http://127.0.0.1:${port}`;
  const reuseExistingServer = ['1', 'true'].includes(
    environment.COQUIC_PLAYWRIGHT_REUSE_SERVER?.trim().toLowerCase() ?? '',
  );

  return defineConfig({
    testDir: './tests/e2e',
    globalSetup: './tests/e2e/global-setup.ts',
    expect: {
      toHaveScreenshot: {
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
      },
    },
    snapshotPathTemplate: '{testDir}/{testFilePath}-snapshots/{projectName}/{arg}{ext}',
    fullyParallel: true,
    workers: Math.min(12, Math.max(1, Math.floor(os.availableParallelism() / 2))),
    forbidOnly: !!environment.CI,
    retries: environment.CI ? 2 : 0,
    reporter: environment.CI ? 'line' : 'list',
    use: {
      baseURL,
      screenshot: 'only-on-failure',
      trace: 'retain-on-failure',
    },
    projects: [
      {
        name: 'desktop',
        use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
      },
      {
        name: 'mobile',
        use: { ...devices['Pixel 5'], viewport: { width: 375, height: 812 } },
      },
    ],
    webServer: {
      command: `next dev --hostname 127.0.0.1 --port ${port}`,
      reuseExistingServer,
      timeout: 120_000,
      url: baseURL,
    },
  });
}

export default createPlaywrightConfig();
