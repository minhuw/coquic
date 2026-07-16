import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import { defineConfig, devices } from '@playwright/test';

const defaultPort = 3101;

type PlaywrightEnvironment = {
  [name: string]: string | undefined;
  CI?: string;
  COQUIC_PLAYWRIGHT_FIXTURE_ROOT?: string;
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

function defaultFixtureRoot(checkoutRoot: string) {
  const checkoutId = createHash('sha256').update(checkoutRoot).digest('hex').slice(0, 12);
  return path.join(os.tmpdir(), `coquic-steward-playwright-${checkoutId}`);
}

export function createPlaywrightConfig(
  environment: PlaywrightEnvironment = process.env,
  checkoutRoot = process.cwd(),
) {
  const configuredPort = environment.COQUIC_PLAYWRIGHT_PORT?.trim() || String(defaultPort);
  const port = parsePort(configuredPort);
  const configuredFixtureRoot = environment.COQUIC_PLAYWRIGHT_FIXTURE_ROOT;
  const fixtureRoot = configuredFixtureRoot === undefined
    ? defaultFixtureRoot(checkoutRoot)
    : configuredFixtureRoot.trim();
  const baseURL = `http://127.0.0.1:${port}`;
  const reuseExistingServer = ['1', 'true'].includes(
    environment.COQUIC_PLAYWRIGHT_REUSE_SERVER?.trim().toLowerCase() ?? '',
  );

  return defineConfig({
    testDir: './tests/e2e',
    expect: {
      toHaveScreenshot: {
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
      },
    },
    snapshotPathTemplate: '{testDir}/{testFilePath}-snapshots/{projectName}/{arg}{ext}',
    fullyParallel: true,
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
      command: `node scripts/prepare-steward-test-fixture.mjs && next dev --hostname 127.0.0.1 --port ${port}`,
      env: {
        COQUIC_PLAYWRIGHT_FIXTURE_ROOT: fixtureRoot,
        COQUIC_STEWARD_PUBLIC_ROOT: fixtureRoot,
      },
      reuseExistingServer,
      timeout: 120_000,
      url: baseURL,
    },
  });
}

export default createPlaywrightConfig();
