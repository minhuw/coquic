import { spawnSync } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { createPlaywrightConfig } from '../playwright.config';

const fixtureScript = path.resolve(process.cwd(), 'scripts/prepare-steward-test-fixture.mjs');

function webServer(config: ReturnType<typeof createPlaywrightConfig>) {
  const server = config.webServer;
  if (!server || Array.isArray(server)) throw new Error('Expected one Playwright web server');
  return server;
}

describe('Playwright isolation configuration', () => {
  it('uses checkout-unique defaults and disables server reuse', () => {
    const first = createPlaywrightConfig({}, '/tmp/coquic-checkout-a');
    const second = createPlaywrightConfig({}, '/tmp/coquic-checkout-b');
    const firstServer = webServer(first);
    const secondServer = webServer(second);

    expect(first.use?.baseURL).toBe('http://127.0.0.1:3101');
    expect(firstServer.url).toBe('http://127.0.0.1:3101');
    expect(firstServer.command).toContain('--port 3101');
    expect(firstServer.reuseExistingServer).toBe(false);
    expect(firstServer.env?.COQUIC_PLAYWRIGHT_FIXTURE_ROOT?.startsWith(
      path.join(os.tmpdir(), 'coquic-steward-playwright-'),
    )).toBe(true);
    expect(firstServer.env?.COQUIC_PLAYWRIGHT_FIXTURE_ROOT)
      .not.toBe(secondServer.env?.COQUIC_PLAYWRIGHT_FIXTURE_ROOT);
  });

  it('uses one overridden port and root throughout and requires reuse opt-in', () => {
    const fixtureRoot = path.join(os.tmpdir(), 'coquic-steward-playwright-config-test');
    const config = createPlaywrightConfig({
      COQUIC_PLAYWRIGHT_FIXTURE_ROOT: fixtureRoot,
      COQUIC_PLAYWRIGHT_PORT: '3202',
      COQUIC_PLAYWRIGHT_REUSE_SERVER: 'true',
    });
    const server = webServer(config);

    expect(config.use?.baseURL).toBe('http://127.0.0.1:3202');
    expect(server.url).toBe('http://127.0.0.1:3202');
    expect(server.command).toContain('--port 3202');
    expect(server.env).toMatchObject({
      COQUIC_PLAYWRIGHT_FIXTURE_ROOT: fixtureRoot,
      COQUIC_STEWARD_PUBLIC_ROOT: fixtureRoot,
    });
    expect(server.reuseExistingServer).toBe(true);
  });

  it('rejects invalid ports before starting Playwright', () => {
    expect(() => createPlaywrightConfig({ COQUIC_PLAYWRIGHT_PORT: '3202; exit 0' }))
      .toThrow(/must be an integer between 1 and 65535/);
  });

  it.each([
    ['an empty root', ''],
    ['the filesystem root', path.parse(os.tmpdir()).root],
    ['the temporary root', os.tmpdir()],
    ['a normalized alias of the temporary root', path.join(os.tmpdir(), 'fixture', '..')],
    ['a path outside the temporary root', process.cwd()],
  ])('rejects %s before fixture deletion', (_label, unsafeRoot) => {
    const result = spawnSync(process.execPath, [fixtureScript], {
      encoding: 'utf8',
      env: { ...process.env, COQUIC_PLAYWRIGHT_FIXTURE_ROOT: unsafeRoot },
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/must not be empty|must be a child of a temporary directory/);
  });

  it('rejects an existing parent symlink that resolves outside the temporary root', async () => {
    const outsideRoot = await mkdtemp(path.join(process.cwd(), '.playwright-fixture-target-'));
    const victim = path.join(outsideRoot, 'victim');
    const sentinel = path.join(victim, 'sentinel');
    const linkedParent = path.join(os.tmpdir(), `coquic-playwright-link-${process.pid}`);
    await mkdir(victim);
    await writeFile(sentinel, 'preserve');
    await rm(linkedParent, { force: true });
    await symlink(outsideRoot, linkedParent, 'dir');

    try {
      const result = spawnSync(process.execPath, [fixtureScript], {
        encoding: 'utf8',
        env: {
          ...process.env,
          COQUIC_PLAYWRIGHT_FIXTURE_ROOT: path.join(linkedParent, 'victim'),
        },
      });

      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/must not resolve outside the temporary directory/);
      await expect(access(sentinel)).resolves.toBeUndefined();
    } finally {
      await rm(linkedParent, { force: true });
      await rm(outsideRoot, { force: true, recursive: true });
    }
  });
});
