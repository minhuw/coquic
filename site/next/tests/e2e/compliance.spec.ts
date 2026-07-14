import { readFileSync } from 'node:fs';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import {
  emptyCoverage,
  malformedCoverage,
  populatedCoverage,
  zeroCoverage,
} from './fixtures/coverage';
import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
  setStoredTheme,
} from './helpers/design-system';

const duvetReportHtml = readFileSync(path.join(process.cwd(), 'tests/e2e/fixtures/duvet-report.html'), 'utf8');

function coverageJson(value: unknown) {
  return JSON.stringify(value);
}

async function fulfillCoverage(page: Page, body: string, status = 200) {
  await page.route('**/coverage-results.json', (route) =>
    route.fulfill({ body, contentType: 'application/json', status }),
  );
}

async function fulfillDuvetReport(page: Page, headStatus = 200) {
  await page.route('**/duvet/report.html', (route) => {
    if (route.request().method() === 'HEAD') {
      return route.fulfill({ status: headStatus });
    }
    return route.fulfill({ body: duvetReportHtml, contentType: 'text/html', status: 200 });
  });
}

async function expectCoverageActions(page: Page) {
  await expect(page.getByRole('link', { name: 'Open LLVM HTML', exact: true })).toHaveAttribute(
    'href',
    '/coverage/index.html',
  );
  await expect(page.getByRole('link', { name: 'Download JSON', exact: true })).toHaveAttribute(
    'href',
    './coverage-results.json',
  );
}

async function expectDuvetActions(page: Page) {
  await expect(page.getByRole('link', { name: 'Open HTML', exact: true }).first()).toHaveAttribute(
    'href',
    '/duvet/report.html',
  );
  await expect(page.getByRole('link', { name: 'JSON', exact: true })).toHaveAttribute('href', '/duvet/report.json');
  await expect(page.getByRole('link', { name: 'Snapshot', exact: true })).toHaveAttribute(
    'href',
    '/duvet/snapshot.txt',
  );
}

test.describe('coverage and compliance route identity', () => {
  for (const path of ['/coverage-results', '/coverage']) {
    test(`${path} preserves identity and resource actions`, async ({ page }) => {
      await page.goto(path);
      await expect(page).toHaveTitle('CoQUIC Coverage Results');
      await expect(page.getByRole('heading', { name: 'CoQUIC Coverage Report' })).toBeVisible();
      await expect(page.locator('meta[name="coquic-coverage-marker"]')).toHaveAttribute(
        'content',
        'coquic-coverage-results-v1',
      );
      await expectCoverageActions(page);
    });
  }

  test('coverage aliases preserve the canonical heading and actions', async ({ page }) => {
    await page.goto('/coverage-results');
    const canonicalHeading = await page.getByRole('heading', { level: 1 }).innerText();
    await page.goto('/coverage');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(canonicalHeading);
    await expectCoverageActions(page);
  });

  test('Duvet preserves identity and all generated resource actions', async ({ page }) => {
    await page.goto('/duvet');
    await expect(page).toHaveTitle('CoQUIC Duvet RFC Compliance');
    await expect(page.getByRole('heading', { name: 'CoQUIC Duvet Report' })).toBeVisible();
    await expect(page.locator('meta[name="coquic-duvet-marker"]')).toHaveAttribute(
      'content',
      'coquic-duvet-report-v1',
    );
    await expectDuvetActions(page);
  });
});

test.describe('coverage evidence states', () => {
  test('renders populated totals, component order, file order, and long paths', async ({ page }) => {
    await fulfillCoverage(page, coverageJson(populatedCoverage));
    await page.goto('/coverage-results');

    await expect(page.locator('[data-coverage-state]')).toHaveAttribute('data-coverage-state', 'loaded');
    await expect(page.locator('#coverage-source-label')).toContainText('2026-07-14T12:34:56Z');
    await expect(page.locator('#coverage-event')).toHaveText('push');
    await expect(page.locator('#coverage-commit')).toHaveText('012abc345def');

    const metrics = page.locator('[data-coverage-metric]');
    await expect(metrics).toHaveCount(3);
    await expect(metrics.nth(0)).toHaveAttribute('data-metric', 'functions');
    await expect(metrics.nth(0)).toContainText('73.00%');
    await expect(metrics.nth(0)).toContainText('73 / 100');
    await expect(metrics.nth(1)).toHaveAttribute('data-metric', 'lines');
    await expect(metrics.nth(1)).toContainText('84.20%');
    await expect(metrics.nth(2)).toHaveAttribute('data-metric', 'branches');
    await expect(metrics.nth(2)).toContainText('61.00%');
    await expect(page.locator('.metric-card, .metric-bar, [role="progressbar"]')).toHaveCount(0);

    expect(await page.locator('#component-list [data-component-name]').evaluateAll((rows) => rows.map((row) => row.getAttribute('data-component-name')))).toEqual([
      'alpha',
      'zeta',
      'transport',
    ]);
    await expect(page.locator('#file-list [data-file-path]')).toHaveCount(2);
    expect(await page.locator('#file-list [data-file-path]').evaluateAll((rows) => rows.map((row) => row.getAttribute('data-file-path')))).toEqual([
      populatedCoverage.least_covered_files[0].path,
      populatedCoverage.least_covered_files[1].path,
    ]);
    await expect(page.locator('#file-list')).toContainText(
      'packet-parser-with-a-deliberately-long-file-name-that-must-wrap-without-widening-the-page.c',
    );
    await expectCoverageActions(page);
  });

  test('keeps loading geometry stable and announces the loaded result', async ({ page }) => {
    let releaseCoverage: (() => void) | undefined;
    const coverageResponse = new Promise<void>((resolve) => {
      releaseCoverage = resolve;
    });
    await page.route('**/coverage-results.json', async (route) => {
      await coverageResponse;
      return route.fulfill({ body: coverageJson(populatedCoverage), contentType: 'application/json' });
    });
    await page.goto('/coverage-results');

    const report = page.locator('[data-coverage-state]');
    await expect(report).toHaveAttribute('data-coverage-state', 'loading');
    await expect(report).toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('#summary-grid [data-coverage-loading-row]')).toHaveCount(3);
    releaseCoverage?.();
    await expect(report).toHaveAttribute('data-coverage-state', 'loaded');
  });

  test('renders an empty valid report without inventing files or components', async ({ page }) => {
    await fulfillCoverage(page, coverageJson(emptyCoverage));
    await page.goto('/coverage-results');
    await expect(page.locator('[data-coverage-state]')).toHaveAttribute('data-coverage-state', 'loaded-empty');
    await expect(page.locator('#component-list')).toContainText('No component coverage loaded.');
    await expect(page.locator('#file-list')).toContainText('No file coverage loaded.');
  });

  test('distinguishes missing data from valid zero coverage', async ({ page }) => {
    await fulfillCoverage(page, 'not found', 404);
    await page.goto('/coverage-results');
    await expect(page.locator('[data-coverage-state]')).toHaveAttribute('data-coverage-state', 'unavailable');
    await expect(page.locator('#coverage-status')).toContainText('HTTP 404');
    await expect(page.locator('#summary-grid')).not.toContainText('0.00%');
    await expect(page.getByRole('button', { name: 'Retry coverage results' })).toHaveClass(/coverage-inline-action/);

    await page.unroute('**/coverage-results.json');
    await fulfillCoverage(page, coverageJson(zeroCoverage));
    await page.reload();
    await expect(page.locator('[data-coverage-state]')).toHaveAttribute('data-coverage-state', 'loaded');
    await expect(page.locator('#summary-grid')).toContainText('0.00%');
    await expect(page.locator('#summary-grid')).toContainText('0 / 10');
  });

  test('reports malformed JSON without rendering a zero fallback', async ({ page }) => {
    await fulfillCoverage(page, malformedCoverage);
    await page.goto('/coverage-results');
    await expect(page.locator('[data-coverage-state]')).toHaveAttribute('data-coverage-state', 'malformed');
    await expect(page.locator('#coverage-status')).toContainText('invalid coverage-results.json');
    await expect(page.locator('#summary-grid')).not.toContainText('0.00%');
  });
});

test.describe('Duvet report boundary', () => {
  /*
   * Maintenance note: generated Duvet output intentionally remains light and
   * wide in this fixture. Full report theme/mobile normalization belongs to a
   * separately validated generator or postprocessor task.
   */
  test('shows a factual unavailable state when the report probe fails', async ({ page }) => {
    await fulfillDuvetReport(page, 404);
    await page.goto('/duvet');
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'unavailable');
    await expect(page.locator('[data-duvet-reason]')).toContainText('HTTP 404');
    await expect(page.getByRole('button', { name: 'Retry Duvet report' })).toBeVisible();
    await expectDuvetActions(page);
  });

  test('enters ready after the same-origin probe and iframe load', async ({ page }) => {
    await fulfillDuvetReport(page);
    await page.goto('/duvet');
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'ready');
    await expect(page.locator('iframe[title="Duvet RFC compliance report"]')).toHaveCount(1);
    await expectLocalScrollRegion(page, '[data-duvet-frame-region]');
    await expectNoGlobalOverflow(page);
    await expectDuvetActions(page);
    await expect(page.frameLocator('iframe[title="Duvet RFC compliance report"]').getByRole('heading', { name: 'Generated Duvet report fixture' })).toBeVisible();
  });

  test('shows iframe errors as unavailable while retaining report actions', async ({ page }) => {
    await page.route('**/duvet/report.html', (route) => {
      if (route.request().method() === 'HEAD') return route.fulfill({ status: 200 });
      return route.fulfill({ body: duvetReportHtml, contentType: 'text/html', status: 200 });
    });
    await page.goto('/duvet');
    await expect(page.locator('iframe[title="Duvet RFC compliance report"]')).toHaveCount(1);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'ready');
    await page.locator('iframe[title="Duvet RFC compliance report"]').evaluate((frame: HTMLIFrameElement) => {
      frame.src = 'http://127.0.0.1:1/unreachable-duvet-report';
    });
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'unavailable');
    await expect(page.locator('[data-duvet-reason]')).toContainText('could not be loaded');
    await expect(page.getByRole('button', { name: 'Retry Duvet report' })).toBeVisible();
    await expectDuvetActions(page);
  });

  test('enters delayed at exactly 15 seconds and accepts a late iframe load', async ({ page }) => {
    await page.clock.install();
    let releaseReport: (() => void) | undefined;
    const reportHeld = new Promise<void>((resolve) => {
      releaseReport = resolve;
    });
    await page.route('**/duvet/report.html', async (route) => {
      if (route.request().method() === 'HEAD') return route.fulfill({ status: 200 });
      await reportHeld;
      return route.fulfill({ body: duvetReportHtml, contentType: 'text/html', status: 200 });
    });
    await page.goto('/duvet');
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'loading');
    const firstAttemptTime = await page.evaluate(() => Date.now());
    await page.clock.pauseAt(firstAttemptTime + 14_000);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'loading');
    await page.clock.pauseAt(firstAttemptTime + 15_000);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'delayed');
    await expect(page.getByRole('button', { name: 'Retry Duvet report' })).toBeVisible();
    await expectDuvetActions(page);
    releaseReport?.();
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'ready');
  });

  test('retry resets the attempt once and does not retain the old delayed timer', async ({ page }) => {
    await page.clock.install();
    let headRequests = 0;
    let reportRequests = 0;
    const releaseReports: Array<() => void> = [];
    await page.route('**/duvet/report.html', async (route) => {
      if (route.request().method() === 'HEAD') {
        headRequests += 1;
        return route.fulfill({ status: 200 });
      }
      reportRequests += 1;
      await new Promise<void>((resolve) => releaseReports.push(resolve));
      return route.fulfill({ body: duvetReportHtml, contentType: 'text/html', status: 200 });
    });
    await page.goto('/duvet');
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'loading');
    const firstAttemptTime = await page.evaluate(() => Date.now());
    await page.clock.pauseAt(firstAttemptTime + 15_000);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'delayed');
    await page.getByRole('button', { name: 'Retry Duvet report' }).click();
    await expect.poll(() => headRequests).toBe(2);
    await expect.poll(() => reportRequests).toBe(2);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'loading');
    const retryAttemptTime = await page.evaluate(() => Date.now());
    await page.clock.pauseAt(retryAttemptTime + 14_999);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'loading');
    await page.clock.pauseAt(retryAttemptTime + 15_000);
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'delayed');
    expect(headRequests).toBe(2);
    releaseReports.forEach((release) => release());
  });

  test('contains a wide generated document without parent overflow or iframe injection', async ({ page }) => {
    await page.setViewportSize(designViewports.phone320);
    await setStoredTheme(page, 'light');
    await fulfillDuvetReport(page);
    await page.goto('/duvet');
    await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'ready');
    await expectNoGlobalOverflow(page);
    await expectNoSeriousAxeViolations(page, 'main');
    await expect(page.locator('iframe[title="Duvet RFC compliance report"]')).toHaveAttribute('src', '/duvet/report.html');
    await expect(page.locator('[data-duvet-frame-region]')).toHaveAttribute('tabindex', '0');

    const frame = page.frames().find((candidate) => candidate.url().endsWith('/duvet/report.html'));
    expect(frame).toBeDefined();
    const generatedBoundary = await frame!.evaluate(() => ({
      bodyClass: document.body.className,
      documentTheme: document.documentElement.dataset.theme,
      reportStyles: document.querySelectorAll('style').length,
      reportScripts: document.querySelectorAll('script').length,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(generatedBoundary).toMatchObject({ bodyClass: '', documentTheme: undefined, reportStyles: 1, reportScripts: 0 });
    expect(generatedBoundary.scrollWidth).toBeGreaterThan(320);
  });

  test('keeps the wrapper visually theme-aware and actions keyboard reachable', async ({ page }) => {
    await fulfillDuvetReport(page);
    const surfaces: Record<string, string> = {};
    for (const theme of ['light', 'dark'] as const) {
      await page.goto('/duvet');
      await page.evaluate((nextTheme) => {
        window.sessionStorage.removeItem('coquic-playwright-theme-initialized');
        window.localStorage.setItem('coquic-theme', nextTheme);
      }, theme);
      await page.reload();
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.locator('[data-duvet-state]')).toHaveAttribute('data-duvet-state', 'ready');
      surfaces[theme] = await page.locator('[data-duvet-frame-region]').evaluate((element) => getComputedStyle(element).backgroundColor);
      const actions = page.locator('.compliance-actions a');
      for (let index = 0; index < await actions.count(); index += 1) {
        const bounds = await actions.nth(index).boundingBox();
        expect(bounds?.height).toBeGreaterThanOrEqual(44);
      }
    }
    expect(surfaces.light).not.toBe(surfaces.dark);
  });
});
