import { expect, test, type Page } from '@playwright/test';

import {
  designViewports,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
} from './helpers/design-system';
import { installPerformanceFixture } from './fixtures/performance';

function collectPageErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  return () => expect(errors).toEqual([]);
}

async function loadReadyPerformance(page: Page, path = '/perf-comparison') {
  const fixture = await installPerformanceFixture(page);
  await page.goto(path);
  await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'ready');
  return fixture;
}

test.describe('performance evidence contracts', () => {
  for (const path of ['/performance', '/perf-comparison']) {
    test(`${path} preserves the route identity and exact data paths`, async ({ page }) => {
      const expectNoPageErrors = collectPageErrors(page);
      const fixture = await loadReadyPerformance(page, path);

      await expect(page.locator('meta[name="coquic-perf-marker"]')).toHaveAttribute('content', 'coquic-perf-comparison-v1');
      await expect(page.locator('#plot-grid')).toHaveCount(1);
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('CoQUIC Performance Comparison');
      await expect(page.locator('#performance-source')).toContainText('nightly-performance');
      await expect(page.locator('#performance-timestamp')).toContainText('2026-07-14');
      await expect(page.locator('#performance-ranking')).toContainText('coquic');
      await expect(page.locator('#performance-current-skeleton')).toBeHidden();
      expect(fixture.requests).toContain('/perf-results.json');
      expect(fixture.requests).toContain('/perf-history/index.json');
      expect(fixture.requests).toContain('/perf-history/2026-07-13.json');
      expect(fixture.requests).toContain('/perf-history/2026-07-14.json');
      expectNoPageErrors();
    });
  }

  test('renders current ranking before delayed history and hydrates trends later', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    const fixture = await installPerformanceFixture(page, { historyDelayMs: 700 });
    await page.goto('/perf-comparison');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#performance-ranking')).toContainText('coquic');
    await expect(page.locator('#performance-history-state')).toHaveAttribute('data-state', 'loading');
    expect(fixture.requests).toContain('/perf-results.json');
    expect(fixture.requests).toContain('/perf-history/index.json');

    await expect(page.locator('#performance-history-state')).toHaveAttribute('data-state', 'ready', { timeout: 5_000 });
    await expect(page.locator('#performance-trend')).toContainText('2026-07-13');
    expectNoPageErrors();
  });

  test('keeps route styling scoped to canonical evidence roles', async ({ page }) => {
    await loadReadyPerformance(page);

    const styles = await page.locator('#performance-page').evaluate((root) => {
      const kicker = root.querySelector<HTMLElement>('[aria-label="Benchmark scope and availability"] span');
      if (!kicker) throw new Error('performance kicker is missing');
      const metadata = [
        ...root.querySelectorAll('[aria-label="Benchmark scope and availability"] dt, [aria-label="Benchmark scope and availability"] dd'),
        root.querySelector('#performance-ranking-unit'),
        root.querySelector('#performance-history-unit'),
      ].filter((element): element is Element => Boolean(element)).map((element) => getComputedStyle(element).fontSize);
      const rootStyle = getComputedStyle(root);
      const themeStyle = getComputedStyle(document.documentElement);
      const dialog = root.querySelector('#perf-detail-dialog');
      return {
        className: root.className,
        letterSpacing: getComputedStyle(kicker).letterSpacing,
        metadata,
        chartValues: Array.from({ length: 6 }, (_, index) => rootStyle.getPropertyValue(`--chart-${index + 1}`).trim()),
        themeChartValues: Array.from({ length: 6 }, (_, index) => themeStyle.getPropertyValue(`--chart-${index + 1}`).trim()),
        modalShadow: dialog ? getComputedStyle(dialog).boxShadow : '',
      };
    });

    expect(styles.className).not.toContain('performance-page');
    expect(['0px', 'normal']).toContain(styles.letterSpacing);
    expect(styles.metadata.every((size) => Number.parseFloat(size) >= 12)).toBe(true);
    expect(styles.chartValues).toEqual(styles.themeChartValues);
    expect(styles.modalShadow).toContain('64px');
    expect(styles.modalShadow).not.toContain('80px');
  });

  test('keeps mode and filter controls stable through keyboard selection', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await loadReadyPerformance(page);

    const tabs = page.getByRole('tab');
    await expect(tabs).toHaveCount(4);
    await tabs.nth(0).focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toBeFocused();
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#performance-ranking-content')).toHaveCount(1);
    await expect(page.locator('#plot-panel')).toHaveAttribute('role', 'tabpanel');
    await expect(page.locator('#performance-ranking')).toContainText('req/s');

    const filterPanel = page.locator('#performance-filter-panel');
    if (await filterPanel.isHidden()) {
      const filterToggle = page.locator('#performance-filter-toggle');
      await filterToggle.focus();
      await page.keyboard.press('Enter');
      await expect(filterPanel).toBeVisible();
    }
    const rust = page.locator('[data-filter-group="languages"] button[data-filter-value="Rust"]');
    await rust.focus();
    const rustButton = rust;
    await page.keyboard.press('Enter');
    await expect(rustButton).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#performance-filter-count')).toHaveText('1 filter active');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#performance-ranking .performance-bar-row')).toHaveCount(1);
    await expect(page.locator('#performance-filter-reset')).toBeEnabled();
    await expect(rustButton).toBeFocused();
    expectNoPageErrors();
  });

  test('uses one mobile filter disclosure and restores focus when it closes', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await page.setViewportSize(designViewports.phone375);
    await loadReadyPerformance(page);

    const toggle = page.locator('#performance-filter-toggle');
    await expect(toggle).toBeVisible();
    await toggle.click();
    await expect(page.locator('#performance-filter-panel')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#performance-filter-panel')).toBeHidden();
    await expect(toggle).toBeFocused();
    expectNoPageErrors();
  });

  test('falls back to legacy history without changing the current result', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    const fixture = await installPerformanceFixture(page, { history: 'legacy' });
    await page.goto('/performance');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#performance-history-state')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#performance-ranking')).toContainText('120.000 MiB/s');
    await expect(page.locator('#performance-trend')).toContainText('2026-07-13');
    expect(fixture.requests).toContain('/perf-history/index.json');
    expect(fixture.requests).toContain('/perf-history.json');
    expect(fixture.requests).not.toContain('/perf-history/2026-07-13.json');
    expectNoPageErrors();
  });

  test('retains current evidence and reports unavailable history', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    const fixture = await installPerformanceFixture(page, { history: 'missing' });
    await page.goto('/perf-comparison');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#performance-history-state')).toHaveAttribute('data-state', 'error');
    await expect(page.locator('#performance-history-state')).toContainText('History unavailable');
    await expect(page.locator('#performance-ranking')).toContainText('120.000 MiB/s');
    await expect(page.locator('#performance-trend')).toContainText('No performance history loaded.');
    expect(fixture.requests).toContain('/perf-history/index.json');
    expect(fixture.requests).toContain('/perf-history.json');
    expectNoPageErrors();
  });

  test('does not present empty fallback rows when current data fails', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await installPerformanceFixture(page, { current: 'missing' });
    await page.goto('/perf-comparison');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'error');
    await expect(page.locator('#performance-current-skeleton')).toBeHidden();
    await expect(page.locator('#performance-ranking')).toContainText('Benchmark data unavailable');
    await expect(page.locator('#performance-ranking')).not.toContainText('120.000 MiB/s');
    await expect(page.locator('#performance-ranking .performance-bar-row')).toHaveCount(0);
    expectNoPageErrors();
  });

  test('reports malformed current and history data as honest states', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await installPerformanceFixture(page, { current: 'malformed', history: 'malformed' });
    await page.goto('/performance');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'error');
    await expect(page.locator('#performance-history-state')).toHaveAttribute('data-state', 'error');
    await expect(page.locator('#performance-ranking')).toContainText('Benchmark data unavailable');
    await expect(page.locator('#performance-ranking .performance-bar-row')).toHaveCount(0);
    expectNoPageErrors();
  });

  test('opens native detail and flamegraph dialogs and restores trigger focus', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    const fixture = await loadReadyPerformance(page);
    const detailTrigger = page.locator('#performance-ranking button[aria-label*="coquic[cubic]"]');
    await expect(detailTrigger).toHaveCount(1);
    await detailTrigger.click();

    const detailDialog = page.locator('#perf-detail-dialog');
    await expect(detailDialog).toBeVisible();
    await expect(detailDialog.getByRole('heading', { name: /coquic\[cubic\] details/i })).toBeVisible();
    await expect(detailDialog.getByRole('link', { name: 'coquic client flamegraph', exact: true })).toHaveAttribute('href', './perf-artifacts/coquic-client.svg');

    const fullscreenTrigger = detailDialog.getByRole('button', { name: /expand .*flamegraph/i }).first();
    await fullscreenTrigger.click();
    const flamegraphDialog = page.locator('#perf-flamegraph-dialog');
    await expect(flamegraphDialog).toBeVisible();
    await expect(flamegraphDialog.locator('iframe')).toHaveAttribute('title', /flamegraph/i);
    await expect(flamegraphDialog.getByRole('link', { name: 'coquic client flamegraph', exact: true })).toHaveAttribute('href', './perf-artifacts/coquic-client.svg');
    await flamegraphDialog.locator('#perf-flamegraph-close').click();
    await expect(flamegraphDialog).toBeHidden();
    await expect(fullscreenTrigger).toBeFocused();
    await detailDialog.locator('#perf-detail-close').click();
    await expect(detailDialog).toBeHidden();
    await expect(detailTrigger).toBeFocused();

    await detailTrigger.click();
    await expect(detailDialog).toBeVisible();
    await detailDialog.locator('#perf-detail-close').click();
    await expect(page.locator('dialog')).toHaveCount(2);
    expect(fixture.requests).toContain('/perf-artifacts/coquic-client.svg');
    expectNoPageErrors();
  });

  test('keeps empty states factual and passes accessibility/overflow checks', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await installPerformanceFixture(page, { current: 'empty', history: 'empty' });
    await page.goto('/perf-comparison');

    await expect(page.locator('#performance-current-state')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#performance-current-state strong')).toHaveText('No completed benchmark rows loaded');
    await expect(page.locator('#performance-ranking .performance-bar-row')).toHaveCount(0);
    await expectNoGlobalOverflow(page);
    await expectNoSeriousAxeViolations(page, '#performance-page');
    expectNoPageErrors();
  });
});
