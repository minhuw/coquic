import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

import type { PublicPlannerRun, PublicStewardMonitor } from '../../src/generated/steward-public';
import { expectNoGlobalOverflow } from './helpers/design-system';

test.describe('Steward planner history', () => {
  test('keeps the published order, pagination boundaries, and native artifact disclosure', async ({ page }, testInfo) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async (text: string) => window.localStorage.setItem('steward-planner-copied-text', text),
        },
      });
    });
    const monitor = await interceptPlanner(page, 11);
    await page.goto('/steward/planner');

    await expect(page.getByRole('heading', { level: 1, name: 'Planner history' })).toHaveCount(1);
    const firstPage = page.getByRole('article');
    await expect(firstPage).toHaveCount(10);
    await expect(firstPage.first().getByRole('heading')).toHaveText(monitor.planner_runs[0]?.id ?? '');
    await expect(firstPage.last().getByRole('heading')).toHaveText(monitor.planner_runs[9]?.id ?? '');
    await expect(page.getByRole('button', { name: 'Previous planner history page' })).toBeDisabled();

    const disclosure = firstPage.first().locator('summary');
    await disclosure.focus();
    await disclosure.press('Enter');
    await expect(firstPage.first().getByText('artifact transcript 1')).toBeVisible();
    const transcript = firstPage.first().getByRole('region', { name: 'Transcript artifact' });
    const artifactText = transcript.getByRole('region', { name: 'Transcript code' });
    const code = artifactText.locator('pre');
    await expect(code).toHaveCSS('white-space', 'pre');
    const codeGeometry = await artifactText.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
      tabIndex: element.tabIndex,
    }));
    expect(codeGeometry.scrollWidth).toBeGreaterThan(codeGeometry.clientWidth);
    expect(codeGeometry.tabIndex).toBeGreaterThanOrEqual(0);
    await artifactText.focus();
    await expect(artifactText).toBeFocused();
    await artifactText.press('ArrowRight');
    await expect.poll(() => artifactText.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);

    const copy = transcript.locator('[data-evidence-code-block="true"]').getByRole('button');
    await expect(copy).toBeVisible();
    await expect(copy).toHaveAccessibleName('Copy code');
    if (testInfo.project.name === 'mobile') {
      const copyTarget = await copy.boundingBox();
      expect(copyTarget?.width).toBeGreaterThanOrEqual(44);
      expect(copyTarget?.height).toBeGreaterThanOrEqual(44);
    }
    await copy.click();
    await expect(copy).toHaveAccessibleName('Code copied');
    const expectedTranscript = monitor.planner_runs[0]?.artifacts.transcript?.text;
    expect(expectedTranscript).toBeTruthy();
    await expect.poll(() => page.evaluate(() => window.localStorage.getItem('steward-planner-copied-text')))
      .toBe(expectedTranscript);

    await page.getByRole('button', { name: 'Next planner history page' }).click();
    await expect(page.getByText('Page 2 of 2')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Previous planner history page' })).toBeFocused();
    await expect(page.getByRole('article')).toHaveCount(1);
    await expect(page.getByRole('article').getByRole('heading')).toHaveText(monitor.planner_runs[10]?.id ?? '');
    await expect(page.getByRole('button', { name: 'Next planner history page' })).toBeDisabled();
  });

  test('fits at mobile width and has no serious accessibility violations', async ({ page }) => {
    await interceptPlanner(page, 4);
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/steward/planner');
    await expect(page.getByRole('article')).toHaveCount(4);

    await expectNoGlobalOverflow(page);

    const results = await new AxeBuilder({ page }).include('.steward-planner-page').analyze();
    expect(results.violations.filter(({ impact }) => impact === 'serious' || impact === 'critical')).toEqual([]);
  });

  test('retains evidence geometry in dark, reduced-motion, forced-color, and zoom-width modes', async ({ page }) => {
    await page.addInitScript(() => window.localStorage.setItem('coquic-theme', 'dark'));
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await interceptPlanner(page, 4);
    await page.setViewportSize({ width: 720, height: 900 });
    await page.goto('/steward/planner');

    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.getByRole('article')).toHaveCount(4);
    await expectNoGlobalOverflow(page);
    const spinnerMotion = await page.locator('.steward-planner-spinner').first().evaluate(
      (element) => ({
        durationSeconds: Number.parseFloat(getComputedStyle(element).animationDuration),
        iterations: getComputedStyle(element).animationIterationCount,
      }),
    );
    expect(spinnerMotion.durationSeconds).toBeLessThan(0.001);
    expect(spinnerMotion.iterations).toBe('1');

    await page.emulateMedia({ colorScheme: 'dark', forcedColors: 'active', reducedMotion: 'reduce' });
    await expect(page.getByRole('heading', { name: 'Planner history' })).toBeVisible();
    await expectNoGlobalOverflow(page);
  });

  test('has no global overflow at required viewport extremes', async ({ page }) => {
    await interceptPlanner(page, 4);
    await page.goto('/steward/planner');
    await expect(page.getByRole('article')).toHaveCount(4);

    for (const viewport of [
      { width: 320, height: 800 },
      { width: 414, height: 896 },
      { width: 768, height: 1024 },
      { width: 844, height: 390 },
      { width: 1024, height: 768 },
    ]) {
      await page.setViewportSize(viewport);
      await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())));
      await expectNoGlobalOverflow(page);
    }
  });
});

async function interceptPlanner(page: Page, count: number) {
  const monitor = await loadMonitor(page);
  monitor.planner_runs = Array.from({ length: count }, (_, index) => plannerRun(index + 1));
  monitor.planner_runs_truncated = true;
  await page.route('**/steward/status', (route) => route.fulfill({ json: monitor }));
  return monitor;
}

async function loadMonitor(page: Page) {
  const response = await page.request.get('/steward/status');
  return await response.json() as PublicStewardMonitor;
}

function plannerRun(index: number): PublicPlannerRun {
  return {
    id: `planner-e2e-${String(index).padStart(2, '0')}-${'long-id-'.repeat(5)}`,
    status: index === 1 ? 'running' : index === 2 ? 'failed' : index === 3 ? 'invalid' : 'succeeded',
    started_at: '2026-07-13T11:50:00Z',
    completed_at: index === 1 ? null : '2026-07-13T11:50:30Z',
    accepted_count: index % 3,
    proposed_count: index,
    consumed_signal_ids: [`wi-${'long-signal-'.repeat(8)}${index}`],
    diagnostics: {
      summary: index === 3 ? '' : `diagnostic ${index}`,
      exit_code: index === 1 ? null : index === 2 ? 1 : 0,
      error_category: index === 2 ? 'provider_error' : index === 3 ? 'invalid_output' : 'none',
      last_message_present: index !== 3,
    },
    artifacts: {
      transcript: {
        availability: index === 3 ? 'redacted' : 'available',
        mode: 'redacted',
        text: index === 3 ? '' : `artifact transcript ${index}\ncolumn  one    two\n${'unbroken-artifact-content-'.repeat(20)}`,
        size_bytes: 600,
        original_size_bytes: index === 3 ? 1200 : 600,
        truncated: index === 3,
        sha256: null,
        url: null,
      },
      last_message: index === 2 ? null : {
        availability: 'available',
        mode: 'redacted',
        text: `last message ${index}`,
        size_bytes: 16,
        original_size_bytes: 16,
        truncated: false,
        sha256: null,
        url: null,
      },
    },
  };
}
