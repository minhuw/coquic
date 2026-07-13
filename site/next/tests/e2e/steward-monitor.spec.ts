import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function expectNoSeriousAccessibilityViolations(page: Page) {
  const selector = stewardViewSelector(page);
  const results = await new AxeBuilder({ page }).include(selector).analyze();
  expect(results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')).toEqual([]);
}

function stewardViewSelector(page: Page) {
  const route = new URL(page.url()).pathname;
  return route === '/steward'
    ? '.steward-mirror-shell'
    : route === '/steward/planner'
      ? '.steward-planner-page'
      : '.task-page-frame';
}

test.describe('Steward public monitor', () => {
  test('renders the active overview and runtime state', async ({ page }) => {
    await page.goto('/steward');
    await expect(page.getByRole('heading', { name: 'CoQUIC Steward' })).toBeVisible();
    await expect(page.getByText('Monitor')).toBeVisible();
    await expect(page.getByRole('region', { name: 'Steward runtime status' }).getByText('Live', { exact: true })).toBeVisible();
    await expect(page.getByText('Daemon')).toBeVisible();
  });

  test('switches between task and signal views', async ({ page }) => {
    await page.goto('/steward');
    await page.getByRole('tab', { name: /Tasks/ }).click();
    await expect(page.getByRole('link', { name: 'Implement dashboard contract', exact: true })).toBeVisible();
    await page.getByRole('tab', { name: /Signals/ }).click();
    await expect(page.getByText('Contract checks are running')).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Signal providers' }).getByRole('tab', { name: /github-actions:ci/ })).toBeVisible();
  });

  test('renders planner history and a retained task detail', async ({ page }) => {
    await page.goto('/steward/planner');
    await expect(page.getByRole('heading', { name: 'Planner history' })).toBeVisible();
    await expect(page.getByText('planner-task-20260713115600-a1b2c3d4')).toBeVisible();

    await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
    await expect(page.getByRole('heading', { name: 'Implement dashboard contract' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worktree ready', level: 3 })).toBeVisible();
    await expect(page.getByText('Timeline')).toBeVisible();
  });

  test('keeps operational controls inside the viewport', async ({ page }) => {
    await page.goto('/steward');
    const overflow = await page.evaluate(() => ({
      document: document.documentElement.scrollWidth,
      viewport: window.innerWidth,
      controls: [...document.querySelectorAll('.steward-mirror-shell button, .steward-mirror-shell a, .steward-mirror-shell input')]
        .filter((element) => element.getBoundingClientRect().right > window.innerWidth + 1)
        .map((element) => element.textContent?.trim() || element.getAttribute('aria-label') || element.tagName),
    }));
    expect(overflow.document).toBeLessThanOrEqual(overflow.viewport + 1);
    expect(overflow.controls).toEqual([]);
  });

  test('supports keyboard-only monitor, task, and diff workflows', async ({ page }) => {
    await page.goto('/steward');
    const tasksTab = page.getByRole('tab', { name: /Tasks/ });
    await tasksTab.focus();
    await tasksTab.press('ArrowLeft');
    await expect(page.getByRole('tab', { name: /State/ })).toHaveAttribute('aria-selected', 'true');
    await page.getByRole('tab', { name: /State/ }).press('End');
    await expect(page.getByRole('tab', { name: /Config/ })).toHaveAttribute('aria-selected', 'true');

    await page.goto('/steward/planner');
    await expect(page.getByRole('heading', { name: 'Planner history' })).toBeVisible();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');

    await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
    await expect(page.getByRole('heading', { name: 'Implement dashboard contract' })).toBeVisible();
    const attempt = page.getByRole('button', { name: /Initial attempt/ });
    await attempt.focus();
    await attempt.press('Enter');
    await attempt.press('Enter');
    const transcriptTab = page.getByRole('tab', { name: 'Transcript' });
    await transcriptTab.focus();
    await transcriptTab.press('ArrowRight');
    await expect(page.getByRole('tab', { name: 'Patch' })).toHaveAttribute('aria-selected', 'true');
    const openDiff = page.getByRole('button', { name: 'Open side-by-side diff' });
    await openDiff.focus();
    await openDiff.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Patch side-by-side' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(openDiff).toBeFocused();
  });

  test('has no serious accessibility violations on retained monitor views', async ({ page }) => {
    for (const route of [
      '/steward',
      '/steward/planner',
      '/steward/tasks/task-20260713115945-a1b2c3d4',
    ]) {
      await page.goto(route);
      await expect(page.locator(stewardViewSelector(page))).toBeVisible();
      await expectNoSeriousAccessibilityViolations(page);
    }
  });
});
