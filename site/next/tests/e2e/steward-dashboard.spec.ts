import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const viewHeadings = {
  overview: 'Operations state',
  tasks: 'Tasks',
  signals: 'Signals',
  audit: 'Audit findings',
  configuration: 'Public configuration',
} as const;

test.describe('Steward dashboard', () => {
  test('leads with one page identity and the current runtime conclusion', async ({ page }) => {
    await page.goto('/steward');

    await expect(page.locator('h1')).toHaveCount(1);
    await expect(page.getByRole('heading', { level: 1, name: 'CoQUIC Steward' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Steward runtime status' })).toBeVisible();
    for (const label of ['Monitor freshness', 'Daemon state', 'Heartbeat', 'Current cycle', 'Last publication', 'Pending signals', 'Active task']) {
      await expect(page.getByText(label, { exact: true })).toBeVisible();
    }
    await expect(page.getByRole('region', { name: 'Steward runtime status' }).getByText('Live', { exact: true })).toBeVisible();
  });

  test('keeps desktop tabs vertical, complete, and keyboard accessible', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/steward');

    const tablist = page.getByRole('tablist', { name: 'Steward views' });
    await expect(tablist).toHaveAttribute('aria-orientation', 'vertical');
    for (const [value, heading] of Object.entries(viewHeadings)) {
      const tab = page.getByRole('tab', { name: new RegExp(`^${value === 'overview' ? 'State' : value === 'configuration' ? 'Config' : value[0].toUpperCase() + value.slice(1)}`) });
      await tab.click();
      await expect(tab).toHaveAttribute('aria-selected', 'true');
      await expect(page.getByRole('heading', { level: 2, name: heading })).toBeVisible();
    }
    await expect(page.getByRole('link', { name: 'Planner' })).toHaveAttribute('href', '/steward/planner');

    const tasks = page.getByRole('tab', { name: /^Tasks/ });
    await tasks.focus();
    await tasks.press('ArrowLeft');
    await expect(page.getByRole('tab', { name: /^State/ })).toHaveAttribute('aria-selected', 'true');
    await page.getByRole('tab', { name: /^State/ }).press('End');
    await expect(page.getByRole('tab', { name: /^Config/ })).toHaveAttribute('aria-selected', 'true');
  });

  test('uses a labeled native mobile selector and keeps all dashboard actions reachable', async ({ page }) => {
    for (const viewport of [
      { width: 320, height: 760 },
      { width: 375, height: 812 },
      { width: 414, height: 896 },
      { width: 844, height: 390 },
    ]) {
      await page.setViewportSize(viewport);
      await page.goto('/steward');
      const select = page.locator('#steward-view-select');
      await expect(select).toBeVisible();
      await expect(page.getByRole('tablist', { name: 'Steward views' })).toHaveCount(0);
      for (const [value, heading] of Object.entries(viewHeadings)) {
        await select.selectOption(value);
        await expect(page.getByRole('heading', { level: 2, name: heading })).toBeVisible();
      }
      await expect(page.getByRole('link', { name: 'Planner' })).toBeVisible();

      const layout = await page.locator('.steward-dashboard-page').evaluate((root) => {
        const visible = [...root.querySelectorAll('button, select, a')].filter((element) => {
          const style = window.getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
        });
        return {
          controls: visible.map((element) => {
            const rect = element.getBoundingClientRect();
            return {
              label: element.textContent?.trim() || element.getAttribute('aria-label') || element.tagName,
              bottom: rect.bottom,
              height: rect.height,
              right: rect.right,
            };
          }),
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth: window.innerWidth,
        };
      });
      expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth + 1);
      expect(layout.controls.filter((control) => control.right > layout.viewportWidth + 1)).toEqual([]);
      expect(layout.controls.filter((control) => control.height < 44)).toEqual([]);
    }
  });

  test('retains every surface layout after legacy Steward rules are removed', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/steward');
    await expect(page.locator('[data-steward-module="dashboard"]')).toBeVisible();
    await removeLegacySurfaceRules(page, 'dashboard', '.steward-dashboard');
    await expect(page.locator('#steward-view-select')).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Steward views' })).toHaveCount(0);
    await expect(page.locator('.steward-dashboard-workspace')).toHaveCSS('display', 'grid');

    await page.goto('/steward/planner');
    await expect(page.locator('.steward-planner-pagination')).toBeVisible();
    await removeLegacySurfaceRules(page, 'planner', '.steward-planner');
    await expect(page.locator('.steward-planner-pagination')).toHaveCSS('display', 'grid');
    for (const button of await page.locator('.steward-planner-pagination button').all()) {
      expect((await button.boundingBox())?.height).toBeGreaterThanOrEqual(40);
    }

    await page.goto('/steward/tasks/task-20260713115945-a1b2c3d4');
    await expect(page.locator('[data-steward-module="task"]')).toBeVisible();
    await removeLegacySurfaceRules(page, 'task', '.steward-public-page');
    await expect(page.locator('.pipeline-graph')).toBeHidden();
    await expect(page.getByRole('list', { name: 'Task pipeline stages and feedback loops' })).toBeVisible();
    await expect(page.locator('.task-page-shell')).toHaveCSS('display', 'grid');
  });

  test('keeps local table and graph overflow contained and passes serious Axe checks', async ({ page }) => {
    await page.goto('/steward');
    const viewSelect = page.locator('#steward-view-select');
    if ((page.viewportSize()?.width ?? 1440) <= 1023) {
      await expect(viewSelect).toBeVisible();
      await viewSelect.selectOption('tasks');
    } else {
      await page.getByRole('tab', { name: /^Tasks/ }).click();
    }
    await expect(page.locator('.steward-dashboard-task-table').getByRole('link', { name: 'Implement dashboard contract', exact: true })).toBeVisible();

    const overflow = await page.locator('.steward-dashboard').evaluate((root) => ({
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: window.innerWidth,
      localScrollRegions: [...root.querySelectorAll('[data-scroll-region]')].map((element) => ({
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      })),
    }));
    expect(overflow.documentWidth).toBeLessThanOrEqual(overflow.viewportWidth + 1);
    expect(overflow.localScrollRegions.every((region) => region.scrollWidth >= region.clientWidth)).toBeTruthy();

    const results = await new AxeBuilder({ page }).include('.steward-dashboard').analyze();
    expect(results.violations.filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')).toEqual([]);
  });

  test('keeps dark, reduced-motion, and zoomed layouts usable', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/steward');
    await expect(page.locator('#steward-view-select')).toBeVisible();

    const reducedMotion = await page.locator('.steward-dashboard').evaluate((root) => getComputedStyle(root.querySelector('[data-testid="steward-dashboard-loading"]') ?? root).animationDuration);
    expect(Number.parseFloat(reducedMotion)).toBeLessThan(1);

    await page.locator('.steward-dashboard-page').evaluate((root) => {
      (root as HTMLElement).style.zoom = '2';
    });
    const zoomed = await page.locator('.steward-dashboard').evaluate((root) => ({
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: window.innerWidth,
      right: root.getBoundingClientRect().right,
    }));
    expect(zoomed.documentWidth).toBeLessThanOrEqual(zoomed.viewportWidth * 2 + 1);
    expect(zoomed.right).toBeLessThanOrEqual(zoomed.viewportWidth * 2 + 1);
  });
});

async function removeLegacySurfaceRules(page: Page, moduleName: string, legacyRoot: string) {
  const moduleClass = await page.locator(`[data-steward-module="${moduleName}"]`).evaluate((element) => (
    [...element.classList].find((className) => className !== `steward-${element.getAttribute('data-steward-module')}-root`) ?? ''
  ));
  expect(moduleClass).not.toBe('');

  const removed = await page.evaluate(({ legacyRootSelector, rootClass }) => {
    type MutableRuleGroup = {
      cssRules: CSSRuleList;
      deleteRule(index: number): void;
    };
    function removeFromGroup(group: MutableRuleGroup): number {
      let count = 0;
      for (let index = group.cssRules.length - 1; index >= 0; index -= 1) {
        const rule = group.cssRules[index];
        if (rule instanceof CSSStyleRule
          && rule.selectorText.includes(legacyRootSelector)
          && !rule.selectorText.includes(`.${rootClass}`)) {
          group.deleteRule(index);
          count += 1;
          continue;
        }
        const nested = rule as CSSRule & Partial<MutableRuleGroup>;
        if (nested.cssRules && typeof nested.deleteRule === 'function') {
          count += removeFromGroup(nested as MutableRuleGroup);
        }
      }
      return count;
    }

    return [...document.styleSheets].reduce((count, sheet) => {
      try {
        return count + removeFromGroup(sheet);
      } catch {
        return count;
      }
    }, 0);
  }, { legacyRootSelector: legacyRoot, rootClass: moduleClass });
  expect(removed).toBeGreaterThan(0);
}
