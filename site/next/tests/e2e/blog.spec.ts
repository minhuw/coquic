import { expect, test } from '@playwright/test';

import { expectNoGlobalOverflow, expectNoSeriousAxeViolations, setStoredTheme, waitForVisualAssets } from './helpers/design-system';

const themes = ['light', 'dark'] as const;

async function prepareVisualSnapshot(page: Parameters<typeof setStoredTheme>[0]) {
  await waitForVisualAssets(page);
}

test.describe('blog characterization', () => {
  test.describe.configure({ mode: 'default' });

  test('lists both known posts in descending date order with metadata and links', async ({ page }) => {
    await page.goto('/blog');

    const articles = page.getByRole('article');
    await expect(articles).toHaveCount(2);
    await expect(articles.nth(0).getByRole('heading', { level: 2 })).toHaveText(
      'CoQUIC Steward: Letting an Agent Maintain the Repository',
    );
    await expect(articles.nth(1).getByRole('heading', { level: 2 })).toHaveText('Why CoQUIC?');
    await expect(articles.nth(0).getByRole('link')).toHaveAttribute('href', '/blog/coquic-steward');
    await expect(articles.nth(1).getByRole('link')).toHaveAttribute('href', '/blog/why-coquic');

    for (const article of [articles.nth(0), articles.nth(1)]) {
      await expect(article.locator('time')).toHaveCount(1);
      await expect(article).toContainText('min read');
      await expect(article).toContainText('Minhu Wang');
      await expect(article.locator('.blog-tags span')).not.toHaveCount(0);
    }
    await expect(articles.nth(0)).toContainText('Written by Claude Fable 5');
    await expect(articles.nth(1)).toContainText('Polished by GPT');
  });

  for (const theme of themes) {
    test(`the index and representative post match the ${theme} visual baseline`, async ({ page }) => {
      await setStoredTheme(page, theme);
      await page.goto('/blog');
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.getByRole('article')).toHaveCount(2);
      await prepareVisualSnapshot(page);
      await expect(page).toHaveScreenshot(`blog-index-${theme}.png`, { fullPage: false });

      await page.goto('/blog/coquic-steward');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(
        'CoQUIC Steward: Letting an Agent Maintain the Repository',
      );
      await prepareVisualSnapshot(page);
      await expect(page).toHaveScreenshot(`blog-post-${theme}.png`, { fullPage: false });
    });
  }

  test('uses divided rows that wrap long labels at 320px without focus layout shift', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/blog');

    const rows = page.locator('.blog-row');
    await expect(rows).toHaveCount(2);
    await expect(page.locator('.blog-card')).toHaveCount(0);
    await expect(rows.first().locator('.blog-row-meta')).toContainText('Written by Claude Fable 5');
    await expect(rows.first().getByRole('heading', { level: 2 })).toContainText('CoQUIC Steward');

    const link = rows.first().getByRole('link');
    const beforeFocus = await link.boundingBox();
    await link.focus();
    const afterFocus = await link.boundingBox();
    expect(afterFocus).toEqual(beforeFocus);

    const geometry = await rows.first().evaluate((row) => ({
      clientWidth: row.clientWidth,
      scrollWidth: row.scrollWidth,
      titleWidth: row.querySelector('h2')?.getBoundingClientRect().width ?? 0,
      metaWidth: row.querySelector('.blog-row-meta')?.getBoundingClientRect().width ?? 0,
    }));
    expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.clientWidth + 1);
    expect(geometry.titleWidth).toBeLessThanOrEqual(geometry.clientWidth);
    expect(geometry.metaWidth).toBeLessThanOrEqual(geometry.clientWidth);
  });

  test('renders both static posts, authored image alt text, and internal blog links', async ({ page }) => {
    await page.goto('/blog/coquic-steward');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      'CoQUIC Steward: Letting an Agent Maintain the Repository',
    );
    await expect(page.locator('.blog-post-body')).toHaveCount(0);
    await expect(page.locator('.blog-post > .article-content')).toHaveCount(1);
    await expect(page.getByRole('img', { name: 'A robot groundskeeper tending a chip-shaped conservatory' })).toBeVisible();
    await expect(
      page.getByRole('img', {
        name: "Steward's pipeline: signals flow through a planner and verifier into sandboxed workers, then validation, review, and gated integration to main",
      }),
    ).toBeVisible();
    await expect(page.getByRole('link', { name: 'Why CoQUIC?' })).toHaveAttribute('href', '/blog/why-coquic');

    await page.goto('/blog/why-coquic');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Why CoQUIC?');
    await expect(page.locator('.blog-post-body')).toHaveCount(0);
    await expect(page.locator('.blog-post > .article-content')).toHaveCount(1);
    await expect(page.getByRole('heading', { level: 2 })).toHaveCount(9);
  });

  test('uses English by default and switches to Chinese while hiding inactive content', async ({ page }) => {
    await page.goto('/blog/coquic-steward');

    const englishPanel = page.locator('[data-blog-language-panel="en"]');
    const chinesePanel = page.locator('[data-blog-language-panel="zh"]');
    const tablist = page.getByRole('tablist', { name: 'Article language' });
    await expect(englishPanel).toHaveAttribute('lang', 'en');
    await expect(chinesePanel).toHaveAttribute('lang', 'zh-CN');
    await expect(englishPanel).toBeVisible();
    await expect(chinesePanel).toBeHidden();
    await expect(tablist.getByRole('tab', { name: 'English' })).toHaveAttribute('aria-selected', 'true');
    await expect(tablist.getByRole('tab', { name: '中文' })).toHaveAttribute('aria-selected', 'false');

    await tablist.getByRole('tab', { name: '中文' }).click();

    await expect(tablist.getByRole('tab', { name: '中文' })).toHaveAttribute('aria-selected', 'true');
    await expect(englishPanel).toBeHidden();
    await expect(chinesePanel).toBeVisible();
    await expect(chinesePanel.getByRole('heading', { level: 2 }).first()).toBeVisible();
  });

  test('supports bilingual tab roving focus and linked panels', async ({ page }) => {
    await page.goto('/blog/why-coquic');

    const tablist = page.getByRole('tablist', { name: 'Article language' });
    const english = tablist.getByRole('tab', { name: 'English' });
    const chinese = tablist.getByRole('tab', { name: '中文' });
    await english.focus();
    await english.press('ArrowRight');
    await expect(chinese).toBeFocused();
    await expect(chinese).toHaveAttribute('aria-selected', 'true');

    await chinese.press('Home');
    await expect(english).toBeFocused();
    await expect(english).toHaveAttribute('aria-selected', 'true');

    await english.press('End');
    await expect(chinese).toBeFocused();
    await expect(chinese).toHaveAttribute('aria-selected', 'true');

    await chinese.press('ArrowLeft');
    await expect(english).toBeFocused();
    await expect(english).toHaveAttribute('aria-selected', 'true');

    const englishPanel = page.locator('[data-blog-language-panel="en"]');
    const chinesePanel = page.locator('[data-blog-language-panel="zh"]');
    const englishId = await english.getAttribute('id');
    const chineseId = await chinese.getAttribute('id');
    expect(englishId).toBeTruthy();
    expect(chineseId).toBeTruthy();
    await expect(englishPanel).toHaveAttribute('aria-labelledby', englishId!);
    await expect(chinesePanel).toHaveAttribute('aria-labelledby', chineseId!);
    await expect(englishPanel).toHaveAttribute('lang', 'en');
    await expect(chinesePanel).toHaveAttribute('lang', 'zh-CN');
  });

  test('stays accessible and horizontally bounded across the editorial viewport matrix', async ({ page }) => {
    test.setTimeout(120_000);

    for (const theme of ['light', 'dark'] as const) {
      for (const width of [320, 375, 768, 1440]) {
        await page.setViewportSize({ width, height: width < 768 ? 900 : 1000 });
        await page.goto('/blog');
        await page.evaluate((nextTheme) => {
          window.localStorage.setItem('coquic-theme', nextTheme);
          document.documentElement.dataset.theme = nextTheme;
        }, theme);
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await expectNoGlobalOverflow(page);
        await expectNoSeriousAxeViolations(page, 'main');

        await page.goto('/blog/coquic-steward');
        await expect(page.locator('.blog-post-header')).toBeVisible();
        await expect(page.getByRole('tablist', { name: 'Article language' })).toBeVisible();
        await expectNoGlobalOverflow(page);
        await expectNoSeriousAxeViolations(page, 'main');
      }
    }
  });

  test('keeps article actions usable with reduced motion and a 200 percent layout probe', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 640, height: 1000 });
    await page.goto('/blog/coquic-steward');
    await expect(page.getByRole('tablist', { name: 'Article language' })).toBeVisible();
    await expect(page.locator('.blog-row-cta')).toHaveCount(0);
    await expect(page.locator('.blog-post-actions')).toBeVisible();
    await expectNoGlobalOverflow(page);

    await page.evaluate(() => {
      document.documentElement.style.fontSize = '200%';
    });
    const geometry = await page.evaluate(() => {
      const header = document.querySelector<HTMLElement>('.blog-post-header')!.getBoundingClientRect();
      const actions = document.querySelector<HTMLElement>('.blog-post-actions')!.getBoundingClientRect();
      const tabs = document.querySelector<HTMLElement>('[role="tablist"]')!.getBoundingClientRect();
      return {
        actionsBottom: actions.bottom,
        actionsTop: actions.top,
        headerBottom: header.bottom,
        tabsBottom: tabs.bottom,
        viewportWidth: window.innerWidth,
      };
    });
    const header = await page.locator('.blog-post-header').boundingBox();
    expect(header).not.toBeNull();
    expect(geometry.actionsTop).toBeGreaterThanOrEqual(header!.y - 1);
    expect(geometry.actionsBottom).toBeLessThanOrEqual(header!.y + header!.height + 1);
    expect(geometry.tabsBottom).toBeLessThanOrEqual(geometry.actionsBottom + 1);
    expect(geometry.actionsBottom).toBeGreaterThan(geometry.actionsTop);
    expect(geometry.viewportWidth).toBe(640);
  });

  test('returns not found for an invalid blog slug', async ({ page }) => {
    const response = await page.goto('/blog/not-a-known-post');

    expect(response?.status()).toBe(404);
  });
});
