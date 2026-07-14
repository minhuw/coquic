import AxeBuilder from '@axe-core/playwright';
import { expect, type Locator, type Page } from '@playwright/test';

export const designViewports = {
  phone320: { width: 320, height: 800 },
  phone375: { width: 375, height: 812 },
  phone414: { width: 414, height: 896 },
  tablet: { width: 768, height: 1024 },
  landscape: { width: 844, height: 390 },
  desktop: { width: 1024, height: 768 },
  wide: { width: 1440, height: 900 },
} as const;

export async function setStoredTheme(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript((storedTheme) => {
    const initializationKey = 'coquic-playwright-theme-initialized';
    if (window.sessionStorage.getItem(initializationKey)) return;
    window.localStorage.setItem('coquic-theme', storedTheme);
    window.sessionStorage.setItem(initializationKey, 'true');
  }, theme);
}

export async function expectNoGlobalOverflow(page: Page) {
  const overflow = await page.evaluate(() => {
    const viewportWidth = window.innerWidth;
    const selectors = [...document.querySelectorAll<HTMLElement>('body *')]
      .filter((element) => {
        const bounds = element.getBoundingClientRect();
        return bounds.left < -1 || bounds.right > viewportWidth + 1;
      })
      .map((element) => {
        const id = element.id ? `#${CSS.escape(element.id)}` : '';
        const classes = [...element.classList]
          .slice(0, 3)
          .map((className) => `.${CSS.escape(className)}`)
          .join('');
        return `${element.tagName.toLowerCase()}${id}${classes}`;
      });
    return {
      documentWidth: document.documentElement.scrollWidth,
      selectors: [...new Set(selectors)],
      viewportWidth,
    };
  });

  expect(
    overflow.documentWidth,
    `Global overflow from: ${overflow.selectors.join(', ') || 'unknown element'}`,
  ).toBeLessThanOrEqual(overflow.viewportWidth + 1);
}

export async function expectNoSeriousAxeViolations(page: Page, include?: string | string[]) {
  let builder = new AxeBuilder({ page });
  if (include) builder = builder.include(include);
  const results = await builder.analyze();
  const violations = results.violations.filter(
    (violation) => violation.impact === 'serious' || violation.impact === 'critical',
  );
  expect(violations).toEqual([]);
}

export async function expectLocalScrollRegion(page: Page, selector: string) {
  const region = page.locator(selector);
  await expect(region).toHaveCount(1);
  await expect(region).toHaveAccessibleName(/\S/);
  const geometry = await region.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      clientWidth: element.clientWidth,
      right: bounds.right,
      scrollWidth: element.scrollWidth,
      tabIndex: (element as HTMLElement).tabIndex,
      viewportWidth: window.innerWidth,
    };
  });
  expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth + 1);
  if (geometry.scrollWidth > geometry.clientWidth + 1) {
    expect(geometry.tabIndex, `${selector} must be keyboard focusable when it overflows`).toBeGreaterThanOrEqual(0);
  }
}

export async function tabUntilFocused(page: Page, locator: Locator, limit = 40) {
  for (let attempt = 0; attempt < limit; attempt += 1) {
    await page.keyboard.press('Tab');
    if (await locator.evaluate((element) => element === document.activeElement)) return;
  }

  const activeElement = await page.evaluate(() => {
    const element = document.activeElement;
    if (!element) return 'none';
    const id = element.id ? `#${element.id}` : '';
    const name = element.getAttribute('aria-label') || element.textContent?.trim() || '';
    return `${element.tagName.toLowerCase()}${id}${name ? ` (${name.slice(0, 80)})` : ''}`;
  });
  throw new Error(`Target was not focused after ${limit} Tab presses; active element: ${activeElement}`);
}
