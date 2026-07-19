import { expect, test } from '@playwright/test';

import { expectNoGlobalOverflow, expectNoSeriousAxeViolations, setStoredTheme, tabUntilFocused } from './helpers/design-system';

test.describe('desktop shell behavior', () => {
  test.skip(({ isMobile }) => isMobile, 'Shell interaction characterization runs in the desktop project.');

  test('home logo navigates and active destinations expose aria-current', async ({ page }) => {
    await page.goto('/docs');
    await expect(page.getByRole('link', { name: 'Docs' })).toHaveAttribute('aria-current', 'page');
    const home = page.getByRole('link', { name: 'Home', exact: true });
    await tabUntilFocused(page, home);
    await home.press('Enter');
    await expect(page).toHaveURL('/');
    await expect(page.getByRole('link', { name: 'Home', exact: true })).toHaveAttribute('aria-current', 'page');
  });

  test('uses the original desktop navigation hierarchy', async ({ page }) => {
    await page.goto('/');
    const navigation = page.locator('[data-shell-primary-nav]');

    await expect(navigation.locator(':scope > a[data-slot="nav-link"]')).toHaveText(['Ask', 'Docs', 'Blog', 'Dataset', 'Workbench']);
    await expect(navigation.locator(':scope > [data-slot="nav-menu"] > [data-shell-control="nav-menu-trigger"]')).toHaveText(['Benchmark', 'Development']);
    await expect(page.getByRole('link', { name: 'Minhu Wang contact page' })).toBeVisible();

    await page.getByRole('button', { name: 'Benchmark' }).click();
    const lan = navigation.locator('[data-slot="nav-menu-content"]').first().getByRole('link');
    await expect(lan).toHaveText(['LAN']);
    expect(await lan.evaluate((link) => {
      const bounds = link.getBoundingClientRect();
      return document.elementFromPoint(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2)?.closest('a') === link;
    })).toBe(true);
    await page.getByRole('button', { name: 'Benchmark' }).click();
    await page.getByRole('button', { name: 'Development' }).click();
    await expect(navigation.locator('[data-slot="nav-menu-content"]').last().getByRole('link')).toHaveText(['Interop', 'Coverage', 'Duvet', 'Steward']);
  });

  test('theme choice persists across navigation and reload', async ({ page }) => {
    await setStoredTheme(page, 'light');
    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.getByRole('button', { name: 'Switch to dark mode' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect.poll(() => page.evaluate(() => localStorage.getItem('coquic-theme'))).toBe('dark');
    await page.getByRole('link', { name: 'Docs' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });

  test('keyboard shortcuts filter, select, navigate, and dismiss search', async ({ page }) => {
    await page.goto('/');
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Site search' });
    const input = page.getByRole('searchbox', { name: 'Search CoQUIC' });
    await expect(dialog).toBeVisible();
    await input.fill('coverage');
    await expect(page.getByRole('link').filter({ hasText: 'Coverage Report' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    await page.keyboard.press('Meta+k');
    await expect(dialog).toBeVisible();
    await input.fill('protocol workbench');
    const firstResult = page.getByRole('link').filter({ hasText: 'Protocol Workbench' }).first();
    await expect(firstResult).toContainText('Protocol Workbench');
    await input.press('ArrowDown');
    await expect(firstResult).not.toHaveAttribute('data-active', 'true');
    await input.press('ArrowUp');
    await expect(firstResult).toHaveAttribute('data-active', 'true');
    await input.press('Enter');
    await expect(page).toHaveURL('/workbench');
  });

  test('search clears and reports no matches', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Search' }).click();
    const input = page.getByRole('searchbox', { name: 'Search CoQUIC' });
    await input.fill('zzzzqv blorpt');
    await expect(page.getByText('No matches')).toBeVisible();
    await expect(page.getByRole('status')).toHaveText('0 results');
    await input.fill('coverage');
    await page.getByRole('button', { name: 'Clear search' }).click();
    await expect(input).toHaveValue('');
    await expect(page.getByText('Suggested destinations')).toBeVisible();
  });

  test('open search has no serious accessibility violations', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Search' }).click();
    await expectNoSeriousAxeViolations(page);
    await page.getByRole('searchbox', { name: 'Search CoQUIC' }).fill('coverage');
    await expectNoSeriousAxeViolations(page);
  });

  for (const disclosure of [
    { destination: 'LAN', href: '/performance', label: 'Benchmark' },
    { destination: 'Coverage', href: '/coverage', label: 'Development' },
  ]) {
    test(`${disclosure.label} disclosure closes on Escape, outside pointer, and link selection`, async ({ page }) => {
      await page.goto('/');
      const trigger = page.getByRole('button', { name: disclosure.label });
      await trigger.click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await trigger.press('Escape');
      await expect(trigger).toHaveAttribute('aria-expanded', 'false');
      await trigger.click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await page.getByRole('heading', { level: 1 }).click();
      await expect(trigger).toHaveAttribute('aria-expanded', 'false');
      await expect(trigger).toBeFocused();
      await trigger.click();
      await page.getByRole('link', { name: disclosure.destination, exact: true }).click();
      await expect(page).toHaveURL(disclosure.href);
    });
  }
});

test('system theme changes update the document without persistence', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.addInitScript(() => localStorage.removeItem('coquic-theme'));
  await page.goto('/');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect.poll(() => page.locator('html').getAttribute('data-theme')).toBe('dark');
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('coquic-theme'))).toBeNull();
});

test('theme script sets the first-frame system and saved themes', async ({ page }) => {
  const scriptErrors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error' && message.text().includes('Encountered a script tag')) scriptErrors.push(message.text());
  });

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.addInitScript(() => {
    localStorage.removeItem('coquic-theme');
    (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame = new Promise((resolve) => requestAnimationFrame(() => resolve({ theme: document.documentElement.dataset.theme, colorScheme: getComputedStyle(document.documentElement).colorScheme })));
  });
  await page.goto('/');
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame)).toEqual({ theme: 'dark', colorScheme: 'dark' });

  await page.emulateMedia({ colorScheme: 'dark' });
  await page.addInitScript(() => {
    localStorage.setItem('coquic-theme', 'light');
    (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame = new Promise((resolve) => requestAnimationFrame(() => resolve({ theme: document.documentElement.dataset.theme, colorScheme: getComputedStyle(document.documentElement).colorScheme })));
  });
  await page.reload();
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __coquicFirstFrame: Promise<unknown> }).__coquicFirstFrame)).toEqual({ theme: 'light', colorScheme: 'light' });
  await expect(page.locator('script#coquic-theme')).toHaveCount(1);
  expect(scriptErrors).toEqual([]);
});

test('plan 003 provides complete mobile menu access', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Open menu' }).click();
  await expect(page.getByRole('dialog', { name: 'CoQUIC navigation' }).getByRole('link')).toHaveCount(12);
});

test('mobile menu preserves destination order and external links', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto('/coverage');
  await page.getByRole('button', { name: 'Open menu' }).click();

  const links = page.getByRole('dialog', { name: 'CoQUIC navigation' }).getByRole('link');
  await expect(links).toHaveText(['Ask', 'Docs', 'Blog', 'Dataset', 'Workbench', 'LAN', 'Interop', 'Coverage', 'Duvet', 'Steward', 'GitHub', 'Contact']);
  const destinations = await links.evaluateAll((elements) => elements.map((element) => {
    const link = element as HTMLAnchorElement;
    const url = new URL(link.href);
    return url.origin === window.location.origin ? url.pathname : url.href;
  }));
  expect(destinations).toEqual([
    '/qa',
    '/docs',
    '/blog',
    '/transcript',
    '/workbench',
    '/performance',
    '/interop',
    '/coverage',
    '/duvet',
    '/steward',
    'https://github.com/minhuw/coquic',
    'https://www.minhuw.dev/',
  ]);
});

test('navigation switches to compact controls before desktop labels wrap', async ({ page }) => {
  await page.setViewportSize({ width: 1023, height: 900 });
  await page.goto('/coverage');

  await expect(page.locator('[data-shell-desktop]')).toBeHidden();
  await expect(page.locator('[data-shell-mobile]')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Search' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open menu' })).toBeVisible();
  await expectNoGlobalOverflow(page);

  await page.setViewportSize({ width: 1024, height: 900 });
  await expect(page.locator('[data-shell-desktop]')).toBeVisible();
  await expect(page.locator('[data-shell-mobile]')).toBeHidden();
  await expect(page.getByRole('button', { name: 'Search' })).toBeVisible();
  await expectNoGlobalOverflow(page);
});

test('short pages keep the footer at the document bottom', async ({ page }) => {
  await page.goto('/blog');

  const geometry = await page.locator('[data-slot="project-footer"]').evaluate((footer) => ({
    documentHeight: document.documentElement.scrollHeight,
    footerBottom: footer.getBoundingClientRect().bottom + window.scrollY,
    viewportHeight: window.innerHeight,
  }));

  expect(geometry.footerBottom).toBeGreaterThanOrEqual(geometry.viewportHeight - 1);
  expect(Math.abs(geometry.documentHeight - geometry.footerBottom)).toBeLessThanOrEqual(1);
});

test('long routes keep the footer after main content in mobile landscape', async ({ page }) => {
  await page.setViewportSize({ width: 844, height: 390 });
  await page.goto('/steward');

  const geometry = await page.locator('[data-slot="project-footer"]').evaluate((footer) => {
    const main = document.querySelector<HTMLElement>('[data-slot="shell-main"]');
    if (!main) throw new Error('shell main is missing');
    const footerBounds = footer.getBoundingClientRect();
    const mainBounds = main.getBoundingClientRect();
    return {
      documentHeight: document.documentElement.scrollHeight,
      footerTop: footerBounds.top + window.scrollY,
      mainBottom: mainBounds.bottom + window.scrollY,
      viewportHeight: window.innerHeight,
    };
  });

  expect(geometry.documentHeight).toBeGreaterThan(geometry.viewportHeight);
  expect(geometry.footerTop).toBeGreaterThanOrEqual(geometry.mainBottom - 1);
  expect(geometry.footerTop).toBeGreaterThan(geometry.viewportHeight);
});

test('plan 003 restores search focus after dismissal', async ({ page }) => {
  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Search' });
  await trigger.click();
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
});
