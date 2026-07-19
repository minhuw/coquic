import { devices, expect, test, type Page } from '@playwright/test';

import { expectNoGlobalOverflow, expectNoSeriousAxeViolations, setStoredTheme, waitForVisualAssets } from './helpers/design-system';

const viewports = [
  { name: 'mobile', width: 375, height: 812 },
  { name: 'wide', width: 1440, height: 900 },
] as const;

const probeMarkup = `
  <section
    id="shared-primitive-probe"
    aria-labelledby="shared-primitive-heading"
    class="mx-auto grid max-w-[var(--container-focused)] gap-[var(--space-4)] border border-[var(--border)] bg-[var(--canvas)] p-[var(--space-4)] text-[var(--text)]"
  >
    <header
      class="m-0 border-0 bg-transparent px-0 py-[var(--space-6)] max-md:py-[var(--space-5)] max-md:pb-[var(--space-4)]"
      data-page-header-variant="standard"
      data-slot="page-header"
    >
      <div class="grid w-full min-w-0 grid-cols-[minmax(0,1fr)_auto] items-end gap-[var(--space-6)] max-md:grid-cols-[minmax(0,1fr)] max-md:items-start max-md:gap-[var(--space-4)]" data-slot="page-header-container">
        <div class="grid min-w-0 max-w-[var(--measure-editorial)] gap-[7px]" data-slot="page-header-measure">
          <div class="min-w-0" data-slot="page-header-context">
            <span class="inline-flex max-w-full items-center gap-[var(--space-2)] text-[var(--accent-ink)] uppercase tracking-[0] [font:var(--type-metadata)] [&::before]:content-none [overflow-wrap:anywhere]" data-slot="page-header-eyebrow">
              <span class="size-[7px] shrink-0 bg-[var(--accent-ink)] forced-colors:[background-color:LinkText]" aria-hidden="true" data-slot="page-header-eyebrow-marker"></span>
              Shared primitives
            </span>
          </div>
          <h2 id="shared-primitive-heading" class="m-0 max-w-[var(--measure-editorial)] text-[var(--text-strong)] tracking-[0] [font:var(--type-page-title)] [overflow-wrap:anywhere] max-md:text-[30px] max-md:leading-[1.15]" data-slot="page-header-title">Source-owned controls</h2>
          <p class="max-w-[var(--measure-reading)] text-[var(--text-muted)] tracking-[0] [font:var(--type-body)]" data-slot="page-header-description">Semantic tokens remain readable in both themes.</p>
        </div>
        <div class="flex min-w-0 flex-wrap items-start justify-end gap-[var(--space-2)] pb-[2px] max-md:w-full max-md:justify-start max-md:pb-0" data-slot="page-header-actions">
          <button class="relative inline-flex min-w-0 shrink-0 cursor-pointer items-center justify-center gap-[var(--space-2)] rounded-[var(--radius-control)] border border-[var(--command)] bg-[var(--command)] px-[var(--space-4)] text-[var(--on-command)] tracking-[0] [font:var(--type-ui-label)] h-[var(--control-default)] hover:border-[var(--command-hover)] hover:bg-[var(--command-hover)] active:border-[var(--command-active)] active:bg-[var(--command-active)] aria-busy:cursor-progress" data-slot="button" data-variant="default" type="button">Run probe</button>
        </div>
      </div>
    </header>
    <div class="flex flex-wrap items-center gap-[var(--space-2)]">
      <button class="relative inline-flex min-w-0 shrink-0 cursor-pointer items-center justify-center gap-[var(--space-2)] rounded-[var(--radius-control)] border border-[var(--command)] bg-[var(--command)] px-[var(--space-4)] text-[var(--on-command)] tracking-[0] [font:var(--type-ui-label)] h-[var(--control-default)] hover:border-[var(--command-hover)] hover:bg-[var(--command-hover)] active:border-[var(--command-active)] active:bg-[var(--command-active)]" data-slot="button" data-variant="default" type="button">Default</button>
      <button class="relative inline-flex min-w-0 shrink-0 cursor-pointer items-center justify-center gap-[var(--space-2)] rounded-[var(--radius-control)] border border-[var(--control-border)] bg-[var(--surface)] px-[var(--space-4)] text-[var(--text-strong)] tracking-[0] [font:var(--type-ui-label)] h-[var(--control-default)] disabled:cursor-not-allowed" data-slot="button" data-variant="outline" type="button">Outline</button>
      <button class="relative inline-flex min-w-0 shrink-0 cursor-pointer items-center justify-center gap-[var(--space-2)] rounded-[var(--radius-control)] border border-transparent bg-transparent px-[var(--space-4)] text-[var(--text-strong)] tracking-[0] [font:var(--type-ui-label)] h-[var(--control-default)]" data-slot="button" data-variant="ghost" type="button">Ghost</button>
      <span class="inline-flex min-h-[24px] items-center rounded-[var(--radius-control)] border border-[var(--status-neutral-border)] bg-[var(--status-neutral-surface)] px-[var(--space-2)] text-[var(--status-neutral-ink)] tracking-[0] [font:var(--type-metadata)]" data-slot="badge" data-variant="success">metadata</span>
      <span class="inline-flex min-h-[24px] items-center rounded-[var(--radius-control)] border border-[var(--status-success-border)] bg-[var(--status-success-surface)] px-[var(--space-2)] text-[var(--status-success-ink)] tracking-[0] [font:var(--type-metadata)]" data-slot="status-label" data-tone="success">PASS</span>
      <span class="inline-flex min-h-[24px] items-center rounded-[var(--radius-control)] border border-[var(--status-warning-border)] bg-[var(--status-warning-surface)] px-[var(--space-2)] text-[var(--status-warning-ink)] tracking-[0] [font:var(--type-metadata)]" data-slot="status-label" data-tone="warning">UNSUPPORTED</span>
    </div>
    <div class="block rounded-[var(--radius-panel)] border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] shadow-none" data-slot="card">
      <div class="grid gap-[var(--space-1)] border-b border-[var(--border)] p-[var(--space-4)]" data-slot="card-header">
        <h3 class="text-[var(--text-strong)] tracking-[0] [font:var(--type-panel-title)]" data-slot="card-title">Packet state</h3>
        <p class="text-[var(--text-muted)] tracking-[0] [font:var(--type-metadata)]" data-slot="card-description">A compact semantic panel.</p>
      </div>
      <div class="p-[var(--space-4)]" data-slot="card-content">
        <div class="flex min-w-0 gap-[var(--space-1)] border-b border-[var(--border)]" data-slot="tabs-list" role="tablist" aria-label="Packet direction">
          <button class="inline-flex min-h-[var(--control-default)] min-w-0 items-center justify-center border-0 border-b-2 border-[var(--accent-ink)] bg-transparent px-[var(--space-3)] text-[var(--text-strong)] tracking-[0] [font:var(--type-ui-label)]" data-slot="tabs-trigger" data-state="active" role="tab" type="button">Client</button>
          <button class="inline-flex min-h-[var(--control-default)] min-w-0 items-center justify-center border-0 border-b-2 border-transparent bg-transparent px-[var(--space-3)] text-[var(--text-muted)] tracking-[0] [font:var(--type-ui-label)]" data-slot="tabs-trigger" data-state="inactive" role="tab" type="button">Server</button>
        </div>
        <div class="py-[var(--space-4)]" data-slot="tabs-content" role="tabpanel">Client packets</div>
        <div class="relative max-w-full overflow-x-auto overscroll-contain" data-slot="table-scroll-region" role="region" aria-label="Packet table" tabindex="0">
          <table class="w-full border-collapse caption-bottom text-sm" data-slot="table">
            <thead data-slot="table-header"><tr class="border-b border-[var(--border)]" data-slot="table-row"><th class="h-10 px-[var(--space-3)] text-left align-middle text-[var(--text-muted)] tracking-[0] [font:var(--type-metadata)]" data-slot="table-head">Frame</th><th class="h-10 px-[var(--space-3)] text-left align-middle text-[var(--text-muted)] tracking-[0] [font:var(--type-metadata)]" data-slot="table-head">State</th></tr></thead>
            <tbody data-slot="table-body"><tr class="border-b border-[var(--border)]" data-slot="table-row"><td class="p-[var(--space-3)] align-middle text-[var(--text)]" data-slot="table-cell">Initial</td><td class="p-[var(--space-3)] align-middle text-[var(--text)]" data-slot="table-cell">Ready</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="relative max-w-full overflow-x-auto overscroll-contain" data-scroll-region="true" data-slot="scroll-region" aria-label="Packet timeline" tabindex="0">
      <div class="flex min-w-[720px] items-center gap-[var(--space-2)] bg-[var(--surface-subtle)] p-[var(--space-3)] text-[var(--text-muted)]" data-slot="scroll-content">packet timeline / 01 / 02 / 03 / 04</div>
    </div>
    <div class="min-h-[1em] w-full rounded-[var(--radius-control)] bg-[var(--surface-strong)] [animation:foundation-skeleton_1.4s_var(--ease-standard)_infinite_alternate] motion-reduce:[animation-duration:0.001ms]" data-skeleton="true" data-slot="skeleton" aria-hidden="true"></div>
  </section>
`;

async function installPrimitiveProbe(page: Page) {
  await page.locator('body').evaluate((body, markup) => {
    body.querySelectorAll('nextjs-portal').forEach((portal) => portal.remove());
    body.querySelector('#shared-primitive-probe')?.remove();
    body.insertAdjacentHTML('beforeend', markup);
  }, probeMarkup);
}

for (const theme of ['light', 'dark'] as const) {
  for (const viewport of viewports) {
    test(`${theme} shared composition at ${viewport.name} viewport`, async ({ page }, testInfo) => {
      test.skip(testInfo.project.name === 'mobile', 'Self-sized visual probes use the approved desktop baselines.');
      await setStoredTheme(page, theme);
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.goto('/');
      await installPrimitiveProbe(page);
      const probe = page.locator('#shared-primitive-probe');
      await expect(probe).toBeVisible();
      await expectNoGlobalOverflow(page);
      await expectNoSeriousAxeViolations(page, '#shared-primitive-probe');
      await waitForVisualAssets(page);
      await expect(probe).toHaveScreenshot(`shared-${theme}-${viewport.name}.png`, {
        animations: 'disabled',
        caret: 'hide',
        scale: 'css',
      });
    });
  }
}

test('button owns hover, active, disabled, and loading states', async ({ page }) => {
  await setStoredTheme(page, 'light');
  await page.goto('/');
  await installPrimitiveProbe(page);

  const button = page.locator('#shared-primitive-probe [data-slot="button"]').nth(1);
  const before = await button.evaluate((element) => getComputedStyle(element).backgroundColor);
  const supportsHover = await page.evaluate(() => matchMedia('(hover: hover)').matches);
  await button.hover();
  const hover = await button.evaluate((element) => getComputedStyle(element).backgroundColor);
  const box = await button.boundingBox();
  if (!box) throw new Error('button probe has no layout box');
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  const active = await button.evaluate((element) => getComputedStyle(element).backgroundColor);
  await page.mouse.up();
  if (supportsHover) expect(hover).not.toBe(before);
  expect(active).not.toBe(before);

  const disabled = page.locator('#shared-primitive-probe [data-slot="button"]').nth(2);
  await disabled.evaluate((element) => element.setAttribute('disabled', 'true'));
  expect(await disabled.evaluate((element) => getComputedStyle(element).cursor)).toBe('not-allowed');

  const loading = page.locator('#shared-primitive-probe [data-slot="button"]').first();
  await loading.evaluate((element) => {
    element.setAttribute('aria-busy', 'true');
    element.setAttribute('data-loading', 'true');
  });
  expect(await loading.evaluate((element) => getComputedStyle(element).cursor)).toBe('progress');
});

test('compact slotted buttons preserve coarse pointer targets', async ({ baseURL, browser }) => {
  const context = await browser.newContext({ ...devices['Pixel 5'], baseURL });
  const page = await context.newPage();

  try {
    await page.goto('/duvet');
    const compactLink = page.getByRole('link', { name: 'Open HTML' });
    await compactLink.evaluate((element) => document.body.append(element));
    const geometry = await compactLink.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        coarse: matchMedia('(pointer: coarse)').matches,
        height: element.getBoundingClientRect().height,
        minHeight: style.minHeight,
      };
    });

    expect(geometry.coarse).toBe(true);
    expect(geometry.height).toBeGreaterThanOrEqual(44);
    expect(geometry.minHeight).toBe('44px');
  } finally {
    await context.close();
  }
});

test('dialog owns overlay and content presentation while preserving focus restoration', async ({ page }) => {
  await setStoredTheme(page, 'light');
  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Search' });
  await trigger.click();
  const dialog = page.getByRole('dialog', { name: 'Site search' });
  await expect(dialog).toBeVisible();
  await expect(dialog).toHaveAttribute('data-slot', 'dialog-content');
  await expect(page.locator('[data-slot="dialog-overlay"]')).toBeVisible();
  const geometry = await dialog.evaluate((element) => {
    const style = getComputedStyle(element);
    return { position: style.position, radius: style.borderRadius, shadow: style.boxShadow };
  });
  expect(geometry).toMatchObject({ position: 'fixed', radius: '6px' });
  expect(geometry.shadow).not.toBe('none');
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
});

test('PageHeader keeps mobile geometry at the inclusive 767px boundary', async ({ page }) => {
  await page.setViewportSize({ width: 767, height: 900 });
  await setStoredTheme(page, 'light');
  await page.goto('/qa');
  const header = page.locator('[data-slot="page-header"]').first();
  await expect(header).toHaveAttribute('data-page-header-variant', 'tool');
  const columns = await header.locator('[data-slot="page-header-container"]').evaluate((element) => getComputedStyle(element).gridTemplateColumns);
  expect(columns.split(' ')).toHaveLength(1);
  await expectNoGlobalOverflow(page);
});

test('shared primitive motion responds to reduced-motion and forced-colors media', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Forced-colors emulation is only available in Chromium.');
  await setStoredTheme(page, 'light');
  await page.goto('/');
  await installPrimitiveProbe(page);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const reduced = await page.locator('[data-slot="skeleton"]').evaluate((element) => getComputedStyle(element).animationDuration);
  expect(['0.001s', '0.01s', '1e-05s']).toContain(reduced);
  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'no-preference' });
  const marker = page.locator('[data-slot="page-header-eyebrow-marker"]');
  await expect(marker).toBeVisible();
  await expectNoGlobalOverflow(page);
});
