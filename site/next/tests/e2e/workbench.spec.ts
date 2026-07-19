import { expect, test, type Page } from '@playwright/test';

import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
  waitForVisualAssets,
} from './helpers/design-system';

function collectPageErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  return () => expect(errors).toEqual([]);
}

async function setRange(page: Page, id: string, value: string) {
  await page.locator(`#${id}`).evaluate((element, nextValue) => {
    const input = element as HTMLInputElement;
    input.value = nextValue;
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, value);
}

async function loadReadyWorkbench(page: Page) {
  await page.goto('/workbench');
  await expect(page.locator('#module-state')).toHaveText('wasm ready', {
    timeout: 15_000,
  });
}

async function runTransfer(page: Page) {
  await setRange(page, 'network-delay', '50');
  await setRange(page, 'network-bandwidth', '100');
  await page.locator('#start').click();
  await expect(page.locator('#stop')).toBeEnabled();
  await expect
    .poll(() => page.locator('#packet-list .packet-row').count(), {
      timeout: 15_000,
    })
    .toBeGreaterThan(0);
  const packetsTab = page.getByRole('tab', { name: 'Packets' });
  if (await packetsTab.isVisible()) await packetsTab.click();
  await expect(page.locator('#packet-list .packet-row').first()).toBeVisible({
    timeout: 15_000,
  });
}

async function disableLegacyGeneratedRules(page: Page) {
  await page.evaluate(() => {
    const legacySelectors = new Set([
      '.empty-state, .diag-empty',
      '.packet-lane .lane-end, .datagram-label',
      '.datagram',
      '.datagram-label',
      '.packet',
      '.packet::before',
      '#start',
      '#start:hover',
      '#stop',
      '#stop:hover',
      '#step',
      '.workbench-page #start',
      '.workbench-page #start:hover:not(:disabled)',
      '.workbench-page #stop, .workbench-page #step',
    ]);

    function clearRules(rules: CSSRuleList) {
      for (const cssRule of Array.from(rules)) {
        const rule = cssRule as CSSRule & {
          cssRules?: CSSRuleList;
          selectorText?: string;
          style?: CSSStyleDeclaration;
        };
        if (rule.selectorText && legacySelectors.has(rule.selectorText) && rule.style) {
          rule.style.cssText = '';
        }
        if (rule.cssRules) clearRules(rule.cssRules);
      }
    }

    for (const sheet of Array.from(document.styleSheets)) {
      try {
        clearRules(sheet.cssRules);
      } catch {
        // Ignore browser-owned stylesheets that do not expose CSS rules.
      }
    }
  });
}

async function prepareVisualSnapshot(page: Page) {
  await waitForVisualAssets(page);
}

test.describe('protocol Workbench contracts', () => {
  test('keeps all presets and stable controls when WASM is unavailable', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await page.route('**/coquic-wasm-quic.wasm', (route) => route.abort('failed'));
    await page.goto('/workbench');

    await expect(page.locator('#module-state')).toHaveText('wasm failed');
    await expect(page.locator('#scenario-preset option')).toHaveCount(16);
    await expect(page.locator('#scenario-preset')).toContainText('Handshake');
    await expect(page.locator('#scenario-preset')).toContainText('Transfer Loss');
    await expect(page.locator('#scenario-preset')).toContainText('Retry');
    await expect(page.locator('#scenario-preset')).toContainText('0-RTT');
    await expect(page.locator('#scenario-preset')).toContainText('Version 2');
    await expect(page.getByRole('button', { name: 'Pause protocol exchange' })).toBeDisabled();
    await expect(page.locator('#start')).toBeDisabled();
    await expect(page.locator('#step')).toBeDisabled();
    await expect(page.locator('#packet-modal')).toHaveCount(1);
    expectNoPageErrors();
  });

  test('runs, pauses, steps, resumes, and preserves network controls', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await loadReadyWorkbench(page);

    await expect(page.locator('#scenario-preset')).toHaveValue('transfer');
    await page.locator('#scenario-preset').selectOption('retry');
    await expect(page.locator('#scenario-summary')).toContainText(/retry/i);
    await page.locator('#scenario-preset').selectOption('transfer');
    await setRange(page, 'network-loss', '5');
    await setRange(page, 'network-bandwidth', '25');
    await setRange(page, 'network-delay', '150');
    await expect(page.locator('#network-summary')).toHaveText('150ms / 25Mbps / 5% loss');

    await setRange(page, 'network-loss', '0');
    await setRange(page, 'network-bandwidth', '100');
    await setRange(page, 'network-delay', '50');
    const start = page.locator('#start');
    const pause = page.getByRole('button', { name: 'Pause protocol exchange' });
    await start.click();
    await expect(pause).toBeEnabled();
    await pause.click();
    await expect(start).toContainText('Resume');
    await expect(pause).toBeDisabled();

    await page.locator('#step').click();
    await expect.poll(() => page.locator('#log .entry').count()).toBeGreaterThan(0);
    await expect(start).toContainText('Resume');
    await start.click();
    await expect
      .poll(() => page.locator('#packet-list .packet-row').count(), {
        timeout: 15_000,
      })
      .toBeGreaterThan(0);
    await expect(start).toContainText('Start', { timeout: 30_000 });
    await expect(page.locator('#global-timer')).not.toHaveText('0ms');
    expectNoPageErrors();
  });

  test('owns script bridges and generated presentation without legacy base rules', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await loadReadyWorkbench(page);

    await expect(page.locator('.packet-lane.c2s')).toHaveCount(1);
    await expect(page.locator('.packet-lane.s2c')).toHaveCount(1);
    await disableLegacyGeneratedRules(page);

    const commandColors = await page.locator('#start').evaluate((button) => {
      const probe = document.createElement('span');
      probe.style.backgroundColor = 'var(--command)';
      document.body.append(probe);
      const expected = getComputedStyle(probe).backgroundColor;
      probe.remove();
      return { actual: getComputedStyle(button).backgroundColor, expected };
    });
    expect(commandColors.actual).toBe(commandColors.expected);

    const emptyState = page.locator('.diag-empty').first();
    await expect(emptyState).toBeVisible();
    expect(await emptyState.evaluate((element) => getComputedStyle(element).padding)).not.toBe('0px');
    expect(await emptyState.evaluate((element) => getComputedStyle(element).borderStyle)).not.toBe('none');

    await setRange(page, 'network-delay', '2500');
    await setRange(page, 'network-bandwidth', '100');
    await page.locator('#start').click();
    const packet = page.locator('#packet-rail .packet').first();
    const datagram = page.locator('#packet-rail .datagram').first();
    await expect(packet).toBeAttached({ timeout: 15_000 });
    await expect(datagram).toBeAttached({ timeout: 15_000 });
    expect(await packet.evaluate((element) => getComputedStyle(element).position)).toBe('absolute');
    expect(await datagram.evaluate((element) => getComputedStyle(element).position)).toBe('absolute');
    expect(await packet.evaluate((element) => getComputedStyle(element, '::before').content)).toBe('""');
    expect(await datagram.locator('.datagram-label').evaluate((element) => getComputedStyle(element).position)).toBe(
      'absolute',
    );

    const laneOffset = await packet.evaluate((element) => {
      const laneSelector = element.classList.contains('from-server') ? '.packet-lane.s2c' : '.packet-lane.c2s';
      const lane = document.querySelector(laneSelector);
      if (!lane) return Number.POSITIVE_INFINITY;
      const packetBox = element.getBoundingClientRect();
      const laneBox = lane.getBoundingClientRect();
      return Math.abs(packetBox.top + packetBox.height / 2 - (laneBox.top + laneBox.height / 2));
    });
    expect(laneOffset).toBeLessThanOrEqual(1);
    expectNoPageErrors();
  });

  test('captures packets, downloads PCAP, and restores focus from the native dialog', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await loadReadyWorkbench(page);
    await runTransfer(page);

    const firstPacket = page.locator('#packet-list .packet-row').first();
    await firstPacket.click();
    const dialog = page.locator('#packet-modal');
    await expect(dialog).toHaveJSProperty('open', true);
    await expect(dialog.getByRole('heading', { name: 'Packet Details' })).toBeVisible();
    await expect(dialog.locator('.hex-dump').first()).toBeVisible();
    await expectLocalScrollRegion(page, '#packet-modal-detail');
    await page.keyboard.press('Escape');
    await expect(dialog).not.toHaveJSProperty('open', true);
    await expect(page.locator('#packet-list .packet-row.selected')).toBeFocused();

    await page.locator('#packet-list .packet-row.selected').click();
    await dialog.locator('#packet-modal-close').click();
    await expect(page.locator('#packet-modal')).toHaveCount(1);

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#download-pcap').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.pcap$/);
    expectNoPageErrors();
  });

  test('switches mobile diagnostic views without page overflow', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    await page.setViewportSize(designViewports.phone375);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await loadReadyWorkbench(page);

    const tabs = page.getByRole('tab');
    await expect(tabs).toHaveCount(4);
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('[data-workbench-panel="client"]')).toBeVisible();
    await expect(page.locator('[data-workbench-panel="server"]')).toBeHidden();

    await tabs.nth(1).click();
    await expect(page.locator('[data-workbench-panel="server"]')).toBeVisible();
    await tabs.nth(1).press('ArrowRight');
    await expect(tabs.nth(2)).toBeFocused();
    await expect(page.locator('[data-workbench-panel="trace"]')).toBeVisible();
    await expectLocalScrollRegion(page, '#log');

    await tabs.nth(3).click();
    await expect(page.locator('[data-workbench-panel="packets"]')).toBeVisible();
    await expectLocalScrollRegion(page, '#packet-list');
    await expectNoGlobalOverflow(page);
    await expectNoSeriousAxeViolations(page, '[data-workbench-root]');
    expectNoPageErrors();
  });

  test('keeps controls and inspector views bounded at compact breakpoints', async ({ page }) => {
    const expectNoPageErrors = collectPageErrors(page);
    for (const viewport of [
      designViewports.phone320,
      designViewports.phone414,
      designViewports.tablet,
      designViewports.landscape,
      designViewports.desktop,
    ]) {
      await page.setViewportSize(viewport);
      await loadReadyWorkbench(page);
      await expect(page.locator('#start')).toBeVisible();
      await expect(page.locator('#packet-rail')).toBeVisible();
      if (viewport.width < 1024) {
        await expect(page.getByRole('tab')).toHaveCount(4);
      } else {
        await expect(page.getByRole('tab')).toHaveCount(0);
        await expect(page.locator('[data-workbench-panel="client"]')).toBeVisible();
        await expect(page.locator('[data-workbench-panel="server"]')).toBeVisible();
      }
      const truncatedLabels = await page
        .locator('label[for^="network-"] > span > span')
        .evaluateAll((labels) =>
          labels.filter((label) => label.scrollWidth > label.clientWidth + 1).map((label) => label.textContent),
        );
      expect(truncatedLabels).toEqual([]);
      await expectNoGlobalOverflow(page);
    }
    expectNoPageErrors();
  });

  test('matches initial and populated packet visuals', async ({ page }) => {
    await loadReadyWorkbench(page);
    await prepareVisualSnapshot(page);
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect(page).toHaveScreenshot('workbench-initial.png', { fullPage: false });

    await runTransfer(page);
    await expect(page.locator('#start-label')).toHaveText('Start', { timeout: 30_000 });
    await prepareVisualSnapshot(page);
    await expect(page.locator('#workbench-panel-packets')).toHaveScreenshot('workbench-populated-packets.png');
  });
});
