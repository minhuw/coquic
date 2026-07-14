import { expect, test, type Locator, type Page } from '@playwright/test';

import { installInteropFixture } from './fixtures/interop';
import {
  designViewports,
  expectLocalScrollRegion,
  expectNoGlobalOverflow,
  expectNoSeriousAxeViolations,
} from './helpers/design-system';

const matrixHeaders = ['All', 'Client', 'Server', 'handshake', 'transfer', 'keyupdate', 'blackhole', 'retry'];

async function findLane(page: Page, client: string, server: string) {
  const rows = page.locator('#matrix-body tr');
  for (let index = 0; index < await rows.count(); index += 1) {
    const row = rows.nth(index);
    if (
      (await row.locator('.participant-name strong').innerText()) === client &&
      (await row.locator('.server-column strong').innerText()) === server
    ) {
      return row;
    }
  }
  throw new Error(`Missing interop lane ${client} -> ${server}`);
}

function resultControl(row: Locator, column: number) {
  return row.locator('td, th').nth(column).locator('.test-cell');
}

async function waitForSnapshot(page: Page) {
  await expect(page.locator('#data-source-label')).toHaveText('interop-results.json from 2026-07-14T12:34:56Z');
  await expect(page.locator('.interop-page')).toHaveAttribute('data-interop-state', 'ready');
  await expect(page.locator('.interop-page')).toHaveAttribute('aria-busy', 'false');
}

test('characterizes every result category, lane direction, and aggregate state', async ({ page }, testInfo) => {
  const requests = await installInteropFixture(page);
  await page.goto('/interop-results');
  await waitForSnapshot(page);

  expect(requests).toEqual(['/interop-results.json']);
  expect(await page.locator('#matrix-head th').allTextContents()).toEqual(matrixHeaders);
  await expect(page.locator('#matrix-body tr')).toHaveCount(3);
  await expect(page.locator('#matrix-body')).not.toContainText('filtered-peer-lane');
  await expect(page.locator('.interop-run-context')).toContainText('interop-fixture');
  await expect(page.locator('.interop-run-context')).toContainText('fixture-011');
  await expect(page.locator('.interop-conclusion')).toContainText('unannotated CoQUIC failure');
  await expect(page.locator('#interop-matrix-region')).toHaveAccessibleName('CoQUIC interop results matrix');

  for (const [category, count] of [
    ['pass', '3'],
    ['unsupported', '3'],
    ['peer-broken', '3'],
    ['known-peer-broken', '4'],
    ['failed', '1'],
    ['not-reported', '1'],
  ]) {
    await expect(page.locator(`[data-interop-count="${category}"]`)).toHaveText(count);
  }

  const clientDirection = await findLane(page, 'CoQUIC', 'quinn');
  const serverDirection = await findLane(page, 'picoquic', 'CoQUIC');
  const acceptableDirection = await findLane(page, 'quic-go', 'CoQUIC');

  await expect(resultControl(clientDirection, 0).locator('..')).toHaveClass(/unknown/);
  await expect(resultControl(clientDirection, 0)).toHaveText('N/R');
  await expect(resultControl(clientDirection, 3).locator('..')).toHaveClass(/succeeded/);
  await expect(resultControl(clientDirection, 3)).toHaveText('PASS');
  await expect(resultControl(clientDirection, 4).locator('..')).toHaveClass(/unsupported/);
  await expect(resultControl(clientDirection, 4)).toHaveText('UNSUP');
  await expect(resultControl(clientDirection, 5).locator('..')).toHaveClass(/unknown/);
  await expect(resultControl(clientDirection, 5)).toHaveText('N/R');
  await expect(resultControl(clientDirection, 6).locator('..')).toHaveClass(/peer-broken/);
  await expect(resultControl(clientDirection, 6)).toHaveText('PEER');
  await expect(resultControl(clientDirection, 7).locator('..')).toHaveClass(/known-peer-broken/);
  await expect(resultControl(clientDirection, 7).locator('..')).toHaveAttribute('data-result', 'failed');
  await expect(resultControl(clientDirection, 7)).toHaveText('KNOWN');
  await expect(resultControl(clientDirection, 7)).toHaveAttribute('aria-label', /Upstream compatibility note/);

  await expect(resultControl(serverDirection, 0).locator('..')).toHaveClass(/failed/);
  await expect(resultControl(serverDirection, 0)).toHaveText('FAIL');
  await expect(resultControl(serverDirection, 3).locator('..')).toHaveClass(/failed/);
  await expect(resultControl(serverDirection, 3)).toHaveText('FAIL');
  await expect(resultControl(serverDirection, 5).locator('..')).toHaveClass(/known-peer-broken/);
  await expect(resultControl(serverDirection, 5)).toHaveAttribute('aria-label', /KNOWN PEER ISSUE/);
  await expect(resultControl(acceptableDirection, 0).locator('..')).toHaveClass(/succeeded/);
  await expect(resultControl(acceptableDirection, 0)).toHaveText('PASS');

  if (testInfo.project.name === 'desktop') {
    await resultControl(clientDirection, 3).hover();
    await expect(page.locator('.interop-tooltip')).toBeVisible();
  }
  await resultControl(clientDirection, 3).focus();
  await expect(page.locator('.interop-tooltip')).toBeVisible();
  await expect(page.locator('.interop-tooltip')).toContainText('handshake');
  await expect(page.locator('.interop-tooltip')).toContainText('PASS');
  await expect(resultControl(clientDirection, 3)).toHaveAttribute('aria-describedby', 'interop-tooltip');
  await expect(resultControl(clientDirection, 3)).toHaveAttribute('aria-expanded', 'true');
  await resultControl(clientDirection, 3).click();
  await expect(page.locator('.interop-tooltip')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('.interop-tooltip')).toBeHidden();
  await expect(resultControl(clientDirection, 3)).toBeFocused();
});

test('both interop aliases render the same evidence contract', async ({ page }) => {
  const requests = await installInteropFixture(page);
  for (const path of ['/interop-results', '/interop']) {
    await page.goto(path);
    await waitForSnapshot(page);
    await expect(page.getByRole('heading', { name: 'CoQUIC Interop Matrix' })).toBeVisible();
    await expect(page.locator('#matrix-body tr')).toHaveCount(3);
    await expect(page.locator('[data-interop-count="failed"]')).toHaveText('1');
  }
  expect(requests).toEqual(['/interop-results.json', '/interop-results.json']);
});

test('uses a bounded, focusable matrix region without global overflow', async ({ page }) => {
  const requests = await installInteropFixture(page);
  for (const viewport of [designViewports.phone320, designViewports.tablet, designViewports.wide]) {
    await page.setViewportSize(viewport);
    await page.goto('/interop-results');
    await waitForSnapshot(page);
    const region = page.locator('#interop-matrix-region');
    await region.evaluate((element) => {
      const node = element as HTMLElement;
      node.style.height = '120px';
      node.dispatchEvent(new Event('resize'));
      window.dispatchEvent(new Event('resize'));
    });
    await expectLocalScrollRegion(page, '#interop-matrix-region');
    const geometryBefore = await region.evaluate((element) => {
      const row = element.querySelector('tbody tr');
      const status = row?.querySelector('.row-status-column');
      const participant = row?.querySelector('.participant-name');
      const server = row?.querySelector('.server-column');
      const header = element.querySelector('thead th');
      return {
        headerTop: header?.getBoundingClientRect().top ?? 0,
        regionTop: element.getBoundingClientRect().top,
        statusLeft: status?.getBoundingClientRect().left ?? 0,
        participantLeft: participant?.getBoundingClientRect().left ?? 0,
        serverLeft: server?.getBoundingClientRect().left ?? 0,
      };
    });
    await region.evaluate((element) => {
      element.scrollTop = element.scrollHeight;
      element.scrollLeft = element.scrollWidth;
    });
    const geometryAfter = await region.evaluate((element) => {
      const row = element.querySelector('tbody tr');
      const status = row?.querySelector('.row-status-column');
      const participant = row?.querySelector('.participant-name');
      const server = row?.querySelector('.server-column');
      const header = element.querySelector('thead th');
      return {
        headerTop: header?.getBoundingClientRect().top ?? 0,
        regionTop: element.getBoundingClientRect().top,
        statusLeft: status?.getBoundingClientRect().left ?? 0,
        participantLeft: participant?.getBoundingClientRect().left ?? 0,
        serverLeft: server?.getBoundingClientRect().left ?? 0,
      };
    });
    expect(geometryAfter.headerTop).toBeGreaterThanOrEqual(geometryAfter.regionTop - 1);
    expect(Math.abs(geometryAfter.statusLeft - geometryBefore.statusLeft)).toBeLessThanOrEqual(1);
    expect(Math.abs(geometryAfter.participantLeft - geometryBefore.participantLeft)).toBeLessThanOrEqual(1);
    expect(Math.abs(geometryAfter.serverLeft - geometryBefore.serverLeft)).toBeLessThanOrEqual(1);
    await expectNoGlobalOverflow(page);
  }
  expect(requests).toHaveLength(3);
});

test('announces unavailable evidence without presenting an empty result as success', async ({ page }) => {
  await page.route('**/interop-results.json', (route) => route.fulfill({ status: 404, body: 'not found' }));
  await page.goto('/interop-results');
  await expect(page.locator('.interop-page')).toHaveAttribute('data-interop-state', 'unavailable');
  await expect(page.locator('.interop-page')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#data-source-label')).toHaveText('interop-results.json not available yet');
  await expect(page.locator('#interop-state')).toContainText('Interop evidence unavailable');
  await expect(page.locator('#interop-conclusion')).toContainText('no conclusion can be drawn');
  await expect(page.locator('[data-interop-count="pass"]')).toHaveText('-');
  await expect(page.locator('#matrix-body')).toContainText('No CoQUIC interop rows loaded.');
});

test('popovers stay within the viewport and the matrix has no serious axe violations', async ({ page }) => {
  const requests = await installInteropFixture(page);
  await page.setViewportSize(designViewports.phone320);
  await page.goto('/interop-results');
  await waitForSnapshot(page);
  await expectNoSeriousAxeViolations(page, 'main');
  const cell = resultControl(await findLane(page, 'CoQUIC', 'quinn'), 3);
  await cell.click();
  const tooltip = page.locator('.interop-tooltip');
  await expect(tooltip).toBeVisible();
  const tooltipBounds = await tooltip.boundingBox();
  expect(tooltipBounds).not.toBeNull();
  const viewport = page.viewportSize();
  expect(viewport).not.toBeNull();
  expect(tooltipBounds!.x).toBeGreaterThanOrEqual(0);
  expect(tooltipBounds!.x + tooltipBounds!.width).toBeLessThanOrEqual(viewport!.width);
  expect(tooltipBounds!.y).toBeGreaterThanOrEqual(0);
  expect(tooltipBounds!.y + tooltipBounds!.height).toBeLessThanOrEqual(viewport!.height);
  await page.mouse.click(4, 4);
  await expect(tooltip).toBeHidden();
  expect(requests).toEqual(['/interop-results.json']);
});

test('touch detail stays within the viewport and closes cleanly', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile', 'Touch behavior is covered by the mobile project.');
  const requests = await installInteropFixture(page);
  await page.setViewportSize(designViewports.phone320);
  await page.goto('/interop-results');
  await waitForSnapshot(page);
  const cell = resultControl(await findLane(page, 'CoQUIC', 'quinn'), 3);
  await cell.tap();
  const tooltip = page.locator('.interop-tooltip');
  await expect(tooltip).toBeVisible();
  const tooltipBounds = await tooltip.boundingBox();
  expect(tooltipBounds).not.toBeNull();
  const viewport = page.viewportSize();
  expect(viewport).not.toBeNull();
  expect(tooltipBounds!.x).toBeGreaterThanOrEqual(0);
  expect(tooltipBounds!.x + tooltipBounds!.width).toBeLessThanOrEqual(viewport!.width);
  expect(tooltipBounds!.y).toBeGreaterThanOrEqual(0);
  expect(tooltipBounds!.y + tooltipBounds!.height).toBeLessThanOrEqual(viewport!.height);
  await page.keyboard.press('Escape');
  await expect(tooltip).toBeHidden();
  await expect(cell).toBeFocused();
  expect(requests).toEqual(['/interop-results.json']);
});
