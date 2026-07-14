import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';

import {
  transcriptDetailResponse,
  transcriptEmptySearch,
  transcriptMissingArchiveSearch,
  transcriptRecords,
  transcriptSearchResponse,
  transcriptSession,
} from './fixtures/transcript';

type TranscriptMockOptions = {
  archiveMissing?: boolean;
  collectionStatus?: number;
  detailStatus?: number;
  empty?: boolean;
  loadMoreStatus?: number;
};

async function mockTranscriptApi(page: Page, options: TranscriptMockOptions = {}) {
  const requests: string[] = [];
  let detailCalls = 0;

  await page.route('**/transcript/api/search?**', async (route) => {
    const url = new URL(route.request().url());
    requests.push(`${url.pathname}?${url.searchParams.toString()}`);
    expect(url.searchParams.get('page')).toBeTruthy();
    if (options.collectionStatus) {
      await json(route, { detail: 'Transcript database unavailable' }, options.collectionStatus);
      return;
    }
    const response = options.empty
      ? transcriptEmptySearch
      : options.archiveMissing
        ? transcriptMissingArchiveSearch
        : transcriptSearchResponse({
            query: url.searchParams.get('q') ?? '',
            from: url.searchParams.get('from') ?? '',
            to: url.searchParams.get('to') ?? '',
            page: Number(url.searchParams.get('page') ?? 1),
            sessions: Number(url.searchParams.get('page') ?? 1) === 1
              ? transcriptSearchResponse().sessions
              : [transcriptSession(26), transcriptSession(27), transcriptSession(28)],
          });
    await json(route, response);
  });

  await page.route('**/transcript/api/session/*/raw', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/x-ndjson', body: '{}\n' });
  });

  await page.route('**/transcript/api/session/*?**', async (route) => {
    const url = new URL(route.request().url());
    requests.push(`${url.pathname}?${url.searchParams.toString()}`);
    detailCalls += 1;
    if (options.detailStatus) {
      await json(route, { detail: 'detail failed' }, options.detailStatus);
      return;
    }
    if (url.searchParams.has('cursor')) {
      expect(url.searchParams.get('cursor')).toBe('2');
      expect(url.searchParams.get('limit')).toBe('80');
      if (options.loadMoreStatus) {
        await json(route, { detail: 'load more failed' }, options.loadMoreStatus);
        return;
      }
      await json(route, transcriptDetailResponse({
        records: [{ ...transcriptRecords[1], line: 3, text: 'Loaded from the second record page.' }],
        hasMore: false,
        nextCursor: 3,
        scannedLines: 3,
      }));
      return;
    }
    expect(url.searchParams.get('limit')).toBe('80');
    await json(route, transcriptDetailResponse());
  });

  await page.route('**/dataset/codex-history-coquic-transcripts-only-20260630.zip', async (route) => {
    await route.fulfill({ status: options.archiveMissing ? 404 : 200, contentType: 'application/zip', body: '' });
  });

  return { requests, detailCalls: () => detailCalls };
}

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

test.describe('transcript master detail', () => {
  test.describe.configure({ mode: 'serial' });

  test('preserves URL history, selection, scroll context, downloads, and record order', async ({ page }) => {
    const api = await mockTranscriptApi(page, { loadMoreStatus: 500 });
    await page.goto('/transcript?utm=fixture');
    const desktopMaster = (page.viewportSize()?.width ?? 0) >= 760;

    await expect(page.getByRole('heading', { name: 'CoQUIC Transcript Dataset' })).toBeVisible();
    await expect(page.getByText('Select a transcript')).toBeVisible({ visible: desktopMaster });
    await expect(page.getByRole('complementary', { name: 'Transcript sessions' })).toBeVisible();
    expect(api.requests[0]).toBe('/transcript/api/search?page=1');

    const list = page.getByRole('complementary', { name: 'Transcript sessions' });
    await list.evaluate((element) => { element.scrollTop = 140; element.dispatchEvent(new Event('scroll')); });
    const selectedRow = page.getByRole('button', { name: /Transcript session 5 with/ });
    await selectedRow.scrollIntoViewIfNeeded();
    await selectedRow.click();
    const selectionScroll = await page.evaluate(() => {
      const map = JSON.parse(sessionStorage.getItem('coquic-transcript:list-scroll:v1') ?? '{}') as Record<string, number>;
      return map[''];
    });
    expect(selectionScroll).toBeGreaterThan(0);
    await expect(page).toHaveURL(/utm=fixture&session=public-session-5/);
    await expect(page.getByText(transcriptRecords[0].text)).toBeVisible();
    await expect(page.getByText(transcriptRecords[1].text)).toBeVisible();
    expect(api.requests).toContain('/transcript/api/session/public-session-5?limit=80');
    await expect(page.getByRole('link', { name: 'JSONL' })).toHaveAttribute('href', '/transcript/api/session/public-session-5/raw');
    await expect(page.getByRole('link', { name: 'ZIP' })).toHaveAttribute('href', '/dataset/codex-history-coquic-transcripts-only-20260630.zip');

    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.getByRole('button', { name: 'Retry load more' })).toBeVisible();
    await expect(page.getByText('More records could not be loaded.')).toBeVisible();
    await expect(page.getByText(transcriptRecords[0].text)).toBeVisible();

    await page.goBack();
    await expect(page).toHaveURL('/transcript?utm=fixture');
    await expect(page.getByText('Select a transcript')).toBeVisible({ visible: desktopMaster });
    await page.goForward();
    await expect(page).toHaveURL(/session=public-session-5/);
    await expect(page.getByText(transcriptRecords[0].text)).toBeVisible();

    await page.getByRole('button', { name: 'Back to results' }).click();
    await expect(page).toHaveURL('/transcript?utm=fixture');
    await expect.poll(() => list.evaluate((element) => element.scrollTop)).toBe(selectionScroll);
  });

  test('debounces filters, preserves unrelated params, and pushes pagination', async ({ page }) => {
    const api = await mockTranscriptApi(page);
    await page.goto('/transcript?campaign=keep');
    await page.getByRole('searchbox', { name: 'Search transcript sessions' }).fill('quic recovery');
    await page.waitForTimeout(100);
    expect(api.requests.filter((request) => request.includes('q=quic')).length).toBe(0);
    await expect(page).toHaveURL('/transcript?campaign=keep&q=quic+recovery');
    await expect.poll(() => api.requests.some((request) => request === '/transcript/api/search?page=1&q=quic+recovery')).toBe(true);

    await page.getByRole('button', { name: 'Next', exact: true }).click();
    await expect(page).toHaveURL('/transcript?campaign=keep&q=quic+recovery&page=2');
    await expect(page.getByText('Transcript session 26 with a deliberately descriptive label')).toBeVisible();

    await page.getByRole('button', { name: 'Clear filters' }).click();
    await expect(page).toHaveURL('/transcript?campaign=keep');
  });

  test('keeps a not-found deep link factual and removable', async ({ page }) => {
    await mockTranscriptApi(page, { detailStatus: 404 });
    await page.goto('/transcript?utm=keep&session=missing-public-id');

    await expect(page.getByText('Transcript not found')).toBeVisible();
    await expect(page.getByText('No public transcript matches missing-public-id.')).toBeVisible();
    await expect(page).toHaveURL(/session=missing-public-id/);
    await page.getByRole('button', { name: 'Back to results' }).click();
    await expect(page).toHaveURL('/transcript?utm=keep');
  });

  test('distinguishes empty, unavailable, and missing archive states', async ({ page }) => {
    await mockTranscriptApi(page, { empty: true });
    await page.goto('/transcript');
    await expect(page.getByText('No transcripts found')).toBeVisible();
    await expect(page.getByText('0 results')).toBeVisible();

    await page.unrouteAll({ behavior: 'wait' });
    await mockTranscriptApi(page, { collectionStatus: 503 });
    await page.reload();
    await expect(page.getByText('The transcript index is currently unavailable.')).toBeVisible();
    await expect(page.getByText('No transcripts found')).toHaveCount(0);

    await page.unrouteAll({ behavior: 'wait' });
    await mockTranscriptApi(page, { archiveMissing: true });
    await page.reload();
    await expect(page.getByText('Archive unavailable')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Download dataset' })).toHaveCount(0);
  });

  test('supports keyboard date dismissal, named scroll regions, Axe, and compact overflow', async ({ page }) => {
    await mockTranscriptApi(page);
    await page.setViewportSize({ width: 320, height: 760 });
    await page.goto('/transcript');

    const dateTrigger = page.getByRole('button', { name: /Date range/ });
    await dateTrigger.focus();
    await dateTrigger.press('Enter');
    await expect(page.getByRole('dialog', { name: 'Transcript date range' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', { name: 'Transcript date range' })).toHaveCount(0);
    await expect(dateTrigger).toBeFocused();

    await expect(page.getByRole('complementary', { name: 'Transcript sessions' })).toHaveAttribute('tabindex', '0');
    for (const viewport of [{ width: 320, height: 760 }, { width: 375, height: 812 }, { width: 414, height: 896 }, { width: 844, height: 390 }]) {
      await page.setViewportSize(viewport);
      const overflow = await page.evaluate(() => ({ document: document.documentElement.scrollWidth - document.documentElement.clientWidth, body: document.body.scrollWidth - document.body.clientWidth }));
      expect(overflow.document).toBeLessThanOrEqual(1);
      expect(overflow.body).toBeLessThanOrEqual(1);
      await expect(page.getByRole('complementary', { name: 'Transcript sessions' })).toBeVisible();
      await expect(page.getByLabel('Selected transcript preview')).toBeVisible({ visible: viewport.width >= 760 });
    }

    await page.setViewportSize({ width: 320, height: 760 });
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await expect(page.locator('.transcript-shell')).toHaveCSS('container-type', 'inline-size');

    const axe = await new AxeBuilder({ page }).include('.transcript-shell').analyze();
    expect(axe.violations).toEqual([]);

    await page.getByRole('button', { name: /Transcript session 1 with/ }).click();
    await expect(page.getByRole('complementary', { name: 'Transcript sessions' })).not.toBeVisible();
    await expect(page.getByLabel('Selected transcript preview')).toBeVisible();
    await page.getByRole('button', { name: 'Back to results' }).click();
    await expect(page.getByRole('complementary', { name: 'Transcript sessions' })).toBeVisible();
  });
});
