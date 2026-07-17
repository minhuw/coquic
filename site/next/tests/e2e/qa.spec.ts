import { expect, test } from '@playwright/test';

import { expectLocalScrollRegion, expectNoGlobalOverflow, expectNoSeriousAxeViolations, setStoredTheme } from './helpers/design-system';
import {
  installQaFixture,
  qaRequests,
  rejectedQaEvents,
  successfulQaEvents,
  wideMarkdownQaEvents,
} from './fixtures/qa';

const themes = ['light', 'dark'] as const;
const screenshotTime = new Date('2026-07-15T12:00:00Z');

test.describe('QUIC specification QA', () => {
  for (const theme of themes) {
    test(`captures idle and streaming presentation in ${theme}`, async ({ page }) => {
      await page.clock.setFixedTime(screenshotTime);
      await setStoredTheme(page, theme);
      await installQaFixture(page, {
        events: successfulQaEvents().slice(1),
        intervalMs: 30_000,
      });
      await page.goto('/qa');
      await hideNextDevTools(page);

      const workspace = page.locator('[data-qa-workspace]');
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(workspace).toHaveAttribute('data-qa-phase', 'ready');
      await page.evaluate(() => document.fonts.ready);
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`qa-idle-${theme}.png`, { fullPage: true });

      await ask(page);
      await expect(workspace).toHaveAttribute('data-qa-phase', 'streaming');
      await expect(page.locator('[data-channel="direct"]:visible')).toContainText('Direct partial');
      await expect(page.getByRole('button', { name: 'Asking question' })).toHaveAttribute('aria-busy', 'true');
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`qa-streaming-${theme}.png`, { fullPage: true });
    });

    test(`captures populated presentation in ${theme}`, async ({ page }) => {
      await page.clock.setFixedTime(screenshotTime);
      await setStoredTheme(page, theme);
      await installQaFixture(page, { events: successfulQaEvents() });
      await page.goto('/qa');
      await hideNextDevTools(page);
      await ask(page);

      const workspace = page.locator('[data-qa-workspace]');
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(workspace).toHaveAttribute('data-qa-phase', 'completed');
      await expect(page.locator('[data-qa-results]')).toBeVisible();
      await page.evaluate(() => document.fonts.ready);
      await expectNoGlobalOverflow(page);
      await expect(page).toHaveScreenshot(`qa-populated-${theme}.png`, { fullPage: true });
    });
  }

  test('uses inline validation for an empty keyboard submission', async ({ page }) => {
    await installQaFixture(page, { events: successfulQaEvents() });
    await page.goto('/qa');

    const textbox = page.getByRole('textbox', { name: 'Question' });
    await textbox.press('Control+Enter');

    await expect(textbox).toHaveAttribute('aria-invalid', 'true');
    await expect(page.locator('#qa-question-error')).toHaveText('Enter a QUIC specification question before asking.');
  });

  test('streams both channels, preserves the wire contract, and renders final evidence', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await installQaFixture(page, { events: successfulQaEvents(), intervalMs: 120 });
    await page.goto('/qa');
    await page.getByRole('textbox', { name: 'Question' }).fill('How does ACK delay affect loss recovery?');
    await page.getByRole('button', { name: 'Ask' }).click();

    const direct = page.locator('[data-qa-results-view="desktop"] [data-channel="direct"]');
    const rag = page.locator('[data-qa-results-view="desktop"] [data-channel="rag"]');
    await expect(direct).toHaveAttribute('aria-busy', 'true');
    await expect(direct).toContainText('Direct partial');
    await expect(rag).toContainText('Grounded partial');
    await expect(page.getByRole('button', { name: 'Asking question' })).toHaveAttribute('aria-busy', 'true');

    await expect(direct).toContainText('Direct final answer without retrieval.');
    await expect(rag).toContainText('RAG final answer with specification evidence.');
    await expect(direct).toHaveAttribute('aria-busy', 'false');
    await expect(rag.getByText('17 tok')).toBeVisible();
    await expect(rag.getByText('84% (High)')).toBeVisible();
    await expect(rag.getByRole('link', { name: 'RFC 9000 Section 13.2' })).toHaveAttribute(
      'href',
      'https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2',
    );
    await expect(rag.getByText('Similarity 0.913')).toHaveAccessibleName('Retrieval similarity 0.913');

    const requests = await qaRequests(page);
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      url: '/rag-api/api/qa/stream',
      method: 'POST',
      body: JSON.stringify({ question: 'How does ACK delay affect loss recovery?' }),
      headers: {
        accept: 'text/event-stream',
        'content-type': 'application/json',
      },
    });
    expect(requests[0]?.headers['x-session-id']).toBeTruthy();
    expect(await page.evaluate(() => window.localStorage.getItem('coquic-qa-session'))).toBe(
      requests[0]?.headers['x-session-id'],
    );
  });

  for (const [reason, message] of [
    ['out_of_scope', 'This question is outside the QUIC specification scope.'],
    ['low_retrieval_confidence', 'The retrieved specification evidence was not strong enough'],
    ['generation_error', 'Answer generation is temporarily unavailable.'],
  ] as const) {
    test(`presents ${reason} as one factual recovery state`, async ({ page }) => {
      await installQaFixture(page, { events: rejectedQaEvents(reason) });
      await page.goto('/qa');
      await ask(page);

      const status = page.locator('[data-qa-request-status]');
      await expect(status).toContainText(message);
      await expect(status.getByRole('button', { name: 'Retry' })).toBeVisible();
      await expect(page.locator('[data-qa-results-view="desktop"] [data-channel="direct"]')).toContainText('Direct response retained.');
      await expect(page.locator('[data-qa-results-view="desktop"] [data-channel="rag"]')).toContainText('Grounded response retained.');
    });
  }

  test('presents rate limiting as one recovery state', async ({ page }) => {
    await installQaFixture(page, { streamStatus: 429 });
    await page.goto('/qa');
    await ask(page);
    await expect(page.locator('[data-qa-request-status]')).toContainText('Request limit reached. Try again in a minute.');
    await expect(page.locator('[data-channel]')).toHaveCount(0);

    await page.close();
  });

  test('keeps a partial answer outside the transport error copy', async ({ page }) => {
    await installQaFixture(page, {
      events: successfulQaEvents(),
      intervalMs: 40,
      streamErrorAfter: 2,
    });
    await page.goto('/qa');
    await ask(page);

    await expect(page.locator('[data-qa-request-status]')).toContainText('could not be completed');
    const direct = page.locator('[data-qa-results-view="desktop"] [data-channel="direct"]');
    await expect(direct).toContainText('Direct partial');
    await expect(direct).not.toContainText('could not be completed');
  });

  test('reports an offline fetch without presenting it as either model answer', async ({ page }) => {
    await installQaFixture(page, { streamNetworkError: true });
    await page.goto('/qa');
    await ask(page);

    await expect(page.locator('[data-qa-request-status]')).toContainText('Unable to reach specification QA.');
    await expect(page.locator('[data-channel]')).toHaveCount(0);
  });

  test('uses mobile roving tabs and keeps supporting evidence keyboard reachable', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await installQaFixture(page, { events: successfulQaEvents() });
    await page.goto('/qa');
    await ask(page);

    const tabs = page.getByRole('tablist', { name: 'Answer comparison' });
    const directTab = tabs.getByRole('tab', { name: 'Direct' });
    const ragTab = tabs.getByRole('tab', { name: 'With RAG' });
    await expect(directTab).toHaveAttribute('aria-selected', 'true');
    await directTab.focus();
    await directTab.press('ArrowRight');
    await expect(ragTab).toBeFocused();
    await expect(ragTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('tabpanel', { name: 'With RAG' })).toContainText('RAG final answer');

    const ragPanel = page.getByRole('tabpanel', { name: 'With RAG' });
    const disclosure = ragPanel.getByText('RFC excerpt');
    await disclosure.focus();
    await disclosure.press('Enter');
    const excerpt = ragPanel.getByRole('region', { name: 'RFC 9000 Section 13.2 excerpt' });
    await expect(excerpt).toBeVisible();
    await expectLocalScrollRegion(page, '[data-qa-results-view="mobile"] [data-channel="rag"] [data-qa-citation-excerpt]');
    const geometry = await excerpt.evaluate((element) => ({ clientHeight: element.clientHeight, scrollHeight: element.scrollHeight }));
    expect(geometry.scrollHeight).toBeGreaterThan(geometry.clientHeight);
    await expectNoGlobalOverflow(page);
  });

  test('keeps wide Markdown tables and code in named keyboard-scrollable regions', async ({ page }) => {
    await installQaFixture(page, { events: wideMarkdownQaEvents() });

    for (const width of [320, 375]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto('/qa');
      await ask(page);

      const codeSelector = '[data-qa-results-view="mobile"] [data-channel="direct"] [data-qa-code-block]';
      const codeRegion = page.locator(codeSelector);
      await expect(codeRegion).toHaveAttribute('data-overflow', 'true');
      await expect(codeRegion).toHaveAccessibleName('typescript answer code');
      await expectLocalScrollRegion(page, codeSelector);

      const tabs = page.getByRole('tablist', { name: 'Answer comparison' });
      await tabs.getByRole('tab', { name: 'With RAG' }).click();
      const tableSelector = '[data-qa-results-view="mobile"] [data-channel="rag"] [data-editorial-table-region]';
      const tableRegion = page.locator(tableSelector);
      await expect(tableRegion).toHaveAttribute('data-overflow', 'true');
      await expect(tableRegion).toHaveAccessibleName('Answer data table');
      await expectLocalScrollRegion(page, tableSelector);
      await expectNoGlobalOverflow(page);
    }
  });

  test('supports suggestion, Ctrl+Enter, privacy touch, and answer copy', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await installQaFixture(page, {
      events: successfulQaEvents(),
      randomQuestion: 'How are QUIC packet numbers encoded?',
    });
    await page.goto('/qa');

    const privacy = page.getByRole('button', { name: 'Privacy notice' });
    await privacy.click();
    await expect(privacy).toHaveAttribute('aria-expanded', 'true');
    await expect(page.getByRole('tooltip')).toBeVisible();

    await page.getByRole('button', { name: 'Suggest question' }).click();
    const textbox = page.getByRole('textbox', { name: 'Question' });
    await expect(textbox).toHaveValue('How are QUIC packet numbers encoded?');
    await textbox.press('Control+Enter');
    await expect(page.locator('[data-qa-results-view="desktop"] [data-channel="direct"]')).toContainText('Direct final answer');

    await page.locator('[data-qa-results-view="desktop"]').getByRole('button', { name: 'Copy Direct answer' }).click();
    await expect(page.locator('[data-qa-results-view="desktop"] [data-channel="direct"]').getByRole('status')).toContainText(
      'copied to clipboard',
    );
    await expect.poll(() => page.evaluate(() => window.localStorage.getItem('coquic-qa-copied'))).toBe(
      'Direct final answer without retrieval.',
    );

    const requests = await qaRequests(page);
    expect(requests.map((request) => request.url)).toEqual([
      '/rag-api/api/questions/random',
      '/rag-api/api/qa/stream',
    ]);
  });

  test('keeps stable commands and accessible bounded layout across themes, zoom, and motion settings', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 320, height: 900 });
    await setStoredTheme(page, 'dark');
    await installQaFixture(page, { events: successfulQaEvents(), intervalMs: 150 });
    await page.goto('/qa');

    const suggest = page.getByRole('button', { name: 'Suggest question' });
    const askButton = page.getByRole('button', { name: 'Ask' });
    const before = { ask: await askButton.boundingBox(), suggest: await suggest.boundingBox() };
    await page.getByRole('textbox', { name: 'Question' }).fill('What is QUIC loss recovery?');
    const enabled = { ask: await askButton.boundingBox(), suggest: await suggest.boundingBox() };
    expect(enabled.ask?.width).toBe(before.ask?.width);
    expect(enabled.suggest?.width).toBe(before.suggest?.width);
    await askButton.click();
    const loadingAsk = page.getByRole('button', { name: 'Asking question' });
    expect((await loadingAsk.boundingBox())?.width).toBe(enabled.ask?.width);
    await expect(page.locator('[data-qa-placeholder] span').first()).toHaveCSS('animation-name', 'none');

    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expectNoGlobalOverflow(page);
    await expectNoSeriousAxeViolations(page, 'main');

    await page.evaluate(() => {
      document.documentElement.style.fontSize = '200%';
    });
    await expectNoGlobalOverflow(page);
    const actionGeometry = await page.locator('[data-qa-actions]').evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(actionGeometry.scrollWidth).toBeLessThanOrEqual(actionGeometry.clientWidth + 1);
  });
});

async function ask(page: Parameters<typeof installQaFixture>[0]) {
  await page.getByRole('textbox', { name: 'Question' }).fill('How does QUIC loss recovery work?');
  await page.getByRole('button', { name: 'Ask' }).click();
}

async function hideNextDevTools(page: Parameters<typeof installQaFixture>[0]) {
  await page.addStyleTag({ content: 'nextjs-portal { display: none !important; }' });
}
