import { expect, test, type Page } from '@playwright/test';

function failOnPageErrors(page: Page) {
  const errors: Error[] = [];
  page.on('pageerror', (error) => errors.push(error));
  return () => expect(errors.map((error) => error.message)).toEqual([]);
}

async function interceptEvidenceData(page: Page) {
  await page.route('**/*.json', (route) => route.fulfill({ status: 404, body: 'not found' }));
}

for (const path of ['/performance', '/perf-comparison']) {
  test(`${path} completes its deterministic fallback`, async ({ page }) => {
    const expectNoPageErrors = failOnPageErrors(page);
    await interceptEvidenceData(page);
    await page.goto(path);
    await expect(page.locator('meta[name="coquic-perf-marker"]')).toHaveAttribute('content', 'coquic-perf-comparison-v1');
    await expect(page.locator('#plot-grid')).toContainText('No performance history loaded.');
    expectNoPageErrors();
  });
}

for (const path of ['/interop', '/interop-results']) {
  test(`${path} completes its deterministic fallback`, async ({ page }) => {
    const expectNoPageErrors = failOnPageErrors(page);
    await interceptEvidenceData(page);
    await page.goto(path);
    await expect(page.locator('meta[name="coquic-interop-marker"]')).toHaveAttribute('content', 'coquic-interop-results-v1');
    await expect(page.locator('#data-source-label')).toHaveText('interop-results.json not available yet');
    await expect(page.locator('#matrix-head')).not.toBeEmpty();
    await expect(page.locator('#matrix-body')).toContainText('No CoQUIC interop rows loaded.');
    expectNoPageErrors();
  });
}

for (const path of ['/coverage', '/coverage-results']) {
  test(`${path} completes its deterministic fallback`, async ({ page }) => {
    const expectNoPageErrors = failOnPageErrors(page);
    await interceptEvidenceData(page);
    await page.goto(path);
    await expect(page.locator('meta[name="coquic-coverage-marker"]')).toHaveAttribute('content', 'coquic-coverage-results-v1');
    await expect(page.locator('#coverage-source-label')).toHaveText('coverage-results.json not available yet');
    await expect(page.locator('#summary-grid')).not.toBeEmpty();
    await expect(page.locator('#component-list')).toHaveText('No component coverage loaded.');
    await expect(page.locator('#file-list')).toHaveText('No file coverage loaded.');
    expectNoPageErrors();
  });
}

test('Workbench preserves its control contract when WASM is unavailable', async ({ page }) => {
  const expectNoPageErrors = failOnPageErrors(page);
  let wasmRequestObserved = false;
  await page.route('**/coquic-wasm-quic.wasm', (route) => {
    wasmRequestObserved = true;
    return route.abort('failed');
  });

  await page.goto('/workbench');
  await expect.poll(() => wasmRequestObserved).toBe(true);
  await expect(page.locator('meta[name="coquic-demo-marker"]')).toHaveAttribute('content', 'coquic-wasm-demo-v1');
  await expect(page.locator('#module-state')).toHaveText('wasm failed');

  const controlIds = [
    'start',
    'stop',
    'step',
    'scenario-preset',
    'network-loss',
    'network-bandwidth',
    'network-delay',
    'download-pcap',
    'packet-modal-close',
    'packet-modal',
  ];
  for (const id of controlIds) await expect(page.locator(`#${id}`)).toHaveCount(1);

  await page.locator('#scenario-preset').selectOption('handshake');
  for (const [id, value] of [
    ['network-loss', '5'],
    ['network-bandwidth', '25'],
    ['network-delay', '150'],
  ] as const) {
    await page.locator(`#${id}`).evaluate((element, nextValue) => {
      const input = element as HTMLInputElement;
      input.value = nextValue;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
  }
  for (const id of ['start', 'stop', 'step', 'download-pcap', 'packet-modal-close', 'packet-modal']) {
    await page.locator(`#${id}`).dispatchEvent('click');
  }

  await expect(page.locator('#module-state')).toHaveText('wasm failed');
  expectNoPageErrors();
});
