import { expect, test, type Page } from '@playwright/test';

import { expectNoGlobalOverflow, setStoredTheme } from './helpers/design-system';

test.describe.configure({ mode: 'serial' });

const lightTokens = {
  '--canvas': 'rgb(250, 250, 248)',
  '--command': 'rgb(20, 22, 19)',
  '--on-command': 'rgb(255, 255, 255)',
  '--inverse-surface': 'rgb(17, 19, 16)',
  '--client': 'rgb(23, 92, 211)',
  '--server': 'rgb(8, 122, 131)',
  '--status-success-ink': 'rgb(14, 107, 72)',
  '--status-warning-surface': 'rgb(255, 246, 216)',
  '--status-danger-border': 'rgb(230, 160, 177)',
  '--status-known-peer-ink': 'rgb(104, 66, 184)',
  '--chart-6': 'rgb(82, 102, 90)',
} as const;

const darkTokens = {
  '--canvas': 'rgb(17, 18, 16)',
  '--command': 'rgb(245, 246, 243)',
  '--on-command': 'rgb(17, 19, 16)',
  '--inverse-surface': 'rgb(242, 243, 240)',
  '--client': 'rgb(130, 174, 255)',
  '--server': 'rgb(103, 209, 216)',
  '--status-success-ink': 'rgb(85, 214, 160)',
  '--status-warning-surface': 'rgb(42, 36, 21)',
  '--status-danger-border': 'rgb(105, 50, 65)',
  '--status-known-peer-ink': 'rgb(196, 168, 255)',
  '--chart-6': 'rgb(178, 193, 181)',
} as const;

async function installFoundationProbe(page: Page) {
  await page.locator('body').evaluate((body) => {
    const probe = document.createElement('section');
    probe.id = 'foundation-probe';
    probe.innerHTML = `
      <button id="focus-probe">Focus probe</button>
      <button id="loading-probe" data-slot="button" data-variant="default">
        <span data-slot="button-content">Connect endpoint</span>
      </button>
      <code id="mono-probe">packet_number=42</code>
      <p id="cjk-probe" lang="zh-Hans">QUIC 协议状态</p>
      <div id="panel-probe" style="border-radius: var(--radius-panel)"></div>
      <div id="motion-probe" class="skeleton" style="width: 40px; height: 12px"></div>
      <div class="container-focused" id="container-probe"></div>
      <div id="modal-shadow-probe" style="box-shadow: var(--elevation-modal)" aria-hidden="true"></div>
    `;
    body.append(probe);
  });
}

async function readTokens(page: Page, names: readonly string[]) {
  return page.evaluate((tokenNames) => {
    const style = getComputedStyle(document.documentElement);
    const normalize = (value: string) => {
      const probe = document.createElement('span');
      probe.style.color = value;
      document.body.append(probe);
      const normalized = getComputedStyle(probe).color;
      probe.remove();
      return normalized;
    };
    return Object.fromEntries(tokenNames.map((name) => [name, normalize(style.getPropertyValue(name).trim())]));
  }, names);
}

function contrastRatio(first: string, second: string) {
  const rgb = (value: string) => value.match(/\d+/g)!.slice(0, 3).map(Number);
  const luminance = (value: string) => {
    const channels = rgb(value).map((channel) => {
      const normalized = channel / 255;
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
  };
  const light = Math.max(luminance(first), luminance(second));
  const dark = Math.min(luminance(first), luminance(second));
  return (light + 0.05) / (dark + 0.05);
}

test('tokens, fonts, geometry, and interaction states resolve through the foundation', async ({ page }) => {
  const thirdPartyFontRequests: string[] = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    const isLocal = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
    if ((!isLocal && request.resourceType() === 'font') || /fonts\.(?:googleapis|gstatic)\.com/i.test(url.hostname)) {
      thirdPartyFontRequests.push(request.url());
    }
  });

  await test.step('light semantic tokens resolve through the canonical theme', async () => {
    await setStoredTheme(page, 'light');
    await page.goto('/');
    await installFoundationProbe(page);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect.poll(() => readTokens(page, Object.keys(lightTokens))).toEqual(lightTokens);
    const modalShadow = await page.locator('#modal-shadow-probe').evaluate((element) => getComputedStyle(element).boxShadow);
    expect(modalShadow).not.toBe('none');
    expect(modalShadow).toContain('24px 64px');
    const resolved = (await readTokens(page, ['--command', '--on-command'])) as Record<string, string>;
    expect(contrastRatio(resolved['--command'], resolved['--on-command'])).toBeGreaterThanOrEqual(15);
  });

  await test.step('dark semantic tokens resolve through the canonical theme', async () => {
    await page.evaluate(() => window.localStorage.setItem('coquic-theme', 'dark'));
    await page.reload();
    await installFoundationProbe(page);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect.poll(() => readTokens(page, Object.keys(darkTokens))).toEqual(darkTokens);
    const modalShadow = await page.locator('#modal-shadow-probe').evaluate((element) => getComputedStyle(element).boxShadow);
    expect(modalShadow).not.toBe('none');
    expect(modalShadow).toContain('28px 72px');
    const resolved = (await readTokens(page, ['--command', '--on-command'])) as Record<string, string>;
    expect(contrastRatio(resolved['--command'], resolved['--on-command'])).toBeGreaterThanOrEqual(15);
  });

  await test.step('local sans, mono, and CJK fallback glyphs render without third-party font requests', async () => {
    await page.evaluate(() => document.fonts.ready);

    const fonts = await page.evaluate(() => {
      const bodyFamily = getComputedStyle(document.body).fontFamily;
      const monoFamily = getComputedStyle(document.querySelector('#mono-probe')!).fontFamily;
      const renderText = (text: string) => {
        const canvas = document.createElement('canvas');
        canvas.width = 240;
        canvas.height = 56;
        const context = canvas.getContext('2d')!;
        context.font = `32px ${bodyFamily}`;
        context.fillText(text, 4, 40);
        return canvas.toDataURL();
      };
      return {
        bodyFamily,
        bodyLoaded: document.fonts.check(`16px ${bodyFamily.split(',')[0]}`),
        cjkDiffersFromMissingGlyphs: renderText('协议状态') !== renderText('\uFFFF\uFFFF\uFFFF\uFFFF'),
        cjkStack: getComputedStyle(document.querySelector('#cjk-probe')!).fontFamily,
        monoFamily,
        monoLoaded: document.fonts.check(`13px ${monoFamily.split(',')[0]}`),
      };
    });

    expect(fonts.bodyFamily).toMatch(/hostGrotesk|Host Grotesk/i);
    expect(fonts.monoFamily).toMatch(/googleSansCode|Google Sans Code/i);
    expect(fonts.bodyFamily).toMatch(/system-ui/);
    expect(fonts.cjkStack).toBe(fonts.bodyFamily);
    expect(fonts.cjkDiffersFromMissingGlyphs).toBe(true);
    expect(fonts.bodyLoaded).toBe(true);
    expect(fonts.monoLoaded).toBe(true);
    expect(thirdPartyFontRequests).toEqual([]);
  });

  await test.step('fixed geometry, loading width, disabled state, and keyboard focus remain stable', async () => {
    const focusProbe = page.locator('#focus-probe');
    await focusProbe.focus();
    const values = await page.evaluate(async () => {
      const root = getComputedStyle(document.documentElement);
      const body = getComputedStyle(document.body);
      const focus = getComputedStyle(document.querySelector('#focus-probe')!);
      const panel = getComputedStyle(document.querySelector('#panel-probe')!);
      const container = document.querySelector('#container-probe')!.getBoundingClientRect();
      const loading = document.querySelector<HTMLButtonElement>('#loading-probe')!;
      const loadingWidthBefore = loading.getBoundingClientRect().width;
      loading.dataset.loading = 'true';
      loading.disabled = true;
      loading.insertAdjacentHTML('afterbegin', '<span data-slot="button-spinner" aria-hidden="true"></span>');
      const loadingWidthAfter = loading.getBoundingClientRect().width;
      await new Promise((resolve) => window.setTimeout(resolve, 160));
      const loadingStyle = getComputedStyle(loading);
      return {
        bodyFontSize: body.fontSize,
        bodyLetterSpacing: body.letterSpacing,
        bodyLineHeight: body.lineHeight,
        containerWidth: container.width,
        focusOffset: focus.outlineOffset,
        focusStyle: focus.outlineStyle,
        focusWidth: focus.outlineWidth,
        loadingBackground: loadingStyle.backgroundColor,
        loadingCursor: loadingStyle.cursor,
        loadingWidthAfter,
        loadingWidthBefore,
        panelRadius: panel.borderRadius,
        radiusControl: root.getPropertyValue('--radius-control').trim(),
        radiusOverlay: root.getPropertyValue('--radius-overlay').trim(),
        space9: root.getPropertyValue('--space-9').trim(),
        zModal: root.getPropertyValue('--z-modal').trim(),
      };
    });

    expect(values).toMatchObject({
      bodyFontSize: '16px',
      bodyLineHeight: '25.6px',
      focusOffset: '3px',
      focusStyle: 'solid',
      focusWidth: '2px',
      loadingCursor: 'not-allowed',
      loadingBackground: 'rgb(41, 45, 40)',
      panelRadius: '3px',
      radiusControl: '2px',
      radiusOverlay: '6px',
      space9: '96px',
      zModal: '50',
    });
    expect(['normal', '0px']).toContain(values.bodyLetterSpacing);
    expect(values.containerWidth).toBeLessThanOrEqual(1072);
    expect(values.loadingWidthAfter).toBe(values.loadingWidthBefore);
    expect(values.loadingBackground).not.toBe('rgba(0, 0, 0, 0)');
    await expectNoGlobalOverflow(page);
  });

  await test.step('the foundation reflows at the 320px minimum viewport', async () => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/');
    await expectNoGlobalOverflow(page);
    expect(await page.evaluate(() => document.documentElement.getBoundingClientRect().width)).toBe(320);
  });
});

test('accessibility media preferences preserve stable behavior', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'Forced-colors emulation is only available in Chromium.');

  await test.step('reduced motion stops skeleton loops and smooth scrolling', async () => {
    await page.emulateMedia({ forcedColors: 'none', reducedMotion: 'reduce' });
    await page.goto('/');
    await installFoundationProbe(page);

    const motion = await page.evaluate(() => {
      const skeleton = getComputedStyle(document.querySelector('#motion-probe')!);
      return {
        animationDuration: skeleton.animationDuration,
        animationIterations: skeleton.animationIterationCount,
        scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
      };
    });
    expect(Number.parseFloat(motion.animationDuration)).toBeLessThanOrEqual(0.00001);
    expect(motion.animationIterations).toBe('1');
    expect(motion.scrollBehavior).toBe('auto');
  });

  await test.step('forced colors preserves native link and focus visibility', async () => {
    await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'no-preference' });
    await page.goto('/');
    await installFoundationProbe(page);

    const probe = page.locator('#focus-probe');
    await probe.focus();
    const forced = await probe.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        boxShadow: style.boxShadow,
        outlineStyle: style.outlineStyle,
        outlineWidth: style.outlineWidth,
      };
    });
    expect(forced).toEqual({ boxShadow: 'none', outlineStyle: 'solid', outlineWidth: '2px' });
  });
});
