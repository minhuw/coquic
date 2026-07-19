import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

// The checker is an executable ESM module and intentionally has no emitted declaration file.
// @ts-expect-error -- the test exercises the source-owned JavaScript checker directly.
import { collectStyleBoundaryViolations } from '../scripts/check-style-boundaries.mjs';

const fixtureRoots: string[] = [];

async function createFixture(files: Record<string, string> = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'coquic-style-boundary-'));
  fixtureRoots.push(root);
  const fixtureFiles = {
    'app/layout.tsx': "import './styles/theme.css';\n",
    'app/styles/theme.css': '@import "tailwindcss";\n',
    'components.json': `${JSON.stringify({ tailwind: { css: 'app/styles/theme.css' } })}\n`,
    ...files,
  };
  for (const [relativePath, content] of Object.entries(fixtureFiles)) {
    const file = path.join(root, relativePath);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, content);
  }
  return root;
}

afterEach(async () => {
  await Promise.all(fixtureRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe('Style boundary checker', () => {
  it('accepts a minimal canonical fixture', async () => {
    const root = await createFixture();
    await expect(collectStyleBoundaryViolations(root)).resolves.toEqual([]);
  });

  it('does not treat test fixtures as production style consumers', async () => {
    const root = await createFixture({
      'public/steward/retired-class-fixture.js': 'document.querySelector(".coquic-page");\n',
      'tests/retired-class-fixture.tsx': 'export const fixture = <main className="coquic-page" />;\n',
    });
    await expect(collectStyleBoundaryViolations(root)).resolves.toEqual([]);
  });

  it('checks component source and top-level public scripts', async () => {
    const root = await createFixture({
      'public/quic-demo.js': 'document.querySelector(".coquic-page");\n',
      'src/components/example.tsx': 'export const Example = () => <main className="coquic-page" />;\n',
    });
    const violations = await collectStyleBoundaryViolations(root);
    expect(violations).toHaveLength(2);
    expect(violations).toEqual(expect.arrayContaining([
      'public/quic-demo.js consumes retired class coquic-page',
      'src/components/example.tsx consumes retired class coquic-page',
    ]));
  });

  it('rejects a url() import of the retired global sheet', async () => {
    const root = await createFixture({
      'app/styles/theme.css': '@import url("../globals.css");\n',
    });
    await expect(collectStyleBoundaryViolations(root)).resolves.toContain(
      'theme imports non-canonical sheet: ../globals.css',
    );
  });

  it('rejects a root route import from a child route CSS Module', async () => {
    const root = await createFixture({
      'app/blog/blog.module.css': '.root {}\n',
      'app/page.tsx': "import styles from './blog/blog.module.css';\nexport default () => <main className={styles.root} />;\n",
    });
    await expect(collectStyleBoundaryViolations(root)).resolves.toContain(
      'app/page.tsx imports another route CSS Module app/blog/blog.module.css',
    );
  });

  it('rejects a retired class after a template interpolation', async () => {
    const root = await createFixture({
      'app/page.tsx': "const styles = { root: 'root' };\nexport default () => <main className={`${styles.root} coquic-page`} />;\n",
    });
    await expect(collectStyleBoundaryViolations(root)).resolves.toContain(
      'app/page.tsx consumes retired class coquic-page',
    );
  });
});
