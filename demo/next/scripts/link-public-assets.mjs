import { existsSync, mkdirSync, rmSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const nextRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(nextRoot, '..', '..');
const publicDir = path.join(nextRoot, 'public');

const assets = [
  ['coquic-logo.svg', path.join(repoRoot, 'demo', 'wasm-quic', 'coquic-logo.svg'), true],
  ['demo-theme.css', path.join(repoRoot, 'demo', 'wasm-quic', 'demo-theme.css'), true],
  ['quic-demo.js', path.join(repoRoot, 'demo', 'wasm-quic', 'quic-demo.js'), true],
  ['perf-comparison.js', path.join(repoRoot, 'demo', 'wasm-quic', 'perf-comparison.js'), true],
  ['interop-results.js', path.join(repoRoot, 'demo', 'wasm-quic', 'interop-results.js'), true],
  ['coverage-results.js', path.join(repoRoot, 'demo', 'wasm-quic', 'coverage-results.js'), true],
  ['perf-results.json', path.join(repoRoot, 'demo', 'wasm-quic', 'perf-results.json'), false],
  ['perf-history.json', path.join(repoRoot, 'demo', 'wasm-quic', 'perf-history.json'), false],
  ['interop-results.json', path.join(repoRoot, 'demo', 'wasm-quic', 'interop-results.json'), false],
  ['coverage-results.json', path.join(repoRoot, 'demo', 'wasm-quic', 'coverage-results.json'), false],
  [
    'coquic-wasm-quic.wasm',
    path.join(repoRoot, 'zig-out', 'share', 'wasm-quic', 'coquic-wasm-quic.wasm'),
    false,
  ],
];

mkdirSync(publicDir, { recursive: true });

for (const [name, target, required] of assets) {
  const linkPath = path.join(publicDir, name);
  if (!existsSync(target)) {
    if (required) {
      throw new Error(`missing demo asset: ${target}`);
    }
    continue;
  }
  rmSync(linkPath, { force: true });
  symlinkSync(path.relative(publicDir, target), linkPath);
}
