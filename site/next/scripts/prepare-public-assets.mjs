import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const nextRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(nextRoot, '..', '..');
const publicDir = path.join(nextRoot, 'public');

const assets = [
  ['coquic-wasm-quic.wasm', path.join(repoRoot, 'zig-out', 'share', 'wasm-quic', 'coquic-wasm-quic.wasm')],
];

mkdirSync(publicDir, { recursive: true });

for (const [name, target] of assets) {
  const linkPath = path.join(publicDir, name);
  rmSync(linkPath, { force: true });
  if (!existsSync(target)) {
    continue;
  }
  copyFileSync(target, linkPath);
  chmodSync(linkPath, 0o644);
}
