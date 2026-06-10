import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const nextRoot = path.resolve(scriptDir, '..');
process.chdir(nextRoot);

mkdirSync('public', { recursive: true });
rmSync('public/coquic-wasm-quic.wasm', { force: true });

if (existsSync('../../zig-out/share/wasm-quic/coquic-wasm-quic.wasm')) {
  copyFileSync('../../zig-out/share/wasm-quic/coquic-wasm-quic.wasm', 'public/coquic-wasm-quic.wasm');
  chmodSync('public/coquic-wasm-quic.wasm', 0o644);
}

const duvetAssets = [
  ['../../.duvet/reports/report.html', 'public/duvet/report.html'],
  ['../../.duvet/reports/report.json', 'public/duvet/report.json'],
  ['../../.duvet/snapshot.txt', 'public/duvet/snapshot.txt'],
];

if (duvetAssets.every(([source]) => existsSync(source))) {
  mkdirSync('public/duvet', { recursive: true });
  for (const [source, destination] of duvetAssets) {
    copyFileSync(source, destination);
    chmodSync(destination, 0o644);
  }
}
