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

if (
  existsSync('../../.duvet/reports/report.html') &&
  existsSync('../../.duvet/reports/report.json') &&
  existsSync('../../.duvet/snapshot.txt')
) {
  mkdirSync('public/duvet', { recursive: true });
  copyFileSync('../../.duvet/reports/report.html', 'public/duvet/report.html');
  chmodSync('public/duvet/report.html', 0o644);
  copyFileSync('../../.duvet/reports/report.json', 'public/duvet/report.json');
  chmodSync('public/duvet/report.json', 0o644);
  copyFileSync('../../.duvet/snapshot.txt', 'public/duvet/snapshot.txt');
  chmodSync('public/duvet/snapshot.txt', 0o644);
}
