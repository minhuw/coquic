# CoQUIC Next.js Demo

This is the framework-backed source for the browser demo. It owns the home
page plus the workbench, performance, interop, and coverage routes. Browser
runtime assets live in `public/`, and `predev`/`prebuild` copies the generated
WASM module there when `zig build wasm-quic` has already produced it.

Build the complete static demo export, including the Zig-built WASM module:

```bash
npm --prefix demo/next install
npm --prefix demo/next run build:demo
```

Package the export as the deployable document root:

```bash
npm --prefix demo/next run package:demo
```

Run a full Next.js development server behind `h3-server`:

```bash
npm --prefix demo/next run build:wasm
npm --prefix demo/next run dev
./zig-out/bin/h3-server --host 127.0.0.1 --port 4433 --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3000 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```
