# CoQUIC Next.js Demo

This is the framework-backed source for the browser demo. It owns the home
page plus the workbench, performance, interop, and coverage routes. Runtime
assets still live in `demo/wasm-quic/`, and `predev`/`prebuild` links them into
`public/` for local Next.js serving.

Build a static export:

```bash
npm --prefix demo/next install
npm --prefix demo/next run build
```

Run a full Next.js development server behind `h3-server`:

```bash
npm --prefix demo/next run dev
./zig-out/bin/h3-server --host 127.0.0.1 --port 4433 --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3000 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```
