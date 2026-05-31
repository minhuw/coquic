# CoQUIC Next.js Demo

This is the framework-backed source for the browser demo. It owns the home
page plus the workbench, performance, QA, interop, and coverage routes. Browser
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

The `/qa` page is a static client for the separate RAG API. Browser code always
calls same-origin `/rag-api/*`; it must not call `127.0.0.1:8787` directly.
In development, Next proxies `/rag-api/*` to the localhost-only FastAPI service:

```bash
rag/scripts/run-qa-api --log-level info
npm --prefix demo/next run dev
```

Those commands run two local services:

```text
127.0.0.1:3001  Next.js dev server and browser entrypoint
127.0.0.1:8787  FastAPI RAG API
```

Open `http://127.0.0.1:3001/qa`.

For deployment, keep FastAPI bound to `127.0.0.1:8787` on the server and make
the public web server reverse-proxy `/rag-api/*` to it. The exported static
Next.js files cannot proxy API requests by themselves.

Run a full Next.js development server behind `h3-server`:

```bash
npm --prefix demo/next run build:wasm
npm --prefix demo/next run dev
./zig-out/bin/h3-server --host 127.0.0.1 --port 4433 --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3001 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```
