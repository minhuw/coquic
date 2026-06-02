# CoQUIC Next.js Demo

This is the framework-backed source for the browser demo. It owns the home
page plus the workbench, performance, QA, interop, and coverage routes. Browser
runtime assets live in `public/`, and `predev`/`prebuild` copies the generated
WASM module there when `zig build wasm-quic` has already produced it.

Build the complete production demo server bundle, including the Zig-built WASM
module:

```bash
npm --prefix site/next install
npm --prefix site/next run build:demo
```

Package the standalone Next.js server bundle:

```bash
npm --prefix site/next run package:demo
```

The `/qa` page calls same-origin `/rag-api/*`; browser code must not call
`127.0.0.1:8787` directly. In development and production, Next proxies
`/rag-api/*` to the localhost-only FastAPI service:

```bash
rag/scripts/run-qa-api --log-level info
npm --prefix site/next run dev
```

Those commands run two local services:

```text
127.0.0.1:3001  Next.js server and browser entrypoint
127.0.0.1:8787  FastAPI RAG API
```

Open `http://127.0.0.1:3001/qa`.

For deployment, `h3-server` reverse-proxies all public traffic to the local
Next.js server, and Next proxies `/rag-api/*` to FastAPI. Keep both Node/Next
and FastAPI bound to loopback on the server. The deploy runner starts FastAPI
when `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `COQUIC_QDRANT_URL`, and
`COQUIC_QDRANT_API_KEY` are available in `/etc/coquic-demo/rag.env`.
The `/rag-api/*` proxy does not forward `X-Forwarded-For`, because the public
request header is spoofable in this deployment path.

Run a full Next.js development server behind `h3-server`:

```bash
npm --prefix site/next run build:wasm
npm --prefix site/next run dev
./zig-out/bin/h3-server --host 127.0.0.1 --port 4433 --bootstrap-port 4433 \
  --reverse-proxy http://127.0.0.1:3001 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```
