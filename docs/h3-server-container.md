# h3-server Container Demo

This guide builds and runs the standalone `h3-server` in a local Docker image.
Certificates are mounted at runtime and are not baked into the image.

## Build A Standalone musl Binary

Use the verified shell for quictls + musl builds with an explicit one-shot
command:

```bash
nix develop .#quictls-musl -c zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false
```

The resulting binary is:

```text
./zig-out/bin/h3-server
```

## Build The Docker Image

From the repo root:

```bash
docker build -t coquic-h3-server:dev -f docker/h3-server/Dockerfile .
```

## Run The Container

Publish both TCP and UDP on the same port and mount cert/key read-only:

```bash
docker run --rm \
  -p 4433:4433/tcp \
  -p 4433:4433/udp \
  -v "$(pwd)/localhost+2.pem:/run/certs/cert.pem:ro" \
  -v "$(pwd)/localhost+2-key.pem:/run/certs/key.pem:ro" \
  coquic-h3-server:dev
```

If your cert files are elsewhere, adjust only the host-side paths; keep
container paths as `/run/certs/cert.pem` and `/run/certs/key.pem`.

## Demo Page Behavior

The bundled page now defaults to `Showcase` mode and exposes a visible
`Showcase`/`Technical` toggle.

- Use `Run Live Checks` to run browser-side same-origin probes.
- The page performs `POST /_coquic/inspect` and `POST /_coquic/echo` from
  browser JavaScript and reports the observed results in-page.
- The UI text includes `coquic.minhuw.dev:4433` as a public-demo deployment
  target string. For local validation, use the actual local URL/origin you are
  serving (for example, `https://localhost:4433/`).

## Browser Validation Flow

1. Open `https://localhost:4433/` once. The first load uses the bootstrap HTTPS
   path before Alt-Svc state is cached.
2. Reload the page and check Chrome DevTools Network `Protocol` for the main
   document request. Confirm it shows `h3`.
3. Switch to `Technical` mode and review the same-origin probe output for
   `/_coquic/inspect` and `/_coquic/echo`.
4. Treat page-visible diagnostics as application-level checks only; use DevTools
   transport details as the source of truth for HTTP/3 verification.
