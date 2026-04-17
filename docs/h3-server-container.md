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

## Browser Validation

Open `https://localhost:4433/` once, then reload the page. In Chrome DevTools
Network, confirm the `Protocol` column shows `h3` on the reload.
