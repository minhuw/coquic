# Standalone h3-server And Demo Container Design

Date: 2026-04-17
Repo: `coquic`
Status: Approved

## Summary

Replace the `coquic h3-server` subcommand with a standalone `h3-server`
executable and add a Docker packaging path for a minimal demo site that serves a
single `Hello HTTP/3` page over the existing HTTP/3 plus HTTPS bootstrap flow.

This slice does not redesign the HTTP/3 protocol engine. It repackages the
existing server runtime behind its own binary, keeps the browser-discovery
behavior intact, and adds a container image that:

- bundles a tiny static document root
- requires the certificate and private key to be mounted at runtime
- exposes the same TCP bootstrap and UDP HTTP/3 port

## Problem

The repo currently exposes the HTTP/3 server as `coquic h3-server`, which is
good enough for local experimentation but not ideal for packaging or demo
distribution:

- the server is not a first-class binary like `coquic-perf`
- container entrypoints have to route through the generic `coquic` CLI
- the repo has no plain Dockerfile-based packaging path for a minimal browser
  demo
- the browser discovery docs still assume the integrated subcommand model

The desired outcome is a narrow, concrete server artifact that can be built,
packaged, and run directly.

## Goals

- Produce a standalone `h3-server` binary from `zig build`.
- Remove `h3-server` support from the `coquic` CLI.
- Keep the existing HTTP/3 server runtime behavior unchanged:
  - static file serving from `--document-root`
  - HTTPS bootstrap with `Alt-Svc`
  - shared TCP bootstrap and UDP HTTP/3 port model
- Add a Dockerfile that packages:
  - the standalone `h3-server` binary
  - a bundled `index.html` containing only `Hello HTTP/3`
- Require certificate and key files to be mounted into the container at runtime.
- Preserve the existing browser-discovery smoke path with the new binary name.

## Non-Goals

- No compatibility alias that keeps `coquic h3-server` working.
- No redesign of the HTTP/3 core, bootstrap protocol logic, or static file
  behavior.
- No certificate generation, embedded credentials, or image-baked private keys.
- No in-container source build workflow; the Dockerfile is for packaging a
  prebuilt binary, not replacing the repo's Nix/Zig build environment.
- No new dynamic web application layer or templating system.

## Chosen Architecture

### Binary Ownership

`h3-server` becomes a first-class executable, similar in spirit to
`coquic-perf`.

The binary split is:

- `coquic`
  - continues to own the HTTP/0.9 runtime and `h3-client`
- `h3-server`
  - becomes the only supported CLI entrypoint for the HTTP/3 server runtime
- `coquic-perf`
  - remains unchanged

`src/main.cpp` must stop recognizing `h3-server`. The change should be explicit
rather than accidental: the generic binary should no longer advertise or accept
that subcommand.

### Runtime Boundaries

The existing HTTP/3 server implementation remains in `src/http3/`. This change
is about binary boundaries and CLI ownership, not reimplementing server logic.

The server-specific entrypoint should:

- parse direct arguments like `h3-server --host ... --port ...`
- build the same `Http3RuntimeConfig` currently used by the server path
- call the existing runtime code for:
  - UDP HTTP/3 serving
  - HTTPS bootstrap serving
  - static file responses

To support the new binary cleanly, `src/http3/http3_runtime.*` should expose a
server-specific parse-and-run path instead of depending on the subcommand being
present in `argv[1]`.

The minimum refactor is:

- add a dedicated `src/main_h3_server.cpp`
- add a server-specific argument parser
- extract or expose a server-specific runtime entrypoint from the existing
  `run_http3_runtime` server branch

The client-side code path stays in `coquic` and continues to use the existing
client runtime path in this slice.

### Build Graph

`build.zig` should install three executables:

- `coquic`
- `h3-server`
- `coquic-perf`

The new `h3-server` binary should link against the same shared project library
and TLS/backend dependencies as the existing server path. This keeps protocol
logic centralized and avoids a duplicate server implementation.

### Container Packaging Model

The repo should add a dedicated Docker packaging directory for the standalone
server:

- `docker/h3-server/Dockerfile`
- `docker/h3-server/www/index.html`

The Dockerfile should package a prebuilt `h3-server` artifact plus the demo
document root. It should not try to recreate the repo's Nix-based toolchain
inside Docker.

Because the default developer build may rely on the local toolchain and shared
libraries, the Docker path should explicitly target the repo's musl-friendly
server build before packaging. The documented build prerequisite is:

```bash
zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false
```

After that build, the Dockerfile copies:

- `zig-out/bin/h3-server`
- the demo site directory containing `index.html`

The runtime image should contain:

- `/usr/local/bin/h3-server`
- `/app/www/index.html`

No source tree, build tools, or credentials are part of the runtime image.

### Demo Site

The packaged document root contains a single `index.html` whose body is only:

```html
Hello HTTP/3
```

No CSS, JavaScript, images, or extra assets are part of this slice.

### TLS Contract

The image must not contain any credentials.

The runtime contract is:

- certificate chain mounted read-only at `/run/certs/cert.pem`
- private key mounted read-only at `/run/certs/key.pem`

The image runtime contract is:

- `ENTRYPOINT ["/usr/local/bin/h3-server"]`
- `CMD ["--host","0.0.0.0","--port","4433","--bootstrap-port","4433","--document-root","/app/www","--certificate-chain","/run/certs/cert.pem","--private-key","/run/certs/key.pem"]`

This keeps the demo path predictable while still allowing callers to replace the
default command arguments on `docker run`.

### Port Model

The containerized server keeps the same browser-discovery model as the local
runtime:

- TCP on the configured port for HTTPS bootstrap
- UDP on the same configured port for HTTP/3

The docs must make it explicit that both protocols need to be published, for
example:

```bash
docker run --rm \
  -p 4433:4433/tcp \
  -p 4433:4433/udp \
  -v "$PWD/certs:/run/certs:ro" \
  coquic-h3-server:dev
```

## Testing

### Runtime And CLI Tests

Add focused tests that verify:

- the standalone `h3-server` argument parser accepts the current server flags
- `coquic` no longer accepts `h3-server`
- `coquic` still accepts `h3-client`
- the existing HTTP/3 server runtime behavior remains green

The intent is to test the binary split, not to duplicate the existing HTTP/3
protocol suite.

### Browser Discovery Smoke

Update the existing browser-discovery smoke flow to launch
`./zig-out/bin/h3-server` instead of `./zig-out/bin/coquic h3-server`.

The smoke contract remains:

- bootstrap HTTPS response includes `Alt-Svc`
- direct HTTP/3 fetch succeeds
- static content served from the configured document root is unchanged

### Container Packaging Check

Add a repo-owned packaging smoke check that validates:

- the Dockerfile builds after the documented musl `zig build` invocation
- the image contains the bundled hello page
- the image entrypoint points at `h3-server`
- the container contract expects mounted TLS files instead of embedded
  credentials

This check should live in `tests/nix/h3_server_container_smoke_test.sh` and run
`docker build` plus `docker image inspect` directly.

## Documentation

Update the browser discovery documentation to use the standalone binary name:

- `./zig-out/bin/h3-server`

Add a short container doc that covers:

- the required musl build command
- `docker build`
- runtime certificate mounting
- TCP and UDP port publishing
- the expectation that the first browser request is bootstrap HTTPS and the
  second request should upgrade to HTTP/3

The root `README.md` stays minimal; the detailed instructions belong in focused
docs.

## Acceptance Criteria

- `zig build` installs `zig-out/bin/h3-server`.
- `coquic` no longer accepts or documents `h3-server`.
- The standalone `h3-server` serves the existing HTTP/3 static site and HTTPS
  bootstrap flow.
- The browser-discovery smoke test passes using the standalone binary path.
- The repo contains a Dockerfile for packaging the standalone server demo.
- The packaged image bundles a single-page site whose body is `Hello HTTP/3`.
- The packaged image requires the certificate and key to be mounted at runtime.
