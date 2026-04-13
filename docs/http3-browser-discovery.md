# HTTP/3 Browser Discovery

This document covers the manual in-repo browser discovery path for
`coquic h3-server`.

The bootstrap flow is:

1. A browser first loads `https://...` over TCP/TLS.
2. The bootstrap response advertises `Alt-Svc: h3=":<udp-port>"; ma=<seconds>`.
3. A later navigation or reload can switch the origin to HTTP/3 over QUIC.

## Prerequisites

- Enter the dev shell with `nix develop`.
- The repo’s Nix shell now provides a pinned HTTP/3-capable `curl` and
  `mkcert`. If you want the same client without entering the shell, use
  `nix run .#curl-http3 -- ...`.
- Build the binary with `zig build`.
- Prepare a document root, for example:

```bash
mkdir -p /tmp/coquic-site
printf 'hello-http3\n' > /tmp/coquic-site/index.html
```

- Use a browser-trusted certificate that covers the host you will open in the
  browser.

The test fixture certificate under `tests/fixtures/` is suitable for automated
tests, but browsers generally require a locally trusted certificate with SANs.
One practical option is `mkcert`:

```bash
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

That produces a certificate and key you can pass to `coquic h3-server`.

## Start The Server

This example keeps the TCP bootstrap origin and the UDP HTTP/3 endpoint on the
same numeric port:

```bash
./zig-out/bin/coquic h3-server \
  --host 127.0.0.1 \
  --port 4433 \
  --bootstrap-port 4433 \
  --alt-svc-max-age 60 \
  --document-root /tmp/coquic-site \
  --certificate-chain ./localhost+2.pem \
  --private-key ./localhost+2-key.pem
```

Adjust the certificate paths to match your local files. If you prefer
`https://localhost:4433/`, start the server with a certificate that covers
`localhost` and use a matching host in the URL.

## Automated Preflight

Before opening a browser, run the repo-owned smoke test:

```bash
nix develop -c bash tests/nix/http3_browser_discovery_test.sh
```

That test starts `coquic h3-server`, verifies the HTTPS bootstrap response
advertises `Alt-Svc`, and verifies direct `--http3-only` content retrieval with
the pinned Nix `curl`.

## Confirm The Bootstrap Response

Before using a browser, confirm that the HTTPS bootstrap response carries the
HTTP/3 advertisement:

```bash
curl -k -I https://127.0.0.1:4433/
```

Expected header:

```text
Alt-Svc: h3=":4433"; ma=60
```

You can also confirm that the UDP endpoint itself answers direct HTTP/3 without
falling back to TCP:

```bash
curl --http3-only -k -I https://127.0.0.1:4433/
```

## Chromium

1. Trust the certificate in the OS or browser trust store before opening the
   site.
2. Open `https://127.0.0.1:4433/` once. The first load is expected to use
   HTTPS over TCP because the browser is only learning the `Alt-Svc` mapping.
3. Open DevTools, go to Network, and enable the `Protocol` column if it is not
   already visible.
4. Reload the page. After the bootstrap response has been cached, subsequent
   requests should show `h3` in the `Protocol` column.
5. If the browser keeps using HTTP/1.1 or HTTP/2, verify:
   - the certificate is trusted
   - the response contains `Alt-Svc`
   - no proxy or VPN is intercepting local traffic

## Firefox

1. Trust the certificate for the same host you will visit.
2. Open `https://127.0.0.1:4433/` once to populate the `Alt-Svc` cache.
3. Reload the page.
4. Check the request details in DevTools Network, or inspect
   `about:networking#http3`, to confirm that the connection upgraded to HTTP/3.
5. If needed, confirm that `network.http.http3.enable` is enabled in
   `about:config`.

## Notes

- The bootstrap listener only serves `GET` and `HEAD`.
- Browser discovery is stateful: the first HTTPS request teaches the browser
  about the `Alt-Svc` mapping, and the next request is the one that should
  switch to HTTP/3.
- `Alt-Svc` is advertised from the bootstrap HTTPS origin, but the advertised
  port is always the UDP HTTP/3 listener port.
