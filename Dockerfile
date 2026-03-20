FROM nixos/nix:2.28.3 AS builder

ENV NIX_CONFIG="experimental-features = nix-command flakes"

WORKDIR /src
COPY build.zig flake.nix flake.lock ./
COPY src ./src

RUN nix develop .#interop-image -c bash -lc 'zig build -Dtls_backend=quictls'

RUN nix develop .#interop-image -c bash -lc 'set -euo pipefail \
    && binary=/src/zig-out/bin/coquic \
    && mkdir -p /runtime-root/usr/local/bin \
    && cp "${binary}" /runtime-root/usr/local/bin/coquic \
    && readelf -l "${binary}" \
         | awk "/Requesting program interpreter/ { gsub(/[][]/, \"\", \$NF); print \$NF; }" \
         > /tmp/coquic-runtime-paths.txt \
    && ldd "${binary}" \
         | awk '"'"'$3 ~ /^\// { print $3; next } $1 ~ /^\// { print $1; }'"'"' \
         >> /tmp/coquic-runtime-paths.txt \
    && sort -u /tmp/coquic-runtime-paths.txt \
         | while read -r path; do \
             mkdir -p "/runtime-root$(dirname "${path}")"; \
             cp -L "${path}" "/runtime-root${path}"; \
           done'

FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=builder /runtime-root/ /
COPY scripts/run_endpoint.sh /run_endpoint.sh

RUN chmod +x /run_endpoint.sh /usr/local/bin/coquic \
    && ln -sf /run_endpoint.sh /entrypoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
