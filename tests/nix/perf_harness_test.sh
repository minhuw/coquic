#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
script="${repo_root}/bench/run-host-matrix.sh"
flake="${repo_root}/flake.nix"
ignore_file="${repo_root}/.gitignore"
msquic_perf="${repo_root}/bench/msquic-perf/src/main.rs"
mvfst_perf="${repo_root}/bench/mvfst-perf/mvfst-perf.cpp"
lsquic_perf="${repo_root}/bench/lsquic-perf/lsquic-perf.c"
quicly_perf="${repo_root}/bench/quicly-perf/quicly-perf.c"

[ -f "${script}" ] || {
  echo "missing harness script: ${script}" >&2
  exit 1
}

[ -f "${msquic_perf}" ] || {
  echo "missing MSQUIC perf client: ${msquic_perf}" >&2
  exit 1
}

[ -f "${mvfst_perf}" ] || {
  echo "missing mvfst perf client: ${mvfst_perf}" >&2
  exit 1
}

[ -f "${lsquic_perf}" ] || {
  echo "missing native LSQUIC perf client: ${lsquic_perf}" >&2
  exit 1
}

[ -f "${quicly_perf}" ] || {
  echo "missing native quicly perf client: ${quicly_perf}" >&2
  exit 1
}

grep -F -- 'image_attr="${PERF_IMAGE_ATTR:-perf-image-quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing perf image attr default in harness script' >&2
  exit 1
}

grep -F -- 'image_tag="${PERF_IMAGE_TAG:-coquic-perf:quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing perf image tag default in harness script' >&2
  exit 1
}

grep -F -- 'congestion_controls="${PERF_CONGESTION_CONTROLS:-newreno cubic bbr copa}"' "${script}" >/dev/null || {
  echo 'missing congestion-control default in harness script' >&2
  exit 1
}

grep -F -- 'client_impl="${PERF_CLIENT_IMPL:-coquic}"' "${script}" >/dev/null || {
  echo 'missing client implementation default in harness script' >&2
  exit 1
}

grep -F -- 'server_impl="${PERF_SERVER_IMPL:-coquic}"' "${script}" >/dev/null || {
  echo 'missing server implementation default in harness script' >&2
  exit 1
}

grep -F -- 'nix build --print-out-paths ".#${image_attr}"' "${script}" >/dev/null || {
  echo 'missing nix image build in harness script' >&2
  exit 1
}

grep -F -- 'docker load -i "${image_path}"' "${script}" >/dev/null || {
  echo 'missing docker image load in harness script' >&2
  exit 1
}

grep -F -- 'docker network create "${network_name}"' "${script}" >/dev/null || {
  echo 'missing Docker bridge network creation in harness script' >&2
  exit 1
}

grep -F -- 'topology=docker-bridge-two-containers' "${script}" >/dev/null || {
  echo 'missing Docker bridge topology marker in harness script' >&2
  exit 1
}

grep -F -- 'client_impl=${client_impl}' "${script}" >/dev/null || {
  echo 'missing client implementation environment marker in harness script' >&2
  exit 1
}

grep -F -- 'server_impl=${server_impl}' "${script}" >/dev/null || {
  echo 'missing server implementation environment marker in harness script' >&2
  exit 1
}

grep -F -- 'coquic|quic-go|quinn|picoquic|msquic|quiche|quicly|google-quiche|tquic|mvfst|s2n-quic|xquic|aioquic|ngtcp2|lsquic|neqo)' "${script}" >/dev/null || {
  echo 'missing quic-go implementation validation in harness script' >&2
  exit 1
}

grep -F -- 'coquic|quic-go|quinn|picoquic|msquic|quiche|quicly|google-quiche|tquic|mvfst|s2n-quic|xquic|aioquic|ngtcp2|lsquic|neqo)' "${script}" >/dev/null || {
  echo 'missing quinn implementation validation in harness script' >&2
  exit 1
}

grep -F -- 'coquic|quic-go|quinn|picoquic|msquic|quiche|quicly|google-quiche|tquic|mvfst|s2n-quic|xquic|aioquic|ngtcp2|lsquic|neqo)' "${script}" >/dev/null || {
  echo 'missing picoquic implementation validation in harness script' >&2
  exit 1
}

grep -F -- 'unsupported server implementation' "${script}" >/dev/null || {
  echo 'missing server implementation validation in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quicgo-perf' "${script}" >/dev/null || {
  echo 'missing quic-go Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quinn-perf' "${script}" >/dev/null || {
  echo 'missing quinn Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/picoquic-perf' "${script}" >/dev/null || {
  echo 'missing picoquic Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/msquic-perf' "${script}" >/dev/null || {
  echo 'missing MSQUIC Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quiche-perf' "${script}" >/dev/null || {
  echo 'missing quiche Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quicly-perf' "${script}" >/dev/null || {
  echo 'missing quicly Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/google-quiche-perf' "${script}" >/dev/null || {
  echo 'missing Google QUICHE Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/tquic-perf' "${script}" >/dev/null || {
  echo 'missing TQUIC Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/mvfst-perf' "${script}" >/dev/null || {
  echo 'missing mvfst Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/s2n-quic-perf' "${script}" >/dev/null || {
  echo 'missing s2n-quic Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/xquic-perf' "${script}" >/dev/null || {
  echo 'missing xquic Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/aioquic-perf' "${script}" >/dev/null || {
  echo 'missing aioquic Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/ngtcp2-perf' "${script}" >/dev/null || {
  echo 'missing ngtcp2 Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/lsquic-perf' "${script}" >/dev/null || {
  echo 'missing LSQUIC Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/neqo-perf' "${script}" >/dev/null || {
  echo 'missing Neqo Docker entrypoint override in harness script' >&2
  exit 1
}

grep -F -- "'client_impl': client_impl" "${script}" >/dev/null || {
  echo 'missing client implementation manifest field in harness script' >&2
  exit 1
}

grep -F -- "'server_impl': server_impl" "${script}" >/dev/null || {
  echo 'missing server implementation manifest field in harness script' >&2
  exit 1
}

grep -F -- 'handle_signal() {' "${script}" >/dev/null || {
  echo 'missing signal handler in harness script' >&2
  exit 1
}

grep -F -- "trap cleanup EXIT" "${script}" >/dev/null || {
  echo 'missing EXIT cleanup trap in harness script' >&2
  exit 1
}

grep -F -- "trap 'handle_signal INT' INT" "${script}" >/dev/null || {
  echo 'missing INT signal trap in harness script' >&2
  exit 1
}

grep -F -- "trap 'handle_signal TERM' TERM" "${script}" >/dev/null || {
  echo 'missing TERM signal trap in harness script' >&2
  exit 1
}

grep -F -- 'exit 130' "${script}" >/dev/null || {
  echo 'missing INT signal exit code in harness script' >&2
  exit 1
}

grep -F -- 'exit 143' "${script}" >/dev/null || {
  echo 'missing TERM signal exit code in harness script' >&2
  exit 1
}

if grep -F -- 'trap cleanup EXIT INT TERM' "${script}" >/dev/null; then
  echo 'unexpected direct cleanup trap for INT/TERM in harness script' >&2
  exit 1
fi

if grep -F -- 'std::mem::forget(connection)' "${msquic_perf}" >/dev/null; then
  echo 'MSQUIC CRR must drop completed connections to avoid exhausting file descriptors' >&2
  exit 1
fi

grep -F -- 'client->unregisterStreamWriteCallback(id)' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst teardown must unregister pending stream write callbacks before closing' >&2
  exit 1
}

grep -F -- '#include <quic/congestion_control/CongestionControllerFactory.h>' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst perf client must include the congestion-controller factory API' >&2
  exit 1
}

grep -F -- '#include <quic/congestion_control/ServerCongestionControllerFactory.h>' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst perf server must include the server congestion-controller factory API' >&2
  exit 1
}

grep -F -- 'std::make_shared<quic::DefaultCongestionControllerFactory>()' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst client must set a congestion-controller factory to avoid per-transport warning spam' >&2
  exit 1
}

grep -F -- 'std::make_shared<quic::ServerCongestionControllerFactory>()' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst server must set a congestion-controller factory explicitly' >&2
  exit 1
}

grep -F -- 'constexpr uint32_t kServerHostId = 1;' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst perf server must use a nonzero host id to avoid default host-id warning spam' >&2
  exit 1
}

grep -F -- 'server->setHostId(kServerHostId);' "${mvfst_perf}" >/dev/null || {
  echo 'mvfst perf server must set the nonzero host id before start' >&2
  exit 1
}

if grep -F -- 'apps.${system}.${binary_attr}.program' "${script}" >/dev/null; then
  echo 'unexpected app fallback in harness script' >&2
  exit 1
fi

if grep -F -- 'builtins.currentSystem' "${script}" >/dev/null; then
  echo 'unexpected system eval fallback in harness script' >&2
  exit 1
fi

if grep -F -- 'package_attr=' "${script}" >/dev/null; then
  echo 'unexpected package attr rewrite fallback in harness script' >&2
  exit 1
fi

if grep -F -- '--network host' "${script}" >/dev/null; then
  echo 'unexpected host-network Docker flag in bridge harness script' >&2
  exit 1
fi

if grep -F -- '--cap-add IPC_LOCK' "${script}" >/dev/null; then
  echo 'unexpected container capability override in bridge harness script' >&2
  exit 1
fi

if grep -F -- 'perf_bin=' "${script}" >/dev/null; then
  echo 'unexpected direct perf binary resolution in Docker harness script' >&2
  exit 1
fi

grep -F -- 'tests/fixtures:/certs:ro' "${script}" >/dev/null || {
  echo 'missing mounted test certificate directory in harness script' >&2
  exit 1
}

grep -F -- '--certificate-chain /certs/quic-server-cert.pem' "${script}" >/dev/null || {
  echo 'missing mounted server certificate path in harness script' >&2
  exit 1
}

grep -F -- '--private-key /certs/quic-server-key.pem' "${script}" >/dev/null || {
  echo 'missing mounted server key path in harness script' >&2
  exit 1
}

grep -F -- 'environment.txt' "${script}" >/dev/null || {
  echo 'missing environment snapshot in harness script' >&2
  exit 1
}

grep -F -- '"${results_root}"/*.cid' "${script}" >/dev/null || {
  echo 'missing stale server cid cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker rm -f "${server_name}"' "${script}" >/dev/null || {
  echo 'missing server container cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker rm -f "${client_name}"' "${script}" >/dev/null || {
  echo 'missing client container cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker network rm "${network_name}"' "${script}" >/dev/null || {
  echo 'missing Docker network cleanup in harness script' >&2
  exit 1
}

grep -F -- 'timeout --kill-after=5s "${run_timeout_seconds}s" docker run --rm' "${script}" >/dev/null || {
  echo 'missing bounded client container run in harness script' >&2
  exit 1
}

grep -F -- 'PERF_MSQUIC_BULK_TOTAL_BYTES:-134217728' "${script}" >/dev/null || {
  echo 'missing fixed-size MSQUIC paired bulk override in harness script' >&2
  exit 1
}

grep -F -- '--congestion-control "${congestion_control}"' "${script}" >/dev/null || {
  echo 'missing congestion-control forwarding in harness script' >&2
  exit 1
}

grep -F -- 'PERF_CONGESTION_CONTROLS   space-separated algorithms to run' "${script}" >/dev/null || {
  echo 'missing congestion-control usage text in harness script' >&2
  exit 1
}

grep -F -- 'usage: bash bench/run-host-matrix.sh [--preset smoke|ci]' "${script}" >/dev/null || {
  echo 'missing ci preset in harness usage' >&2
  exit 1
}

grep -F -- 'ci)' "${script}" >/dev/null || {
  echo 'missing ci preset case in harness script' >&2
  exit 1
}

smoke_runs=(
  '"socket bulk download 0 65536 65536 1 1 1 0ms 5s"'
  '"socket rr stay 32 48 32 1 1 4 0ms 5s"'
  '"socket crr stay 24 24 8 1 2 1 0ms 5s"'
)

for run in "${smoke_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing smoke run tuple: ${run}" >&2
    exit 1
  }
done

ci_runs=(
  '"socket bulk download 0 1048576 none 4 1 1 0ms 60s"'
  '"socket rr stay 32 32 none 1 128 4 5s 45s"'
  '"socket crr stay 32 32 none 1 64 1 5s 45s"'
)

for run in "${ci_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing ci run tuple: ${run}" >&2
    exit 1
  }
done

if grep -F -- '"io_uring ' "${script}" >/dev/null; then
  echo 'unexpected io_uring run tuple in harness script' >&2
  exit 1
fi

grep -F -- 'perf-image-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing perf image package export in flake.nix' >&2
  exit 1
}

for attr in \
  'perf-image-coquic-quictls-musl' \
  'perf-image-quic-go-quictls-musl' \
  'perf-image-quinn-quictls-musl' \
  'perf-image-picoquic-quictls-musl' \
  'perf-image-msquic-quictls-musl' \
  'perf-image-quiche-quictls-musl' \
  'perf-image-quicly-quictls-musl' \
  'perf-image-google-quiche-quictls-musl' \
  'perf-image-tquic-quictls-musl' \
  'perf-image-mvfst-quictls-musl' \
  'perf-image-s2n-quic-quictls-musl' \
  'perf-image-xquic-quictls-musl' \
  'perf-image-aioquic-quictls-musl' \
  'perf-image-ngtcp2-quictls-musl' \
  'perf-image-lsquic-quictls-musl' \
  'perf-image-neqo-quictls-musl'; do
  grep -F -- "${attr}" "${flake}" >/dev/null || {
    echo "missing split perf image package export in flake.nix: ${attr}" >&2
    exit 1
  }
done

grep -F -- 'quicgoPerfClient = pkgs.buildGoModule' "${flake}" >/dev/null || {
  echo 'missing quic-go perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${quicgoPerfClient}/bin/quicgo-perf $out/usr/local/bin/quicgo-perf' "${flake}" >/dev/null || {
  echo 'missing quic-go perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'quinnPerfClient = pkgs.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing quinn perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${quinnPerfClient}/bin/quinn-perf $out/usr/local/bin/quinn-perf' "${flake}" >/dev/null || {
  echo 'missing quinn perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'picoquicPerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing picoquic perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${picoquicPerfClient}/bin/picoquic-perf $out/usr/local/bin/picoquic-perf' "${flake}" >/dev/null || {
  echo 'missing picoquic perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'msquicPerfClient = pkgs.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing MSQUIC perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${msquicPerfClient}/bin/msquic-perf $out/usr/local/bin/msquic-perf' "${flake}" >/dev/null || {
  echo 'missing MSQUIC perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'quichePerfClient = pkgs.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing quiche perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${quichePerfClient}/bin/quiche-perf $out/usr/local/bin/quiche-perf' "${flake}" >/dev/null || {
  echo 'missing quiche perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'quiclyPerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing quicly perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'perfSource = ./bench/quicly-perf/quicly-perf.c;' "${flake}" >/dev/null || {
  echo 'quicly perf client package must build the native C adapter' >&2
  exit 1
}

grep -F -- 'cmake --build . --target quicly' "${flake}" >/dev/null || {
  echo 'quicly perf client package must build the quicly library target' >&2
  exit 1
}

grep -F -- 'libquicly.a' "${flake}" >/dev/null || {
  echo 'quicly perf client package must link directly against libquicly' >&2
  exit 1
}

grep -F -- '#include "quicly.h"' "${quicly_perf}" >/dev/null || {
  echo 'quicly perf client must use the native quicly API' >&2
  exit 1
}

grep -F -- 'quicly_open_stream' "${quicly_perf}" >/dev/null || {
  echo 'quicly perf client must create streams through the native quicly API' >&2
  exit 1
}

if grep -F -- 'subprocess' "${quicly_perf}" >/dev/null; then
  echo 'quicly perf client must not shell out through subprocess' >&2
  exit 1
fi

grep -F -- 'ln -s ${quiclyPerfClient}/bin/quicly-perf $out/usr/local/bin/quicly-perf' "${flake}" >/dev/null || {
  echo 'missing quicly perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'googleQuichePerfClient = pkgs.buildBazelPackage' "${flake}" >/dev/null || {
  echo 'missing Google QUICHE perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${googleQuichePerfClient}/bin/google-quiche-perf $out/usr/local/bin/google-quiche-perf' "${flake}" >/dev/null || {
  echo 'missing Google QUICHE perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'tquicPerfClient = pkgs.rust_1_88.packages.stable.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing TQUIC perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${tquicPerfClient}/bin/tquic-perf $out/usr/local/bin/tquic-perf' "${flake}" >/dev/null || {
  echo 'missing TQUIC perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'mvfstPerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing mvfst perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${mvfstPerfClient}/bin/mvfst-perf $out/usr/local/bin/mvfst-perf' "${flake}" >/dev/null || {
  echo 'missing mvfst perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 's2nQuicPerfClient = pkgs.rust_1_88.packages.stable.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing s2n-quic perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${s2nQuicPerfClient}/bin/s2n-quic-perf $out/usr/local/bin/s2n-quic-perf' "${flake}" >/dev/null || {
  echo 'missing s2n-quic perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'xquicPerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing xquic perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${xquicPerfClient}/bin/xquic-perf $out/usr/local/bin/xquic-perf' "${flake}" >/dev/null || {
  echo 'missing xquic perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'aioquicPerfClient = pkgs.stdenvNoCC.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing aioquic perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${aioquicPerfClient}/bin/aioquic-perf $out/usr/local/bin/aioquic-perf' "${flake}" >/dev/null || {
  echo 'missing aioquic perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'ngtcp2PerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing ngtcp2 perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${ngtcp2PerfClient}/bin/ngtcp2-perf $out/usr/local/bin/ngtcp2-perf' "${flake}" >/dev/null || {
  echo 'missing ngtcp2 perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'lsquicPerfClient = pkgs.stdenv.mkDerivation' "${flake}" >/dev/null || {
  echo 'missing LSQUIC perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'perfSource = ./bench/lsquic-perf/lsquic-perf.c;' "${flake}" >/dev/null || {
  echo 'LSQUIC perf client package must build the native C adapter' >&2
  exit 1
}

grep -F -- 'cmake --build . --target lsquic' "${flake}" >/dev/null || {
  echo 'LSQUIC perf client package must build the LSQUIC library target' >&2
  exit 1
}

grep -F -- 'src/liblsquic/liblsquic.a' "${flake}" >/dev/null || {
  echo 'LSQUIC perf client package must link directly against liblsquic' >&2
  exit 1
}

grep -F -- '#include "lsquic.h"' "${lsquic_perf}" >/dev/null || {
  echo 'LSQUIC perf client must use the native LSQUIC API' >&2
  exit 1
}

grep -F -- 'lsquic_conn_make_stream' "${lsquic_perf}" >/dev/null || {
  echo 'LSQUIC perf client must create streams through the native LSQUIC API' >&2
  exit 1
}

if grep -F -- 'subprocess' "${lsquic_perf}" >/dev/null; then
  echo 'LSQUIC perf client must not shell out through subprocess' >&2
  exit 1
fi

grep -F -- 'ln -s ${lsquicPerfClient}/bin/lsquic-perf $out/usr/local/bin/lsquic-perf' "${flake}" >/dev/null || {
  echo 'missing LSQUIC perf client in perf image overlay' >&2
  exit 1
}

grep -F -- 'neqoPerfClient = pkgs.rustPlatform.buildRustPackage' "${flake}" >/dev/null || {
  echo 'missing Neqo perf client package in flake.nix' >&2
  exit 1
}

grep -F -- 'ln -s ${neqoPerfClient}/bin/neqo-perf $out/usr/local/bin/neqo-perf' "${flake}" >/dev/null || {
  echo 'missing Neqo perf client in perf image overlay' >&2
  exit 1
}

grep -F -- '.bench-results/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark results ignore rule' >&2
  exit 1
}

grep -F -- 'bench/*/target/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark Rust target ignore rule' >&2
  exit 1
}

if [ "${PERF_HARNESS_TEST_REAL_IMAGE:-0}" = 1 ]; then
  image_path="$(nix build --no-link --print-out-paths .#perf-image-quictls-musl)"
  [ -f "${image_path}" ] || {
    echo 'real perf image package did not produce a tarball path' >&2
    exit 1
  }
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
fake_bin_dir="${tmp_dir}/fake-bin"
fake_image="${tmp_dir}/fake-image.tar"
results_root="${tmp_dir}/results"
log_path="${tmp_dir}/invocations.log"
mkdir -p "${fake_bin_dir}" "${results_root}"
touch "${fake_image}"

cat > "${fake_bin_dir}/nix" <<'FAKE_NIX'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'nix\t%s\n' "$*" >>"${log_path}"
if [ "$1" = 'build' ] && [ "$2" = '--print-out-paths' ] && [ "$3" = '.#perf-image-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_IMAGE:?}"
  exit 0
fi
if [ "$1" = 'build' ] && [ "$2" = '--no-link' ] && [ "$3" = '--print-out-paths' ] && [ "$4" = '.#perf-image-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_IMAGE:?}"
  exit 0
fi
exec /usr/bin/env nix "$@"
FAKE_NIX
chmod +x "${fake_bin_dir}/nix"

cat > "${fake_bin_dir}/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'docker\t%s\n' "$*" >>"${log_path}"
case "$1" in
  load)
    [ "$2" = '-i' ] || {
      echo 'expected docker load -i' >&2
      exit 1
    }
    ;;
  image)
    [ "$2" = 'inspect' ] || {
      echo 'unexpected docker image command' >&2
      exit 1
    }
    ;;
  network)
    case "$2" in
      create)
        printf '%s\n' "${3:-fake-network}"
        ;;
      inspect)
        printf '[{"Name":"%s"}]\n' "${3:-fake-network}"
        ;;
      rm)
        ;;
      *)
        echo "unexpected docker network command: $2" >&2
        exit 1
        ;;
    esac
    ;;
  version)
    echo 'fake docker version'
    ;;
  info)
    echo 'fake docker info'
    ;;
  run)
    shift
    detached=0
    name=''
    args=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -d)
          detached=1
          shift
          ;;
        --rm)
          shift
          ;;
        --name)
          name="$2"
          shift 2
          ;;
        --entrypoint)
          args+=("$1" "$2")
          shift 2
          ;;
        --network|--cpuset-cpus|-v)
          shift 2
          ;;
        --network=*)
          shift
          ;;
        *)
          args+=("$1")
          shift
          ;;
      esac
    done
    role_index=1
    if [ "${args[0]:-}" = 'coquic-perf:quictls-musl' ]; then
      role_index=1
    fi
    if [ "${args[0]:-}" = '--entrypoint' ]; then
      role_index=3
    fi
    role="${args[${role_index}]:-}"
    congestion_control=''
    for ((i = 0; i < ${#args[@]}; i++)); do
      if [ "${args[$i]}" = '--congestion-control' ]; then
        congestion_control="${args[$((i + 1))]}"
      fi
    done
    case "${congestion_control}" in
      newreno|cubic|bbr|copa|default)
        ;;
      *)
        echo "unexpected congestion-control: ${congestion_control}; args=${args[*]}" >&2
        exit 1
        ;;
    esac
    if [ "${detached}" -eq 1 ]; then
      [ "${role}" = 'server' ] || {
        echo "expected server role in detached docker run, got args=${args[*]}" >&2
        exit 1
      }
      printf 'fake-server-container-id\n'
      exit 0
    fi
    [ "${role}" = 'client' ] || {
      echo "expected client role in docker run, got args=${args[*]}" >&2
      exit 1
    }
    json_out=''
    for ((i = 0; i < ${#args[@]}; i++)); do
      if [ "${args[$i]}" = '--json-out' ]; then
        json_out="${args[$((i + 1))]}"
      fi
    done
    [ "${json_out}" = '/results/result.json' ] || {
      echo "unexpected json out: ${json_out}" >&2
      exit 1
    }
    printf '{"status":"ok","mode":"fake","congestion_control":"%s"}\n' "${congestion_control}" >"${FAKE_RESULTS_ROOT}/result.json"
    echo 'status=ok mode=fake direction=download throughput_mib/s=1.000 throughput_gbit/s=0.008 requests/s=10.000'
    ;;
  logs)
    echo 'fake server log'
    ;;
  rm)
    ;;
  *)
    echo "unexpected docker command: $1" >&2
    exit 1
    ;;
esac
FAKE_DOCKER
chmod +x "${fake_bin_dir}/docker"

cat > "${fake_bin_dir}/timeout" <<'FAKE_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'timeout\t%s\n' "$*" >>"${log_path}"
if [ "${1:-}" = '--kill-after=5s' ]; then
  shift
fi
shift
exec "$@"
FAKE_TIMEOUT
chmod +x "${fake_bin_dir}/timeout"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
bash "${script}" --preset smoke >/dev/null

[ -f "${results_root}/environment.txt" ] || {
  echo 'behavioral harness test missing environment.txt' >&2
  exit 1
}

[ -f "${results_root}/manifest.json" ] || {
  echo 'behavioral harness test missing manifest.json' >&2
  exit 1
}

for run_name in \
  smoke-newreno-socket-bulk-s1-c1-q1 \
  smoke-newreno-socket-rr-s1-c1-q4 \
  smoke-newreno-socket-crr-s1-c2-q1 \
  smoke-cubic-socket-bulk-s1-c1-q1 \
  smoke-cubic-socket-rr-s1-c1-q4 \
  smoke-cubic-socket-crr-s1-c2-q1 \
  smoke-bbr-socket-bulk-s1-c1-q1 \
  smoke-bbr-socket-rr-s1-c1-q4 \
  smoke-bbr-socket-crr-s1-c2-q1 \
  smoke-copa-socket-bulk-s1-c1-q1 \
  smoke-copa-socket-rr-s1-c1-q4 \
  smoke-copa-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing JSON result for ${run_name}" >&2
    exit 1
  }
  [ -f "${results_root}/${run_name}.txt" ] || {
    echo "behavioral harness test missing summary output for ${run_name}" >&2
    exit 1
  }
  [ -f "${results_root}/${run_name}.server.log" ] || {
    echo "behavioral harness test missing server log for ${run_name}" >&2
    exit 1
  }
done

grep -F -- $'nix\tbuild --print-out-paths .#perf-image-quictls-musl' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use image nix build path' >&2
  exit 1
}

grep -F -- $'docker\tload -i '"${fake_image}" "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not load Docker image' >&2
  exit 1
}

grep -F -- $'docker\tnetwork create coquic-perf-smoke-' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not create Docker bridge network' >&2
  exit 1
}

grep -F -- '--network coquic-perf-smoke-' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing bridge network on docker run' >&2
  exit 1
}

grep -F -- '--cpuset-cpus 2' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server cpuset' >&2
  exit 1
}

grep -F -- '--cpuset-cpus 3' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing client cpuset' >&2
  exit 1
}

grep -F -- 'tests/fixtures:/certs:ro' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing cert mount' >&2
  exit 1
}

grep -F -- '--certificate-chain /certs/quic-server-cert.pem' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server cert argument' >&2
  exit 1
}

grep -F -- '--private-key /certs/quic-server-key.pem' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server key argument' >&2
  exit 1
}

grep -F -- '--congestion-control newreno' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing NewReno congestion-control argument' >&2
  exit 1
}

grep -F -- '--congestion-control cubic' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing CUBIC congestion-control argument' >&2
  exit 1
}

grep -F -- '--congestion-control bbr' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing BBR congestion-control argument' >&2
  exit 1
}

grep -F -- '--congestion-control copa' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing Copa congestion-control argument' >&2
  exit 1
}

if grep -F -- '--network host' "${log_path}" >/dev/null; then
  echo 'behavioral harness test unexpectedly used host networking' >&2
  exit 1
fi

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("topology") != "docker-bridge-two-containers":
    raise SystemExit("manifest missing Docker bridge topology")
if manifest.get("image_tag") != "coquic-perf:quictls-musl":
    raise SystemExit("manifest missing perf image tag")
if manifest.get("image_attr") != "perf-image-quictls-musl":
    raise SystemExit("manifest missing perf image attr")
if manifest.get("congestion_controls") != ["newreno", "cubic", "bbr", "copa"]:
    raise SystemExit("manifest missing congestion-control list")
if manifest.get("client_impl") != "coquic":
    raise SystemExit("manifest missing default client implementation")
if manifest.get("server_impl") != "coquic":
    raise SystemExit("manifest missing default server implementation")
if len(manifest.get("runs", [])) != 12:
    raise SystemExit("manifest missing per-algorithm smoke runs")
seen = {run.get("congestion_control") for run in manifest.get("runs", [])}
if seen != {"newreno", "cubic", "bbr", "copa"}:
    raise SystemExit("manifest missing per-run congestion-control values")
PY

rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid "${results_root}/environment.txt"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
PERF_CLIENT_IMPL=quic-go \
PERF_SERVER_IMPL=quic-go \
PERF_CONGESTION_CONTROLS=default \
bash "${script}" --preset smoke >/dev/null

for run_name in \
  smoke-quic-go-to-quic-go-default-socket-bulk-s1-c1-q1 \
  smoke-quic-go-to-quic-go-default-socket-rr-s1-c1-q4 \
  smoke-quic-go-to-quic-go-default-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing quic-go JSON result for ${run_name}" >&2
    exit 1
  }
done

grep -F -- '--entrypoint /usr/local/bin/quicgo-perf coquic-perf:quictls-musl client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quic-go client entrypoint' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quicgo-perf coquic-perf:quictls-musl server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quic-go server entrypoint' >&2
  exit 1
}

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("client_impl") != "quic-go":
    raise SystemExit("manifest missing quic-go client implementation")
if manifest.get("server_impl") != "quic-go":
    raise SystemExit("manifest missing quic-go server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit("manifest missing quic-go congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit("manifest missing quic-go smoke runs")
PY

rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid "${results_root}/environment.txt"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
PERF_CLIENT_IMPL=quinn \
PERF_SERVER_IMPL=quinn \
PERF_CONGESTION_CONTROLS=default \
bash "${script}" --preset smoke >/dev/null

for run_name in \
  smoke-quinn-to-quinn-default-socket-bulk-s1-c1-q1 \
  smoke-quinn-to-quinn-default-socket-rr-s1-c1-q4 \
  smoke-quinn-to-quinn-default-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing quinn JSON result for ${run_name}" >&2
    exit 1
  }
done

grep -F -- '--entrypoint /usr/local/bin/quinn-perf coquic-perf:quictls-musl client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quinn client entrypoint' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quinn-perf coquic-perf:quictls-musl server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quinn server entrypoint' >&2
  exit 1
}

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("client_impl") != "quinn":
    raise SystemExit("manifest missing quinn client implementation")
if manifest.get("server_impl") != "quinn":
    raise SystemExit("manifest missing quinn server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit("manifest missing quinn congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit("manifest missing quinn smoke runs")
PY

rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid "${results_root}/environment.txt"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
PERF_CLIENT_IMPL=picoquic \
PERF_SERVER_IMPL=picoquic \
PERF_CONGESTION_CONTROLS=default \
bash "${script}" --preset smoke >/dev/null

for run_name in \
  smoke-picoquic-to-picoquic-default-socket-bulk-s1-c1-q1 \
  smoke-picoquic-to-picoquic-default-socket-rr-s1-c1-q4 \
  smoke-picoquic-to-picoquic-default-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing picoquic JSON result for ${run_name}" >&2
    exit 1
  }
done

grep -F -- '--entrypoint /usr/local/bin/picoquic-perf coquic-perf:quictls-musl client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use picoquic client entrypoint' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/picoquic-perf coquic-perf:quictls-musl server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use picoquic server entrypoint' >&2
  exit 1
}

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("client_impl") != "picoquic":
    raise SystemExit("manifest missing picoquic client implementation")
if manifest.get("server_impl") != "picoquic":
    raise SystemExit("manifest missing picoquic server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit("manifest missing picoquic congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit("manifest missing picoquic smoke runs")
PY

rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid "${results_root}/environment.txt"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
PERF_CLIENT_IMPL=msquic \
PERF_SERVER_IMPL=msquic \
PERF_CONGESTION_CONTROLS=default \
bash "${script}" --preset smoke >/dev/null

for run_name in \
  smoke-msquic-to-msquic-default-socket-bulk-s1-c1-q1 \
  smoke-msquic-to-msquic-default-socket-rr-s1-c1-q4 \
  smoke-msquic-to-msquic-default-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing MSQUIC JSON result for ${run_name}" >&2
    exit 1
  }
done

grep -F -- '--entrypoint /usr/local/bin/msquic-perf coquic-perf:quictls-musl client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use MSQUIC client entrypoint' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/msquic-perf coquic-perf:quictls-musl server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use MSQUIC server entrypoint' >&2
  exit 1
}

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("client_impl") != "msquic":
    raise SystemExit("manifest missing MSQUIC client implementation")
if manifest.get("server_impl") != "msquic":
    raise SystemExit("manifest missing MSQUIC server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit("manifest missing MSQUIC congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit("manifest missing MSQUIC smoke runs")
PY

rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid "${results_root}/environment.txt"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
PERF_RESULTS_ROOT="${results_root}" \
PERF_CLIENT_IMPL=quiche \
PERF_SERVER_IMPL=quiche \
PERF_CONGESTION_CONTROLS=default \
bash "${script}" --preset smoke >/dev/null

for run_name in \
  smoke-quiche-to-quiche-default-socket-bulk-s1-c1-q1 \
  smoke-quiche-to-quiche-default-socket-rr-s1-c1-q4 \
  smoke-quiche-to-quiche-default-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing quiche JSON result for ${run_name}" >&2
    exit 1
  }
done

grep -F -- '--entrypoint /usr/local/bin/quiche-perf coquic-perf:quictls-musl client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quiche client entrypoint' >&2
  exit 1
}

grep -F -- '--entrypoint /usr/local/bin/quiche-perf coquic-perf:quictls-musl server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use quiche server entrypoint' >&2
  exit 1
}

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("client_impl") != "quiche":
    raise SystemExit("manifest missing quiche client implementation")
if manifest.get("server_impl") != "quiche":
    raise SystemExit("manifest missing quiche server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit("manifest missing quiche congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit("manifest missing quiche smoke runs")
PY

run_external_baseline_contract() {
  local impl="$1"
  local entrypoint="$2"
  local label="$3"

  rm -f "${log_path}" "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
    "${results_root}"/*.cid "${results_root}/environment.txt"

  PATH="${fake_bin_dir}:$PATH" \
  FAKE_PERF_LOG="${log_path}" \
  FAKE_PERF_IMAGE="${fake_image}" \
  FAKE_RESULTS_ROOT="${results_root}" \
  PERF_RESULTS_ROOT="${results_root}" \
  PERF_CLIENT_IMPL="${impl}" \
  PERF_SERVER_IMPL="${impl}" \
  PERF_CONGESTION_CONTROLS=default \
  bash "${script}" --preset smoke >/dev/null

  for run_name in \
    "smoke-${impl}-to-${impl}-default-socket-bulk-s1-c1-q1" \
    "smoke-${impl}-to-${impl}-default-socket-rr-s1-c1-q4" \
    "smoke-${impl}-to-${impl}-default-socket-crr-s1-c2-q1"
    do
    [ -f "${results_root}/${run_name}.json" ] || {
      echo "behavioral harness test missing ${label} JSON result for ${run_name}" >&2
      exit 1
    }
  done

  grep -F -- "--entrypoint ${entrypoint} coquic-perf:quictls-musl client" "${log_path}" >/dev/null || {
    echo "behavioral harness test did not use ${label} client entrypoint" >&2
    exit 1
  }

  grep -F -- "--entrypoint ${entrypoint} coquic-perf:quictls-musl server" "${log_path}" >/dev/null || {
    echo "behavioral harness test did not use ${label} server entrypoint" >&2
    exit 1
  }

  python3 - "${results_root}/manifest.json" "${impl}" "${label}" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
impl = sys.argv[2]
label = sys.argv[3]
if manifest.get("client_impl") != impl:
    raise SystemExit(f"manifest missing {label} client implementation")
if manifest.get("server_impl") != impl:
    raise SystemExit(f"manifest missing {label} server implementation")
if manifest.get("congestion_controls") != ["default"]:
    raise SystemExit(f"manifest missing {label} congestion-control subset")
if len(manifest.get("runs", [])) != 3:
    raise SystemExit(f"manifest missing {label} smoke runs")
PY
}

run_external_baseline_contract quicly /usr/local/bin/quicly-perf quicly
run_external_baseline_contract google-quiche /usr/local/bin/google-quiche-perf "Google QUICHE"
run_external_baseline_contract tquic /usr/local/bin/tquic-perf TQUIC

echo 'perf harness contract looks correct'
