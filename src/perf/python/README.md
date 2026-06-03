# CoQUIC Python Perf

`coquic-python-perf` is a Python perf runner built on the CoQUIC Python QUIC
facade. It uses `asyncio` UDP sockets for I/O and follows the same perf command
line as the C++ and Rust runners.

Run it from the source tree after building the C FFI package:

```sh
zig build package -Dtls_backend=boringssl
COQUIC_LIB_DIR="$PWD/zig-out/lib" COQUIC_LIB_NAME=coquic-boringssl \
  PYTHONPATH="$PWD/bindings/python:$PWD/src/perf/python" \
  python3 -m coquic_python_perf --help
```
