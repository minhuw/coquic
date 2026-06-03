# CoQUIC Python Wrapper

This package provides a Python-native wrapper over the public CoQUIC C FFI. It
uses `ctypes`, remains sans-I/O, and exposes a QUIC facade API through
`coquic.quic`.

Build a local C FFI package first:

```sh
zig build package -Dtls_backend=quictls
```

Then run Python with the local shared library on the loader path:

```sh
COQUIC_LIB_DIR="$PWD/zig-out/lib" COQUIC_LIB_NAME=coquic-quictls \
  PYTHONPATH="$PWD/bindings/python" python3 -c 'import coquic; print(coquic.TransportConfig.default())'
```
