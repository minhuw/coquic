# CoQUIC JavaScript Binding

This package exposes the CoQUIC sans-I/O QUIC core to Node.js through the C FFI
and a small native N-API addon.

Build the CoQUIC FFI library first, then build the addon:

```sh
zig build package
npm --prefix bindings/javascript run build
```

By default the addon links `zig-out/lib/libcoquic-quictls.so`. Override the
library when needed:

```sh
COQUIC_LIB_DIR=zig-out/lib COQUIC_LIB_NAME=coquic-boringssl \
  npm --prefix bindings/javascript run build
```

At runtime, `LD_LIBRARY_PATH` must include the directory containing the selected
CoQUIC shared library unless the addon was built with a usable rpath.
