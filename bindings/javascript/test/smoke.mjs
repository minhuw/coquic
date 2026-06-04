import assert from "node:assert/strict";
import * as coquic from "../index.js";

assert.equal(coquic.ffiAbiVersion(), coquic.FFI_ABI_VERSION);

const clientConfig = new coquic.EndpointConfig({
  role: coquic.Role.CLIENT,
  applicationProtocol: Buffer.from("coquic-js-smoke/1"),
});
const endpoint = new coquic.Endpoint(clientConfig);

assert.equal(endpoint.connectionCount(), 0);
assert.equal(endpoint.nextWakeup(), null);
endpoint.close();

console.log("coquic-js smoke ok");
