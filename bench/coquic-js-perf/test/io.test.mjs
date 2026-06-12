import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { UdpRuntime } from "../lib/io.mjs";

class FakeSocket extends EventEmitter {
  send(_bytes, _port, _host, callback) {
    callback(null);
  }

  close() {}
}

test("wait uses the idle guard when the core wakeup is far in the future", async () => {
  const io = new UdpRuntime(new FakeSocket());
  const startedAt = io.nowUs();

  const event = await io.wait(Number.MAX_SAFE_INTEGER, 0.001);
  const elapsedUs = io.nowUs() - startedAt;

  assert.equal(event.kind, "idle");
  assert.ok(elapsedUs < 500_000, `wait took ${elapsedUs}us`);
});

test("wait reports a timer when the core wakeup is earlier than the idle guard", async () => {
  const io = new UdpRuntime(new FakeSocket());
  const event = await io.wait(io.nowUs() + 1_000, 1.0);

  assert.equal(event.kind, "timer");
});
