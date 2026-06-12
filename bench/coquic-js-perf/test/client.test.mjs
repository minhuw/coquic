import assert from "node:assert/strict";
import test from "node:test";

import { Direction, Mode, PerfConfig } from "../lib/config.mjs";
import { Client, testHooks } from "../lib/client.mjs";
import { FIRST_DATA_STREAM_ID } from "../lib/protocol.mjs";

const { BenchmarkPhase, ConnectionState, OutstandingRequest, durationUs } = testHooks;

class FakeEndpoint {
  nextWakeup() {
    return null;
  }

  connection() {
    return {
      stream() {
        return {
          send() {
            return { effects: [], localError: null };
          },
        };
      },

      close() {
        return { effects: [], localError: null };
      },
    };
  }
}

const fakeIo = Object.freeze({
  nowUs() {
    return 0;
  },

  async flushSends() {},

  collectResultEffects() {
    return [];
  },
});

function timedPersistentRrClient() {
  const config = new PerfConfig();
  config.mode = Mode.PERSISTENT_RR;
  config.direction = Direction.DOWNLOAD;
  config.requests = null;
  config.requestBytes = 32;
  config.responseBytes = 32;
  config.connections = 1;
  config.requestsInFlight = 4;
  config.duration = 5;

  const client = new Client(config, new FakeEndpoint(), fakeIo, 1, Buffer.alloc(0));
  client.benchmarkStartedAt = 100_000;
  client.phase = BenchmarkPhase.MEASURE;
  client.measureStartedAt = 200_000;
  client.measureDeadline = client.measureStartedAt + durationUs(config.duration);

  const state = new ConnectionState();
  state.sessionReady = true;
  state.persistentStreamId = FIRST_DATA_STREAM_ID;
  state.persistentRequests.push(new OutstandingRequest(client.measureStartedAt, true));
  client.connections.set(1, state);

  return { client, state };
}

function timedBulkClient() {
  const config = new PerfConfig();
  config.mode = Mode.BULK;
  config.direction = Direction.DOWNLOAD;
  config.totalBytes = null;
  config.duration = 5;

  return new Client(config, new FakeEndpoint(), fakeIo, 1, Buffer.alloc(0));
}

test("timed persistent rr drain is bounded by a benchmark wakeup", async () => {
  const { client, state } = timedPersistentRrClient();

  await client.enterDrainPhase(client.measureDeadline);

  const expectedDrainDeadline = client.measureDeadline + durationUs(2);
  assert.equal(client.drainDeadline, expectedDrainDeadline);
  assert.equal(client.benchmarkNextWakeup(), expectedDrainDeadline);
  assert.equal(client.nextWaitWakeup(null), expectedDrainDeadline);
  assert.equal(client.runComplete(), false);

  await client.forceCloseTimedDrain(expectedDrainDeadline - 1);
  assert.equal(state.closeRequested, false);

  await client.forceCloseTimedDrain(expectedDrainDeadline);
  assert.equal(state.closeRequested, true);
  assert.equal(client.runComplete(), true);
});

test("timed persistent rr hard drain closes without waiting for FIN", async () => {
  const { client, state } = timedPersistentRrClient();

  client.phase = BenchmarkPhase.DRAIN;
  client.drainDeadline = client.measureDeadline + durationUs(2);

  await client.forceCloseTimedDrain(client.drainDeadline);

  assert.equal(state.persistentFinSent, true);
  assert.equal(state.closeRequested, true);
  assert.equal(client.runComplete(), true);
});

test("timed bulk can wait through idle only after benchmark start", () => {
  const client = timedBulkClient();

  assert.equal(client.canWaitThroughIdle(), false);

  client.benchmarkStartedAt = 100_000;
  assert.equal(client.canWaitThroughIdle(), true);
});

test("timed request response idle remains fatal", () => {
  const { client } = timedPersistentRrClient();

  assert.equal(client.canWaitThroughIdle(), false);
});
