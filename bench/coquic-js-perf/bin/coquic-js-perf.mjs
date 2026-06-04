#!/usr/bin/env node

import { runClient } from "../lib/client.mjs";
import { parseRuntimeArgs, Role } from "../lib/config.mjs";
import { emitSummary, finalizeSummary, newRunSummary } from "../lib/metrics.mjs";
import { runServer } from "../lib/server.mjs";

async function main() {
  let config;
  try {
    config = parseRuntimeArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }

  if (config.role === Role.SERVER) {
    await runServer(config);
    return;
  }

  let summary = newRunSummary(config);
  try {
    summary = await runClient(config);
  } catch (error) {
    summary.status = "failed";
    summary.failure_reason = error.message;
  }

  finalizeSummary(summary);
  emitSummary(summary, config.jsonOut);
  if (summary.status !== "ok") {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
