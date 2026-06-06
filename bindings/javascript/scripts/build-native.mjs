#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const outDir = path.join(packageRoot, "build", "Release");
const outPath = path.join(outDir, "coquic_js.node");

const tlsBackend = process.env.COQUIC_TLS_BACKEND || "quictls";
const libName = process.env.COQUIC_LIB_NAME || `coquic-${tlsBackend}`;
const libDir = process.env.COQUIC_LIB_DIR || path.join(repoRoot, "zig-out", "lib");
const cxx = process.env.CXX || "c++";
const nodeIncludeDir = findNodeIncludeDir();

fs.mkdirSync(outDir, { recursive: true });

const args = [
  "-std=c++20",
  "-O2",
  "-fPIC",
  "-shared",
  "-DNAPI_VERSION=8",
  `-I${path.join(repoRoot, "include")}`,
  `-I${nodeIncludeDir}`,
  path.join(packageRoot, "src", "addon.cpp"),
  `-L${libDir}`,
  `-Wl,-rpath,${libDir}`,
  `-l${libName}`,
  "-o",
  outPath,
];

const result = spawnSync(cxx, args, { stdio: "inherit" });
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

function findNodeIncludeDir() {
  const candidates = [
    process.env.NODE_INCLUDE_DIR,
    path.resolve(path.dirname(process.execPath), "..", "include", "node"),
    "/usr/include/node",
    "/usr/include/nodejs/src",
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      fs.accessSync(path.join(candidate, "node_api.h"), fs.constants.R_OK);
      return candidate;
    } catch {
      continue;
    }
  }

  throw new Error(
    "unable to locate node_api.h; set NODE_INCLUDE_DIR to the Node.js include directory",
  );
}
