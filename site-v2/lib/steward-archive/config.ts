import { isAbsolute, relative, resolve, sep } from "node:path";
import { existsSync, lstatSync } from "node:fs";

export type ArchiveRuntime = "production" | "development" | "test";

export interface ArchiveConfig {
  tasksRoot: string;
  cachePath: string;
  runtime: ArchiveRuntime;
  fixtureMode: boolean;
  reconcileMs: number;
  batchSize: number;
}

export class ArchiveConfigError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ArchiveConfigError";
    this.code = code;
  }
}

const PRODUCTION_TASKS_ROOT = "/opt/coquic-demo/steward/tasks";
const PRODUCTION_CACHE_PATH = "/opt/coquic-demo/steward/cache/site-v2.sqlite";

function runtimeFromEnv(env: NodeJS.ProcessEnv = process.env): ArchiveRuntime {
  if (env.NODE_ENV === "test") return "test";
  if (env.NODE_ENV === "development") return "development";
  return "production";
}

function envPositiveInteger(value: string | undefined, fallback: number, max: number) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= max ? parsed : fallback;
}

function hasPathPrefix(parent: string, child: string) {
  const relation = relative(parent, child);
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== ".." && !isAbsolute(relation));
}

export function validateArchivePaths(tasksRoot: string, cachePath: string, runtime: ArchiveRuntime = runtimeFromEnv()) {
  if (!isAbsolute(tasksRoot) || !isAbsolute(cachePath)) {
    throw new ArchiveConfigError("relative-path", "archive paths must be absolute");
  }
  if (tasksRoot.includes("\0") || cachePath.includes("\0") || tasksRoot.includes("\\") || cachePath.includes("\\")) {
    throw new ArchiveConfigError("unsafe-path", "archive paths contain an unsafe character");
  }

  const raw = resolve(tasksRoot);
  const cache = resolve(cachePath);
  if (raw === cache || hasPathPrefix(raw, cache) || hasPathPrefix(cache, raw)) {
    throw new ArchiveConfigError("nested-path", "archive and cache paths must not contain one another");
  }
  const releaseRoot = /(?:^|\/)releases(?:\/|$)/;
  if (releaseRoot.test(raw) || releaseRoot.test(cache)) {
    throw new ArchiveConfigError("release-path", "archive state must be outside immutable releases");
  }
  if (runtime === "production" && (!isAbsolute(raw) || !isAbsolute(cache))) {
    throw new ArchiveConfigError("relative-production-path", "production archive paths must be absolute");
  }
  if (existsSync(raw)) {
    const stat = lstatSync(raw);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ArchiveConfigError("raw-root", "archive root must be a real directory");
  }
  if (existsSync(cache)) {
    const stat = lstatSync(cache);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new ArchiveConfigError("cache-file", "archive cache must be a regular file");
  }
  return { tasksRoot: raw, cachePath: cache };
}

export function getArchiveConfig(env: NodeJS.ProcessEnv = process.env): ArchiveConfig {
  const runtime = runtimeFromEnv(env);
  const fixtureMode = env.COQUIC_STEWARD_FIXTURE_MODE === "1" || env.COQUIC_STEWARD_FIXTURE_MODE === "true";
  const tasksRoot = env.COQUIC_STEWARD_TASKS_ROOT || (runtime === "production" ? PRODUCTION_TASKS_ROOT : "");
  const cachePath = env.COQUIC_STEWARD_CACHE_PATH || (runtime === "production" ? PRODUCTION_CACHE_PATH : "");
  if (!tasksRoot || !cachePath) {
    throw new ArchiveConfigError("missing-path", "archive paths must be supplied outside production");
  }
  const paths = validateArchivePaths(tasksRoot, cachePath, runtime);
  return {
    ...paths,
    runtime,
    fixtureMode,
    reconcileMs: envPositiveInteger(env.COQUIC_STEWARD_RECONCILE_MS, 60_000, 86_400_000),
    batchSize: envPositiveInteger(env.COQUIC_STEWARD_BATCH_SIZE, 8, 256),
  };
}

export { PRODUCTION_CACHE_PATH, PRODUCTION_TASKS_ROOT };
