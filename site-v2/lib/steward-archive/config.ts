import { isAbsolute, relative, resolve, sep } from "node:path";
import { existsSync, lstatSync, realpathSync } from "node:fs";

export type ArchiveRuntime = "production" | "development" | "test";

export interface ArchiveConfig {
  tasksRoot: string;
  controlLoopRoot: string;
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
const PRODUCTION_CONTROL_LOOP_ROOT = "/opt/coquic-demo/steward/control-loop";
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

function effectivePathWithoutSymlinks(path: string) {
  const absolute = resolve(path);
  const segments = absolute.split(sep).filter(Boolean);
  let existing: string = sep;
  let index = 0;
  for (; index < segments.length; index += 1) {
    const candidate = resolve(existing, segments[index]);
    if (!existsSync(candidate)) break;
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink()) throw new ArchiveConfigError("symlink-path", "archive paths must not contain symlink ancestors");
    existing = candidate;
  }
  return resolve(realpathSync(existing), ...segments.slice(index));
}

export function validateArchivePaths(tasksRoot: string, cachePath: string, runtime: ArchiveRuntime = runtimeFromEnv(), controlLoopRoot = "") {
  if (!isAbsolute(tasksRoot) || !isAbsolute(cachePath) || (controlLoopRoot !== "" && !isAbsolute(controlLoopRoot))) {
    throw new ArchiveConfigError("relative-path", "archive paths must be absolute");
  }
  if (tasksRoot.includes("\0") || cachePath.includes("\0") || controlLoopRoot.includes("\0") || tasksRoot.includes("\\") || cachePath.includes("\\") || controlLoopRoot.includes("\\")) {
    throw new ArchiveConfigError("unsafe-path", "archive paths contain an unsafe character");
  }

  const raw = resolve(tasksRoot);
  const control = controlLoopRoot ? resolve(controlLoopRoot) : null;
  const cache = resolve(cachePath);
  if (raw === cache || hasPathPrefix(raw, cache) || hasPathPrefix(cache, raw)) {
    throw new ArchiveConfigError("nested-path", "archive and cache paths must not contain one another");
  }
  if (control && (control === cache || hasPathPrefix(control, cache) || hasPathPrefix(cache, control) || control === raw || hasPathPrefix(control, raw) || hasPathPrefix(raw, control))) {
    throw new ArchiveConfigError("nested-path", "archive roots and cache paths must be separate");
  }
  const releaseRoot = /(?:^|\/)releases(?:\/|$)/;
  if (releaseRoot.test(raw) || releaseRoot.test(cache)) {
    throw new ArchiveConfigError("release-path", "archive state must be outside immutable releases");
  }
  if (control && releaseRoot.test(control)) throw new ArchiveConfigError("release-path", "archive state must be outside immutable releases");
  if (runtime === "production" && (!isAbsolute(raw) || !isAbsolute(cache))) {
    throw new ArchiveConfigError("relative-production-path", "production archive paths must be absolute");
  }
  if (existsSync(raw)) {
    const stat = lstatSync(raw);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ArchiveConfigError("raw-root", "archive root must be a real directory");
  }
  if (control && existsSync(control)) {
    const stat = lstatSync(control);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new ArchiveConfigError("raw-root", "control-loop root must be a real directory");
  }
  const effectiveRaw = effectivePathWithoutSymlinks(raw);
  const effectiveControl = control ? effectivePathWithoutSymlinks(control) : null;
  const effectiveCache = effectivePathWithoutSymlinks(cache);
  const basename = (path: string) => path.split(sep).filter(Boolean).at(-1) ?? "";
  if (basename(raw) !== "tasks") throw new ArchiveConfigError("unsafe-basename", "task archive root must be named tasks");
  if (control && basename(control) !== "control-loop") throw new ArchiveConfigError("unsafe-basename", "control-loop root must be named control-loop");
  if (effectiveRaw === effectiveCache || hasPathPrefix(effectiveRaw, effectiveCache) || hasPathPrefix(effectiveCache, effectiveRaw)) {
    throw new ArchiveConfigError("nested-real-path", "archive and cache real paths must not contain one another");
  }
  if (effectiveControl && (effectiveControl === effectiveCache || hasPathPrefix(effectiveControl, effectiveCache) || hasPathPrefix(effectiveCache, effectiveControl) || effectiveControl === effectiveRaw || hasPathPrefix(effectiveControl, effectiveRaw) || hasPathPrefix(effectiveRaw, effectiveControl))) {
    throw new ArchiveConfigError("nested-real-path", "archive roots and cache real paths must be separate");
  }
  if (existsSync(cache)) {
    const stat = lstatSync(cache);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new ArchiveConfigError("cache-file", "archive cache must be a regular file");
  }
  return { tasksRoot: raw, controlLoopRoot: control ?? "", cachePath: cache };
}

export function getArchiveConfig(env: NodeJS.ProcessEnv = process.env): ArchiveConfig {
  const runtime = runtimeFromEnv(env);
  const fixtureMode = env.COQUIC_STEWARD_FIXTURE_MODE === "1" || env.COQUIC_STEWARD_FIXTURE_MODE === "true";
  const tasksRoot = env.COQUIC_STEWARD_TASKS_ROOT || (runtime === "production" ? PRODUCTION_TASKS_ROOT : "");
  const controlLoopRoot = env.COQUIC_STEWARD_CONTROL_LOOP_ROOT || (runtime === "production" ? PRODUCTION_CONTROL_LOOP_ROOT : "");
  const cachePath = env.COQUIC_STEWARD_CACHE_PATH || (runtime === "production" ? PRODUCTION_CACHE_PATH : "");
  if (!tasksRoot || !cachePath) {
    throw new ArchiveConfigError("missing-path", "archive paths must be supplied outside production");
  }
  const paths = validateArchivePaths(tasksRoot, cachePath, runtime, controlLoopRoot);
  return {
    ...paths,
    runtime,
    fixtureMode,
    reconcileMs: envPositiveInteger(env.COQUIC_STEWARD_RECONCILE_MS, 60_000, 86_400_000),
    batchSize: envPositiveInteger(env.COQUIC_STEWARD_BATCH_SIZE, 8, 256),
  };
}

export { PRODUCTION_CACHE_PATH, PRODUCTION_CONTROL_LOOP_ROOT, PRODUCTION_TASKS_ROOT };
