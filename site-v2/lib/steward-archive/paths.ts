import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_PATH = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;

export function isSafeId(value: unknown): value is string {
  return typeof value === "string" && SAFE_ID.test(value) && !value.includes("..");
}

export function isSafeRelativePath(value: unknown): value is string {
  return typeof value === "string" && value.length <= 1024 && SAFE_PATH.test(value) && !value.includes("..") && !value.includes("\\") && !value.includes("\0");
}

export function assertSafeId(value: unknown, label = "id"): asserts value is string {
  if (!isSafeId(value)) throw new Error(`invalid ${label}`);
}

export function assertSafeRelativePath(value: unknown, label = "path"): asserts value is string {
  if (!isSafeRelativePath(value)) throw new Error(`invalid ${label}`);
}

function contained(root: string, target: string) {
  const relation = relative(root, target);
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== ".." && !isAbsolute(relation));
}

export function resolveSafePath(root: string, relativePath: string) {
  assertSafeRelativePath(relativePath);
  const resolvedRoot = resolve(root);
  const target = resolve(resolvedRoot, relativePath.split("/").join(sep));
  if (!contained(resolvedRoot, target)) throw new Error("path escapes archive root");
  return target;
}

export async function resolveRegularContainedPath(root: string, relativePath: string) {
  const target = resolveSafePath(root, relativePath);
  const lexicalStat = await lstat(target);
  if (lexicalStat.isSymbolicLink() || !lexicalStat.isFile()) throw new Error("archive artifact must be a regular non-symlink file");
  const rootReal = await realpath(root);
  const targetReal = await realpath(target);
  if (!contained(rootReal, targetReal) || targetReal === rootReal) throw new Error("path is outside archive root");
  const stat = await lstat(targetReal);
  if (!stat.isFile()) throw new Error("archive artifact is not a regular file");
  return { path: targetReal, stat };
}

export async function assertDirectoryRoot(root: string) {
  const stat = await lstat(root);
  if (!stat.isDirectory()) throw new Error("archive root is not a directory");
  const actual = await realpath(root);
  if (actual !== resolve(root)) throw new Error("archive root must not be a symlink");
  return actual;
}

export function joinSafe(root: string, ...parts: string[]) {
  return resolveSafePath(root, parts.join("/"));
}

export { SAFE_ID, SAFE_PATH };
