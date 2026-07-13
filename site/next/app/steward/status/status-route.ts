import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const PUBLIC_STEWARD_STATUS_SCHEMA_VERSION = 3;

export type PublicStewardStatus = Record<string, unknown> & {
  schema_version: typeof PUBLIC_STEWARD_STATUS_SCHEMA_VERSION;
};

export type StewardStatusUnavailableReason =
  | 'missing'
  | 'unreadable'
  | 'malformed'
  | 'incompatible';

export type StewardStatusUnavailable = {
  status: 'unavailable';
  reason: StewardStatusUnavailableReason;
};

export type StewardStatusReadResult =
  | { status: 'ok'; data: PublicStewardStatus }
  | StewardStatusUnavailable;

export function parsePublicStewardStatus(text: string): StewardStatusReadResult {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return unavailable('malformed');
  }

  if (!isObject(value)) return unavailable('malformed');
  if (value.schema_version !== PUBLIC_STEWARD_STATUS_SCHEMA_VERSION) {
    return unavailable('incompatible');
  }

  return {
    status: 'ok',
    data: value as PublicStewardStatus,
  };
}

export async function readPublicStewardStatus(siteRoot: string): Promise<StewardStatusReadResult> {
  const filePath = path.join(siteRoot, 'public', 'steward', 'status.json');
  let text: string;
  try {
    text = await readFile(filePath, 'utf8');
  } catch (error) {
    return unavailable(isMissingFile(error) ? 'missing' : 'unreadable');
  }

  return parsePublicStewardStatus(text);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return typeof error === 'object'
    && error !== null
    && 'code' in error
    && error.code === 'ENOENT';
}

function unavailable(reason: StewardStatusUnavailableReason): StewardStatusUnavailable {
  return { status: 'unavailable', reason };
}
