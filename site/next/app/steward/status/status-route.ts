import { readFile } from 'node:fs/promises';
import path from 'node:path';

import {
  decodePublicStewardJson,
  PUBLIC_STEWARD_SCHEMA_VERSION,
} from '@/lib/steward-schema';
import type { PublicStewardMonitor } from '@/generated/steward-public';

export const PUBLIC_STEWARD_STATUS_SCHEMA_VERSION = PUBLIC_STEWARD_SCHEMA_VERSION;
export type PublicStewardStatus = PublicStewardMonitor;

export type StewardStatusUnavailableReason =
  | 'missing'
  | 'unreadable'
  | 'malformed'
  | 'incompatible'
  | 'invalid';

export type StewardStatusUnavailable = {
  status: 'unavailable';
  reason: StewardStatusUnavailableReason;
};

export type StewardStatusReadResult =
  | { status: 'ok'; data: PublicStewardStatus }
  | StewardStatusUnavailable;

export function parsePublicStewardStatus(text: string): StewardStatusReadResult {
  const decoded = decodePublicStewardJson(text);
  return decoded.ok ? { status: 'ok', data: decoded.data } : unavailable(decoded.reason);
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

function isMissingFile(error: unknown): boolean {
  return typeof error === 'object'
    && error !== null
    && 'code' in error
    && error.code === 'ENOENT';
}

function unavailable(reason: StewardStatusUnavailableReason): StewardStatusUnavailable {
  return { status: 'unavailable', reason };
}
