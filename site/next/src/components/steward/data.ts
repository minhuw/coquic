'use client';

import { useEffect, useRef, useState } from 'react';

import { stewardPollIntervalMs } from '@/lib/steward-freshness';
import { decodePublicStewardJson } from '@/lib/steward-schema';

import type { PublicStewardState, PublicStewardTaskDetail } from './types';

export type StewardRequestStatus = 'loading' | 'ready' | 'not-published' | 'unavailable' | 'invalid' | 'incompatible';

export type StewardRequestResult<T> =
  | { status: 'loading'; data: null }
  | { status: 'ready'; data: T }
  | { status: 'not-published'; data: T | null }
  | { status: 'unavailable'; data: T | null }
  | { status: 'invalid'; data: T | null }
  | { status: 'incompatible'; data: T | null };

export type StewardFetchError = Exclude<StewardRequestStatus, 'loading' | 'ready' | 'not-published'> | null;

function errorForResult<T>(result: StewardRequestResult<T>): StewardFetchError {
  return result.status === 'unavailable' || result.status === 'invalid' || result.status === 'incompatible'
    ? result.status
    : null;
}

function retainData<T>(result: StewardRequestResult<T>, lastValid: T | null): StewardRequestResult<T> {
  if (result.status === 'ready') return result;
  if (result.status === 'loading') return result;
  return { ...result, data: lastValid };
}

export async function loadPublicStewardStateResult(): Promise<StewardRequestResult<PublicStewardState>> {
  try {
    const response = await fetch('/steward/status', {
      cache: 'no-store',
    });
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { reason?: string } | null;
      if (response.status === 404 || body?.reason === 'not-published' || body?.reason === 'not_published') {
        return { status: 'not-published', data: null };
      }
      if (body?.reason === 'incompatible') return { status: 'incompatible', data: null };
      return { status: 'unavailable', data: null };
    }
    const decoded = decodePublicStewardJson(await response.text());
    if (!decoded.ok) {
      return {
        status: decoded.reason === 'incompatible' ? 'incompatible' : 'invalid',
        data: null,
      };
    }
    return { status: 'ready', data: decoded.data as unknown as PublicStewardState };
  } catch {
    return { status: 'unavailable', data: null };
  }
}

export async function loadPublicStewardState(): Promise<PublicStewardState | null> {
  const result = await loadPublicStewardStateResult();
  return result.status === 'ready' ? result.data : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function loadPublicStewardTaskDetailResult(
  taskId: string,
  detailJson?: string,
): Promise<StewardRequestResult<PublicStewardTaskDetail>> {
  let response: Response;
  try {
    response = await fetch(detailJson ?? publicTaskDetailJsonPath(taskId), {
      cache: 'no-store',
    });
  } catch {
    return { status: 'unavailable', data: null };
  }
  if (response.status === 404) return { status: 'not-published', data: null };
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { reason?: string } | null;
    if (body?.reason === 'incompatible') return { status: 'incompatible', data: null };
    if (body?.reason === 'not-published' || body?.reason === 'not_published') return { status: 'not-published', data: null };
    return { status: 'unavailable', data: null };
  }
  let value: unknown;
  try {
    value = JSON.parse(await response.text()) as unknown;
  } catch {
    return { status: 'invalid', data: null };
  }
  if (!isRecord(value)) return { status: 'invalid', data: null };
  return { status: 'ready', data: value as unknown as PublicStewardTaskDetail };
}

export async function loadPublicStewardTaskDetail(
  taskId: string,
  detailJson?: string,
): Promise<PublicStewardTaskDetail | null> {
  const result = await loadPublicStewardTaskDetailResult(taskId, detailJson);
  return result.status === 'ready' ? result.data : null;
}

export function usePublicStewardState() {
  const [result, setResult] = useState<StewardRequestResult<PublicStewardState>>({ status: 'loading', data: null });
  const lastValid = useRef<PublicStewardState | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    async function refresh() {
      const next = await loadPublicStewardStateResult();
      if (cancelled) return;
      if (next.status === 'ready') lastValid.current = next.data;
      const retained = retainData(next, lastValid.current);
      setResult(retained);
      timer = window.setTimeout(() => {
        if (!cancelled) void refresh();
      }, stewardPollIntervalMs(lastValid.current ?? retained.data));
    }

    void refresh();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  // Polling is scheduled after each response so active daemons update faster
  // without creating overlapping requests during a slow mirror fetch.
  }, []);

  return {
    error: errorForResult(result),
    loading: result.status === 'loading',
    result,
    state: result.data,
  };
}

export function usePublicStewardTaskDetail(taskId: string, detailJson?: string) {
  const [result, setResult] = useState<StewardRequestResult<PublicStewardTaskDetail>>({ status: 'loading', data: null });
  const lastValid = useRef<PublicStewardTaskDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    let refreshing = false;
    lastValid.current = null;
    setResult({ status: 'loading', data: null });

    async function refresh() {
      if (refreshing) return;
      refreshing = true;
      try {
        const next = await loadPublicStewardTaskDetailResult(taskId, detailJson);
        if (cancelled) return;
        if (next.status === 'ready') lastValid.current = next.data;
        setResult(retainData(next, lastValid.current));
      } finally {
        refreshing = false;
      }
    }

    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [detailJson, taskId]);

  return {
    detail: result.data,
    error: errorForResult(result),
    loaded: result.status !== 'loading',
    result,
  };
}

function publicTaskDetailJsonPath(taskId: string) {
  return `/steward/data/tasks/${encodeURIComponent(taskId)}.json`;
}
