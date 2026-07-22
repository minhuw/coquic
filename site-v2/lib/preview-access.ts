import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export const PREVIEW_ACCESS_COOKIE = "coquic-v2-preview";
export const PREVIEW_ACCESS_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

const PREVIEW_TOKEN_PREFIX = "coquic-v2-preview:";

export function previewPassword(): string | null {
  const value = process.env.COQUIC_V2_PREVIEW_PASSWORD;
  return value && value.length > 0 ? value : null;
}

export async function previewAccessToken(password: string): Promise<string> {
  const bytes = new TextEncoder().encode(`${PREVIEW_TOKEN_PREFIX}${password}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export function previewReturnPath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
    return "/";
  }

  try {
    const parsed = new URL(value, "https://preview.invalid");
    if (parsed.origin !== "https://preview.invalid") return "/";
    if (parsed.pathname === "/preview" || parsed.pathname === "/api/preview-access") {
      return "/";
    }
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return "/";
  }
}

function requestOrigin(request: NextRequest): string {
  const forwardedHost = request.headers
    .get("x-forwarded-host")
    ?.split(",")[0]
    ?.trim();
  const host = forwardedHost || request.headers.get("host");
  const forwardedProtocol = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim();
  const protocol = forwardedProtocol === "https" ? "https" : "http";

  if (host) {
    try {
      const origin = new URL(`${protocol}://${host}`);
      if (!origin.username && !origin.password && origin.pathname === "/") {
        return origin.origin;
      }
    } catch {
      // Fall back to the origin parsed by Next.js.
    }
  }
  return request.nextUrl.origin;
}

export function previewRedirect(
  request: NextRequest,
  location: string,
  status = 307,
): NextResponse {
  return NextResponse.redirect(new URL(location, requestOrigin(request)), status);
}
