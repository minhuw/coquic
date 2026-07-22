import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  PREVIEW_ACCESS_COOKIE,
  previewAccessToken,
  previewPassword,
  previewRedirect,
  previewReturnPath,
} from "@/lib/preview-access";

const GATE_PATHS = new Set(["/preview", "/api/preview-access"]);

export async function proxy(request: NextRequest) {
  const password = previewPassword();
  if (!password || GATE_PATHS.has(request.nextUrl.pathname)) {
    return NextResponse.next();
  }

  const expectedToken = await previewAccessToken(password);
  if (request.cookies.get(PREVIEW_ACCESS_COOKIE)?.value === expectedToken) {
    return NextResponse.next();
  }

  const query = new URLSearchParams();
  query.set(
    "next",
    previewReturnPath(`${request.nextUrl.pathname}${request.nextUrl.search}`),
  );
  return previewRedirect(request, `/preview?${query.toString()}`);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
