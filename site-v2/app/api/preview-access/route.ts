import type { NextRequest } from "next/server";

import {
  PREVIEW_ACCESS_COOKIE,
  PREVIEW_ACCESS_MAX_AGE_SECONDS,
  previewAccessToken,
  previewPassword,
  previewRedirect,
  previewReturnPath,
} from "@/lib/preview-access";

export async function POST(request: NextRequest) {
  const password = previewPassword();
  const form = await request.formData();
  const suppliedPassword = form.get("password");
  const next = previewReturnPath(form.get("next"));

  if (!password) {
    return previewRedirect(request, next, 303);
  }

  const suppliedToken =
    typeof suppliedPassword === "string"
      ? await previewAccessToken(suppliedPassword)
      : "";
  const expectedToken = await previewAccessToken(password);
  if (suppliedToken !== expectedToken) {
    const query = new URLSearchParams({ error: "invalid", next });
    return previewRedirect(request, `/preview?${query.toString()}`, 303);
  }

  const response = previewRedirect(request, next, 303);
  response.cookies.set({
    name: PREVIEW_ACCESS_COOKIE,
    value: expectedToken,
    httpOnly: true,
    maxAge: PREVIEW_ACCESS_MAX_AGE_SECONDS,
    path: "/",
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });
  return response;
}
