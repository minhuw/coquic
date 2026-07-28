// Server-only configuration. Keep this module out of client components and
// never mirror its values into a public environment variable.

export interface CloudReaderConfig {
  readonly accountId: string;
  readonly databaseId: string;
  readonly d1ReadToken: string;
  readonly publicR2BaseUrl: string;
}

export type CloudReaderEnvironment = Readonly<Record<string, string | undefined>>;

export type CloudReaderConfigField =
  | "accountId"
  | "databaseId"
  | "d1ReadToken"
  | "publicR2BaseUrl";

export type CloudReaderConfigErrorCode =
  | "missing-account-id"
  | "invalid-account-id"
  | "missing-database-id"
  | "invalid-database-id"
  | "missing-d1-read-token"
  | "invalid-d1-read-token"
  | "missing-public-r2-base-url"
  | "invalid-public-r2-base-url"
  | "unsafe-public-r2-base-url";

export class CloudReaderConfigError extends Error {
  readonly code: CloudReaderConfigErrorCode;
  readonly field: CloudReaderConfigField;

  constructor(code: CloudReaderConfigErrorCode, field: CloudReaderConfigField, message: string) {
    super(message);
    this.name = "CloudReaderConfigError";
    this.code = code;
    this.field = field;
  }
}

const ACCOUNT_ID = /^[0-9a-f]{32}$/i;
const DATABASE_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const MAX_READ_TOKEN_LENGTH = 4096;

function missing(code: CloudReaderConfigErrorCode, field: CloudReaderConfigField, label: string): never {
  throw new CloudReaderConfigError(code, field, `${label} is required`);
}

function invalid(code: CloudReaderConfigErrorCode, field: CloudReaderConfigField, label: string): never {
  throw new CloudReaderConfigError(code, field, `${label} is invalid`);
}

function unsafeUrl(label: string): never {
  throw new CloudReaderConfigError("unsafe-public-r2-base-url", "publicR2BaseUrl", `${label} is unsafe`);
}

function requiredText(
  value: unknown,
  missingCode: CloudReaderConfigErrorCode,
  invalidCode: CloudReaderConfigErrorCode,
  field: CloudReaderConfigField,
  label: string,
) {
  if (value === undefined || value === null) missing(missingCode, field, label);
  if (typeof value !== "string") invalid(invalidCode, field, label);
  const normalized = value.trim();
  if (normalized === "") missing(missingCode, field, label);
  return normalized;
}

function parseAccountId(value: unknown) {
  const accountId = requiredText(value, "missing-account-id", "invalid-account-id", "accountId", "CLOUDFLARE_ACCOUNT_ID");
  if (!ACCOUNT_ID.test(accountId)) invalid("invalid-account-id", "accountId", "CLOUDFLARE_ACCOUNT_ID");
  return accountId.toLowerCase();
}

function parseDatabaseId(value: unknown) {
  const databaseId = requiredText(value, "missing-database-id", "invalid-database-id", "databaseId", "COQUIC_STEWARD_D1_DATABASE_ID");
  if (!DATABASE_ID.test(databaseId)) invalid("invalid-database-id", "databaseId", "COQUIC_STEWARD_D1_DATABASE_ID");
  return databaseId.toLowerCase();
}

function parseReadToken(value: unknown) {
  if (typeof value === "string" && CONTROL_CHARACTER.test(value)) {
    invalid("invalid-d1-read-token", "d1ReadToken", "COQUIC_STEWARD_D1_READ_TOKEN");
  }
  const token = requiredText(value, "missing-d1-read-token", "invalid-d1-read-token", "d1ReadToken", "COQUIC_STEWARD_D1_READ_TOKEN");
  if (token.length > MAX_READ_TOKEN_LENGTH) invalid("invalid-d1-read-token", "d1ReadToken", "COQUIC_STEWARD_D1_READ_TOKEN");
  return token;
}

function rawPath(value: string) {
  const schemeEnd = value.indexOf("://");
  const authorityStart = schemeEnd < 0 ? 0 : schemeEnd + 3;
  const slash = value.indexOf("/", authorityStart);
  return slash < 0 ? "/" : value.slice(slash);
}

function hasUnsafePathSegments(path: string) {
  for (const segment of path.split("/")) {
    if (segment === "") continue;
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return true;
    }
    if (segment === "." || segment === ".." || decoded === "." || decoded === "..") return true;
    if (decoded.includes("/") || decoded.includes("\\") || CONTROL_CHARACTER.test(decoded)) return true;
  }
  return false;
}

function parsePublicR2BaseUrl(value: unknown) {
  const raw = requiredText(value, "missing-public-r2-base-url", "invalid-public-r2-base-url", "publicR2BaseUrl", "COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  if (CONTROL_CHARACTER.test(raw) || raw.includes("\\") || raw.includes("?") || raw.includes("#")) {
    unsafeUrl("COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    invalid("invalid-public-r2-base-url", "publicR2BaseUrl", "COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  }
  if (parsed.protocol !== "https:" || parsed.hostname === "" || parsed.username !== "" || parsed.password !== "") {
    unsafeUrl("COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  }
  if (parsed.search !== "" || parsed.hash !== "") unsafeUrl("COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  if (hasUnsafePathSegments(rawPath(raw)) || hasUnsafePathSegments(parsed.pathname)) {
    unsafeUrl("COQUIC_STEWARD_PUBLIC_R2_BASE_URL");
  }

  if (!parsed.pathname.endsWith("/")) parsed.pathname += "/";
  return parsed.href;
}

function makeConfig(accountId: string, databaseId: string, d1ReadToken: string, publicR2BaseUrl: string) {
  // Keep the credential available to server callers while excluding it from
  // ordinary object enumeration and JSON/React prop serialization.
  const config = { accountId, databaseId, publicR2BaseUrl } as CloudReaderConfig;
  Object.defineProperty(config, "d1ReadToken", {
    configurable: false,
    enumerable: false,
    value: d1ReadToken,
    writable: false,
  });
  Object.defineProperty(config, "toJSON", {
    configurable: false,
    enumerable: false,
    value: () => ({ accountId, databaseId, publicR2BaseUrl }),
    writable: false,
  });
  return Object.freeze(config);
}

/** Parse the four server-side cloud values without reading process.env at import time. */
export function parseCloudReaderConfig(env: CloudReaderEnvironment = process.env): CloudReaderConfig {
  const accountId = parseAccountId(env.CLOUDFLARE_ACCOUNT_ID);
  const databaseId = parseDatabaseId(env.COQUIC_STEWARD_D1_DATABASE_ID);
  const d1ReadToken = parseReadToken(env.COQUIC_STEWARD_D1_READ_TOKEN);
  const publicR2BaseUrl = parsePublicR2BaseUrl(env.COQUIC_STEWARD_PUBLIC_R2_BASE_URL);
  return makeConfig(accountId, databaseId, d1ReadToken, publicR2BaseUrl);
}

/** Runtime alias with lazy default environment loading. */
export function getCloudReaderConfig(env: CloudReaderEnvironment = process.env) {
  return parseCloudReaderConfig(env);
}
