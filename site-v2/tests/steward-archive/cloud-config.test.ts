import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CloudReaderConfigError,
  getCloudReaderConfig,
  parseCloudReaderConfig,
} from "@/lib/steward-archive/cloud-config";

const ACCOUNT_ID = "ABCDEF0123456789ABCDEF0123456789";
const DATABASE_ID = "12345678-1234-4abc-8def-1234567890AB";
const READ_TOKEN = "cf-read-token/does-not-leak";

function environment(overrides: Record<string, string | undefined> = {}) {
  return {
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    COQUIC_STEWARD_D1_DATABASE_ID: DATABASE_ID,
    COQUIC_STEWARD_D1_READ_TOKEN: READ_TOKEN,
    COQUIC_STEWARD_PUBLIC_R2_BASE_URL: "https://objects.example.test/archive",
    ...overrides,
  };
}

function errorCode(action: () => unknown, code: CloudReaderConfigError["code"]) {
  assert.throws(action, (error: unknown) => error instanceof CloudReaderConfigError && error.code === code);
}

test("valid cloud values normalize and remain server-only", () => {
  const config = parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_READ_TOKEN: ` ${READ_TOKEN} ` }));
  assert.equal(config.accountId, ACCOUNT_ID.toLowerCase());
  assert.equal(config.databaseId, DATABASE_ID.toLowerCase());
  assert.equal(config.d1ReadToken, READ_TOKEN);
  assert.equal(config.publicR2BaseUrl, "https://objects.example.test/archive/");
  assert(Object.isFrozen(config));
  assert(!Object.keys(config).includes("d1ReadToken"));
  assert(!Object.keys(config).some((key) => key.includes("PUBLIC")));
  assert(!JSON.stringify(config).includes(READ_TOKEN));
});

test("runtime loading is lazy and accepts only the four canonical names", () => {
  const config = getCloudReaderConfig(environment());
  assert.equal(config.d1ReadToken, READ_TOKEN);

  errorCode(
    () => parseCloudReaderConfig({
      COQUIC_STEWARD_CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
      COQUIC_STEWARD_D1_DATABASE_ID: DATABASE_ID,
      COQUIC_STEWARD_D1_TOKEN: READ_TOKEN,
      COQUIC_STEWARD_R2_BASE_URL: "https://objects.example.test/archive/",
    }),
    "missing-account-id",
  );
});

test("missing and malformed identifiers or token fail by stable category", () => {
  errorCode(() => parseCloudReaderConfig(environment({ CLOUDFLARE_ACCOUNT_ID: undefined })), "missing-account-id");
  errorCode(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_DATABASE_ID: undefined })), "missing-database-id");
  errorCode(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_READ_TOKEN: "   " })), "missing-d1-read-token");
  errorCode(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_PUBLIC_R2_BASE_URL: undefined })), "missing-public-r2-base-url");
  errorCode(() => parseCloudReaderConfig(environment({ CLOUDFLARE_ACCOUNT_ID: "not-an-account" })), "invalid-account-id");
  errorCode(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_DATABASE_ID: "not-a-uuid" })), "invalid-database-id");

  const secret = "secret-token-that-must-not-appear";
  assert.throws(
    () => parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_READ_TOKEN: `${secret}\n` })),
    (error: unknown) => error instanceof CloudReaderConfigError && !String(error).includes(secret),
  );
  errorCode(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_D1_READ_TOKEN: "x".repeat(4097) })), "invalid-d1-read-token");
});

test("public R2 bases require safe HTTPS origins and contained paths", () => {
  for (const value of [
    "http://objects.example.test/archive/",
    "https://user:password@objects.example.test/archive/",
    "https://objects.example.test/archive?download=1",
    "https://objects.example.test/archive#fragment",
    "https://objects.example.test/archive/../private",
    "https://objects.example.test/archive/%2e%2e/private",
    "not a URL",
  ]) {
    assert.throws(() => parseCloudReaderConfig(environment({ COQUIC_STEWARD_PUBLIC_R2_BASE_URL: value })), CloudReaderConfigError);
  }

  assert.equal(
    parseCloudReaderConfig(environment({ COQUIC_STEWARD_PUBLIC_R2_BASE_URL: "https://CDN.Example.test/nested/base" })).publicR2BaseUrl,
    "https://cdn.example.test/nested/base/",
  );
  assert.equal(parseCloudReaderConfig(environment({ COQUIC_STEWARD_PUBLIC_R2_BASE_URL: "https://objects.example.test" })).publicR2BaseUrl, "https://objects.example.test/");
});
