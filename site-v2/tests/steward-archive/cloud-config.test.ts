import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import Module, { createRequire } from "node:module";
import { test } from "node:test";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

type CloudConfigModule = typeof import("@/lib/steward-archive/cloud-config");
type CloudReaderConfigError = InstanceType<CloudConfigModule["CloudReaderConfigError"]>;

const requireForTest = createRequire(resolve(process.cwd(), "tests/steward-archive/cloud-config.test.ts"));
const runtimeModule = Module as unknown as {
  _resolveFilename: (request: string, parent?: unknown, isMain?: boolean, options?: unknown) => string;
};

function loadCloudConfig(): CloudConfigModule {
  const serverOnlyEmpty = join(dirname(requireForTest.resolve("next/package.json")), "dist/compiled/server-only/empty.js");
  const previousResolveFilename = runtimeModule._resolveFilename;
  runtimeModule._resolveFilename = function (request, parent, isMain, options) {
    if (request === "server-only") return serverOnlyEmpty;
    return previousResolveFilename.call(this, request, parent, isMain, options);
  };
  try {
    return requireForTest(resolve(process.cwd(), "lib/steward-archive/cloud-config.ts")) as CloudConfigModule;
  } finally {
    runtimeModule._resolveFilename = previousResolveFilename;
  }
}

const { CloudReaderConfigError, getCloudReaderConfig, parseCloudReaderConfig } = loadCloudConfig();

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

test("Next rejects a client graph that imports cloud configuration", async () => {
  const project = await mkdtemp(join(tmpdir(), "coquic-site-v2-cloud-config-"));
  try {
    const source = await readFile(resolve(process.cwd(), "lib/steward-archive/cloud-config.ts"), "utf8");
    await mkdir(join(project, "app"));
    await symlink(resolve(process.cwd(), "node_modules"), join(project, "node_modules"), "dir");
    await writeFile(join(project, "cloud-config.ts"), source);
    await writeFile(
      join(project, "app/layout.tsx"),
      "export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) { return <html><body>{children}</body></html>; }\n",
    );
    await writeFile(
      join(project, "app/page.tsx"),
      "\"use client\";\nimport { parseCloudReaderConfig } from \"../cloud-config\";\nexport default function Page() { return <main>{typeof parseCloudReaderConfig}</main>; }\n",
    );

    const result = spawnSync(process.execPath, [resolve(process.cwd(), "node_modules/next/dist/bin/next"), "build", "--webpack"], {
      cwd: project,
      encoding: "utf8",
      env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
    });
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    assert.equal(result.error, undefined, String(result.error));
    assert.notEqual(result.status, 0, output);
    assert.match(output, /server-only[\s\S]*(?:cannot be imported from a Client Component module|only available in Server Components)/);
  } finally {
    await rm(project, { force: true, recursive: true });
  }
});
