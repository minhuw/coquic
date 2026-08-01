import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import cleanTrajectory from "../examples/steward-cloud/complete-trajectory-clean.json";
import redactedTrajectory from "../examples/steward-cloud/complete-trajectory-redacted-multimodal.json";

type JsonObject = { [key: string]: unknown };

const ONE_PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);
const ONE_PIXEL_IMAGES = {
  "image/png": ONE_PIXEL_PNG,
  "image/jpeg": Buffer.from(
    "/9j/4AAQSkZJRgABAQAAAAAAAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAABAAEDAREAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAVAQEBAAAAAAAAAAAAAAAAAAAHCf/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/ADoDFU3/2Q==",
    "base64",
  ),
  "image/gif": Buffer.from(
    "R0lGODlhAQABAPAAAP8AAAAAACH5BAAAAAAAIf8LSW1hZ2VNYWdpY2sOZ2FtbWE9MC40NTQ1NDUALAAAAAABAAEAAAICRAEAOw==",
    "base64",
  ),
  "image/webp": Buffer.from(
    "UklGRjwAAABXRUJQVlA4IDAAAADQAQCdASoBAAEAAgA0JaACdLoB+AADsAD+8MQL/yC5YXXI1/8gP+QH/ID/+PIAAAA=",
    "base64",
  ),
} as const;

function cloneJson(value: unknown): JsonObject {
  return structuredClone(value) as JsonObject;
}

function trajectoryData(value: JsonObject): JsonObject {
  return value.data as JsonObject;
}

async function serveTrajectory(page: Page, taskId: string, runId: string, value: unknown) {
  await page.route(`**/api/steward/tasks/${taskId}/transcript**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("run") !== runId) {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(value),
    });
  });
}

async function serveImageArtifacts(page: Page, taskId: string) {
  await page.route(`**/api/steward/tasks/${taskId}/artifact**`, async (route) => {
    const path = new URL(route.request().url()).searchParams.get("path");
    const mediaType = path?.endsWith(".jpg") ? "image/jpeg"
      : path?.endsWith(".gif") ? "image/gif"
        : path?.endsWith(".webp") ? "image/webp"
          : path?.endsWith(".png") ? "image/png" : null;
    if (mediaType && path?.startsWith("steps/2/")) {
      await route.fulfill({ status: 200, contentType: mediaType, body: ONE_PIXEL_IMAGES[mediaType] });
      return;
    }
    await route.fallback();
  });
}

async function openCleanTrajectory(page: Page) {
  await serveTrajectory(page, "task-clean", "run-clean", cleanTrajectory);
  await serveImageArtifacts(page, "task-clean");
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  const trajectory = page.locator("[data-atif-trajectory]");
  await expect(trajectory).toBeVisible();
  await expect(page.locator('[data-trajectory-state="ready"]')).toBeVisible();
  return trajectory;
}

function failedToolTrajectory(): JsonObject {
  const payload = cloneJson(cleanTrajectory);
  const data = trajectoryData(payload);
  const steps = data.steps as JsonObject[];
  for (const key of ["calls", "toolCalls", "tools"] as const) {
    const calls = (steps[1]?.[key] ?? []) as JsonObject[];
    if (calls[0]) calls[0].extensions = { status: "failed", error: "command failed" };
  }
  return payload;
}

function emptyTrajectory(): JsonObject {
  const payload = cloneJson(cleanTrajectory);
  const data = trajectoryData(payload);
  data.steps = [];
  data.artifacts = [];
  (data.metadata as JsonObject).artifacts = [];
  return payload;
}

function toolHeavyTrajectory(): JsonObject {
  const payload = cloneJson(cleanTrajectory);
  const data = trajectoryData(payload);
  const step = (data.steps as JsonObject[])[1]!;
  const calls = Array.from({ length: 8 }, (_, index) => {
    const callId = `call-${index + 1}`;
    const observation = {
      content: `Inspection ${callId}.`,
      parts: [{ kind: "text", type: "text", text: `Inspection ${callId}.` }],
      sourceCallId: callId,
      matchedCallId: callId,
      extensions: null,
      lineage: null,
    };
    return {
      anchor: `call-${callId}`,
      callId,
      id: callId,
      functionName: `inspect-${index + 1}`,
      arguments: { index },
      observations: [observation],
      extensions: null,
    };
  });
  for (const key of ["toolCalls", "calls", "tools"] as const) step[key] = structuredClone(calls);
  step.observation = { results: calls.map((call) => call.observations[0]) };
  step.observations = calls.map((call) => call.observations[0]);
  return payload;
}

function multimodalTrajectory(): JsonObject {
  const payload = cloneJson(redactedTrajectory);
  const data = trajectoryData(payload);
  const step = (data.steps as JsonObject[])[1]!;
  const formats = [
    ["image/jpeg", "artifact-photo", "steps/2/photo.jpg", "11"],
    ["image/gif", "artifact-animation", "steps/2/animation.gif", "22"],
    ["image/webp", "artifact-webp", "steps/2/photo.webp", "33"],
  ] as const;
  const images = formats.map(([mediaType, artifactId, logicalPath, digestByte]) => {
    const href = `/api/steward/tasks/task-redacted/artifact?path=${encodeURIComponent(logicalPath)}`;
    const action = { kind: "image", artifactId, taskId: "task-redacted", runId: "run-redacted", mediaType, logicalPath, href };
    return {
      kind: "image",
      type: "image",
      mediaType,
      artifactId,
      action,
    };
  });
  for (const key of ["message", "content", "parts"] as const) {
    step[key] = [...((step[key] ?? []) as unknown[]), ...structuredClone(images)];
  }
  const artifacts = formats.map(([mediaType, artifactId, logicalPath, digestByte]) => ({
    artifactId,
    mediaType,
    sha256: digestByte.repeat(32),
    byteSize: ONE_PIXEL_IMAGES[mediaType].byteLength,
    ownerStepId: 2,
    action: {
      kind: "image",
      artifactId,
      taskId: "task-redacted",
      runId: "run-redacted",
      mediaType,
      logicalPath,
      href: `/api/steward/tasks/task-redacted/artifact?path=${encodeURIComponent(logicalPath)}`,
    },
    disclosure: { redactionApplied: true, originalRetained: true },
  }));
  data.artifacts = [...(data.artifacts as unknown[]), ...artifacts];
  const metadata = data.metadata as JsonObject;
  metadata.artifacts = structuredClone(data.artifacts);
  return payload;
}

function problemBody(retryable: boolean) {
  return JSON.stringify({
    schemaVersion: "3.0",
    generatedAt: "2026-07-28T00:00:02Z",
    problem: {
      code: "UNAVAILABLE",
      message: "The complete trajectory is temporarily unavailable.",
      retryable,
      status: 503,
      type: null,
    },
  });
}

async function holdTrajectoryResponse(page: Page, taskId: string, runId: string, response: unknown) {
  let release!: () => Promise<void>;
  const pending = new Promise<void>((resolve) => {
    release = async () => {
      resolve();
    };
  });
  await page.route(`**/api/steward/tasks/${taskId}/transcript**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("run") !== runId) {
      await route.fallback();
      return;
    }
    await pending;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
  });
  return () => release();
}

test("Steward task navigation exposes the public task channels", async ({ page }) => {
  await page.goto("/steward?view=tasks");
  await expect(page.getByRole("heading", { level: 1, name: "Steward" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Every visible task publication" })).toBeVisible();
  const channels = page.getByRole("region", { name: "Steward task channels" });
  for (const label of ["Signals", "Planning", "Tasks", "Integration"]) await expect(channels.getByRole("link", { name: new RegExp(label) })).toBeVisible();
  const taskLinks = page.locator('a[href^="/steward/tasks/"]');
  await expect(taskLinks.first()).toBeVisible();
  await taskLinks.first().click();
  await expect(page).toHaveURL(/\/steward\/tasks\//);
});

test("global Signals and Planning remain explicit terminal unavailable states", async ({ page, request }) => {
  for (const [view, heading] of [["signals", "Signals unavailable"], ["planning", "Planning unavailable"]] as const) {
    await page.goto(`/steward?view=${view}`);
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    await expect(page.getByText("No local fallback or fixture records are displayed.", { exact: true })).toBeVisible();
  }
  for (const endpoint of ["/api/steward/revision", "/api/steward/signals/example/events", "/api/steward/planner-runs/example/transcript"]) {
    const response = await request.get(endpoint);
    expect(response.status()).toBe(410);
    expect(await response.text()).not.toContain("example");
  }
});

test("complete trajectory renders every record in source order with stable anchors", async ({ page }) => {
  const trajectory = await openCleanTrajectory(page);
  const records = trajectory.locator("[data-trajectory-anchor]");
  await expect(records).toHaveCount(2);
  expect(await records.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-trajectory-anchor")))).toEqual(["step-1", "step-2"]);
  const ids = await records.evaluateAll((nodes) => nodes.map((node) => node.id));
  expect(new Set(ids).size).toBe(ids.length);
  const outlineLinks = page.getByRole("complementary", { name: "Run outline" }).locator("a[href^='#']");
  await expect(outlineLinks).toHaveCount(2);
  for (const href of await outlineLinks.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href")))) {
    expect(href).toMatch(/^#/);
    expect(await page.locator(href!).count()).toBe(1);
  }
  await expect(trajectory.getByRole("button", { name: /load|more|next page/i })).toHaveCount(0);
});

test("trajectory content uses safe links, local overflow, and paired tool evidence", async ({ page }) => {
  const trajectory = await openCleanTrajectory(page);
  const links = await trajectory.locator("a[href]").evaluateAll((nodes) => nodes.map((node) => ({
    href: node.getAttribute("href") ?? "",
    target: node.getAttribute("target"),
    rel: node.getAttribute("rel"),
  })));
  for (const link of links) {
    const resolved = new URL(link.href, page.url());
    if (resolved.origin !== new URL(page.url()).origin) {
      expect(resolved.protocol).toMatch(/^https?:$/);
      expect(link.target).toBe("_blank");
      expect(link.rel).toContain("noreferrer");
    } else {
      expect(link.href.startsWith("/") || link.href.startsWith("#"), JSON.stringify(link)).toBeTruthy();
    }
    expect(link.href).not.toContain("objects.example");
  }
  await expect(trajectory.locator("[data-tool-call]")).toHaveCount(1);
  await expect(trajectory.locator("[data-tool-observation-association='call-1']")).toBeAttached();
  const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
  const localOverflow = await trajectory.locator("[class*='overflow-auto'], [class*='overflow-x-auto']").evaluateAll((nodes) => nodes.map((node) => node.scrollWidth >= node.clientWidth));
  expect(localOverflow.every(Boolean)).toBeTruthy();
});

test("failed tools open by default and remain keyboard-operable", async ({ page }) => {
  await serveTrajectory(page, "task-clean", "run-clean", failedToolTrajectory());
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  const failedTool = page.locator("details[data-tool-status='failed']");
  await expect(failedTool).toHaveCount(1);
  await expect(failedTool).toHaveAttribute("open", "");
  const summary = failedTool.locator(":scope > summary");
  await summary.focus();
  await expect(summary).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(failedTool).not.toHaveAttribute("open", "");
  await page.keyboard.press("Enter");
  await expect(failedTool).toHaveAttribute("open", "");
});

test("tool-heavy trajectories preserve every paired call and observation", async ({ page }) => {
  const heavyTrajectory = toolHeavyTrajectory();
  await serveTrajectory(page, "task-clean", "run-clean", heavyTrajectory);
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  const trajectory = page.locator("[data-atif-trajectory]");
  await expect(trajectory).toBeVisible();
  await expect(page.locator('[data-trajectory-state="ready"]')).toBeVisible();
  await expect(trajectory.locator("[data-tool-call]")).toHaveCount(8);
  await expect(trajectory.locator("[data-tool-observation-association]")).toHaveCount(8);
  expect(await trajectory.locator("[data-tool-observation-association]").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-tool-observation-association")))).toEqual(
    Array.from({ length: 8 }, (_, index) => `call-${index + 1}`),
  );
});

test("redacted multimodal trajectory preserves disclosure and stable image frames", async ({ page }) => {
  await serveTrajectory(page, "task-redacted", "run-redacted", redactedTrajectory);
  await serveImageArtifacts(page, "task-redacted");
  await page.goto("/steward/tasks/task-redacted?pipeline=pipeline-redacted&run=run-redacted");
  const trajectory = page.locator("[data-atif-trajectory]");
  await expect(page.getByText("Public values redacted", { exact: true })).toBeVisible();
  await expect(page.getByText("Original retained", { exact: true })).toBeVisible();
  const frame = trajectory.locator("[data-artifact-frame]").first();
  await expect(frame).toBeVisible();
  const image = frame.locator("img[data-artifact-image]");
  await expect(image).toBeVisible();
  await expect.poll(async () => image.evaluate((node) => ({ width: (node as HTMLImageElement).naturalWidth, height: (node as HTMLImageElement).naturalHeight }))).toEqual({ width: 1, height: 1 });
  await expect(trajectory.locator("[data-artifact-unavailable]")).toHaveCount(1);
  const hrefs = await trajectory.locator("[data-artifact-download]").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href") ?? ""));
  expect(hrefs.length).toBeGreaterThan(0);
  expect(hrefs.every((href) => href.startsWith("/api/steward/tasks/task-redacted/artifact?path="))).toBeTruthy();
});

test("published JPEG, PNG, GIF, and WebP evidence decodes in stable frames", async ({ page }) => {
  await serveTrajectory(page, "task-redacted", "run-redacted", multimodalTrajectory());
  await serveImageArtifacts(page, "task-redacted");
  await page.goto("/steward/tasks/task-redacted?pipeline=pipeline-redacted&run=run-redacted");
  const trajectory = page.locator("[data-atif-trajectory]");
  const images = trajectory.locator("img[data-artifact-image]");
  await expect(images).toHaveCount(8);
  const decoded = await images.evaluateAll((nodes) => nodes.map((node) => {
    const image = node as HTMLImageElement;
    const frame = image.closest("[data-artifact-frame]") as HTMLElement | null;
    const box = frame?.getBoundingClientRect();
    return { naturalWidth: image.naturalWidth, naturalHeight: image.naturalHeight, width: box?.width ?? 0, height: box?.height ?? 0 };
  }));
  expect(decoded.every((image) => image.naturalWidth > 0 && image.naturalHeight > 0 && image.width >= 160 && image.height >= 120)).toBeTruthy();
  const geometries = new Set(decoded.map((image) => `${Math.round(image.width)}x${Math.round(image.height)}`));
  expect(geometries.size).toBe(2);
  expect(decoded.filter((image) => `${Math.round(image.width)}x${Math.round(image.height)}` === [...geometries][0]).length).toBe(4);
  expect(decoded.filter((image) => `${Math.round(image.width)}x${Math.round(image.height)}` === [...geometries][1]).length).toBe(4);
});

test("trajectory loading announces completion after one cancellable request", async ({ page }) => {
  const release = await holdTrajectoryResponse(page, "task-clean", "run-clean", cleanTrajectory);
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  await expect(page.locator('[data-trajectory-state="loading"]')).toBeVisible();
  await expect(page.locator('[data-trajectory-state="loading"] p[role="status"]')).toHaveText("Loading complete trajectory");
  await release();
  await expect(page.locator('[data-trajectory-state="ready"]')).toBeVisible();
  await expect(page.locator('[data-trajectory-state="ready"] p[role="status"]')).toHaveText("Complete trajectory loaded");
});

test("navigation ignores a late trajectory response after cancellation", async ({ page }) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let completed = false;
  await page.route("**/api/steward/tasks/task-clean/transcript**", async (route) => {
    await pending;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(cleanTrajectory) });
    completed = true;
  });
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  await expect(page.locator('[data-trajectory-state="loading"]')).toBeVisible();
  await page.goto("/steward?view=tasks");
  release();
  await expect.poll(() => completed).toBeTruthy();
  await expect(page).toHaveURL(/\/steward\?view=tasks/);
  await expect(page.locator("[data-atif-trajectory]")).toHaveCount(0);
});

test("empty trajectory is complete without fabricated records", async ({ page }) => {
  await serveTrajectory(page, "task-clean", "run-clean", emptyTrajectory());
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  await expect(page.getByRole("heading", { name: "Completed empty run" })).toBeVisible();
  await expect(page.locator("[data-empty-run]")).toBeVisible();
  await expect(page.locator("[data-trajectory-records]")).toHaveCount(0);
});

test("transient trajectory failure offers manual Retry and terminal failure does not", async ({ page }) => {
  let attempts = 0;
  await page.route("**/api/steward/tasks/task-clean/transcript**", async (route) => {
    attempts += 1;
    if (attempts === 1) {
      await route.fulfill({ status: 503, contentType: "application/json", body: problemBody(true) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(cleanTrajectory) });
  });
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  await expect(page.getByRole("heading", { name: "Trajectory unavailable" })).toBeVisible();
  const retry = page.locator('[data-trajectory-state="unavailable"] button');
  await expect(retry).toBeVisible();
  await retry.click();
  await expect(page.locator('[data-trajectory-state="ready"]')).toBeVisible();
  expect(attempts).toBe(2);

  await page.unroute("**/api/steward/tasks/task-clean/transcript**");
  await page.route("**/api/steward/tasks/task-clean/transcript**", async (route) => {
    await route.fulfill({ status: 404, contentType: "application/json", body: problemBody(false) });
  });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Trajectory unavailable" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
});

test("Steward trajectory surfaces meet accessibility and overflow gates", async ({ page }) => {
  for (const media of [
    { colorScheme: "dark" as const, reducedMotion: "reduce" as const },
    { forcedColors: "active" as const },
  ]) {
    await page.emulateMedia(media);
    await page.setViewportSize({ width: 390, height: 844 });
    const trajectory = await openCleanTrajectory(page);
    const findings = (await new AxeBuilder({ page }).analyze()).violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious");
    expect(findings, findings.map((finding) => `${finding.id}: ${finding.help}`).join("\n")).toEqual([]);
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
    await expect(trajectory.getByRole("heading", { name: "Complete trajectory" }).first()).toBeVisible();
  }
});

test("trajectory remains nonblank and nonoverlapping at desktop, mobile, and 320px", async ({ page }, testInfo) => {
  await serveTrajectory(page, "task-clean", "run-clean", cleanTrajectory);
  await serveImageArtifacts(page, "task-clean");
  for (const viewport of [{ width: 1600, height: 1000 }, { width: 390, height: 844 }, { width: 320, height: 900 }]) {
    await page.setViewportSize(viewport);
    await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
    const trajectory = page.locator("[data-atif-trajectory]");
    await expect(trajectory).toBeVisible();
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
    const records = await trajectory.locator("[data-trajectory-anchor]").evaluateAll((nodes) => nodes.map((node) => {
      const box = node.getBoundingClientRect();
      return { top: box.top, bottom: box.bottom, clipped: node.scrollWidth > node.clientWidth };
    }));
    expect(records.every((record) => !record.clipped)).toBeTruthy();
    for (let index = 1; index < records.length; index += 1) expect(records[index]!.top).toBeGreaterThanOrEqual(records[index - 1]!.bottom - 1);
    const probe = await trajectory.evaluate((node) => {
      const box = node.getBoundingClientRect();
      const point = document.elementFromPoint(box.left + Math.min(8, box.width / 2), box.top + Math.min(8, box.height / 2));
      const style = getComputedStyle(node);
      return { area: box.width * box.height, hasDescendantAtPoint: point !== null && node.contains(point), color: style.color, background: style.backgroundColor };
    });
    expect(probe.area).toBeGreaterThan(0);
    expect(probe.hasDescendantAtPoint || probe.color !== "rgba(0, 0, 0, 0)" || probe.background !== "rgba(0, 0, 0, 0)").toBeTruthy();
    const overlays = await page.evaluate(() => {
      const main = document.querySelector<HTMLElement>("main");
      if (!main) return { conflicts: ["missing main content"] };
      const surface = main.getBoundingClientRect();
      const nodes: HTMLElement[] = [];
      const collect = (root: Document | ShadowRoot) => {
        for (const node of Array.from(root.querySelectorAll<HTMLElement>("*"))) {
          nodes.push(node);
          if (node.shadowRoot) collect(node.shadowRoot);
        }
      };
      collect(document);
      const conflicts = nodes.flatMap((node) => {
        const style = getComputedStyle(node);
        const zIndex = Number.parseInt(style.zIndex, 10);
        if ((style.position !== "fixed" && style.position !== "absolute") || !Number.isFinite(zIndex) || zIndex < 1_000) return [];
        if (style.display === "none" || style.visibility === "hidden" || Number.parseFloat(style.opacity) === 0) return [];
        const box = node.getBoundingClientRect();
        const inViewport = box.right > 0 && box.bottom > 0 && box.left < window.innerWidth && box.top < window.innerHeight;
        const overlapsSurface = box.right > surface.left && box.left < surface.right && box.bottom > surface.top && box.top < surface.bottom;
        return inViewport && overlapsSurface && box.width > 0 && box.height > 0
          ? [{ tag: node.tagName, className: String(node.className), zIndex, box: { left: box.left, top: box.top, right: box.right, bottom: box.bottom } }]
          : [];
      });
      return { conflicts };
    });
    expect(overlays.conflicts, JSON.stringify(overlays.conflicts)).toEqual([]);
    const screenshot = await page.screenshot({ path: testInfo.outputPath(`trajectory-${viewport.width}.png`), fullPage: true });
    expect(screenshot.byteLength).toBeGreaterThan(1_000);
    const pixels = await page.evaluate(async (encoded) => {
      const image = new Image();
      image.src = `data:image/png;base64,${encoded}`;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("canvas 2D context unavailable");
      context.drawImage(image, 0, 0);
      const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
      let opaque = 0;
      let nonBackground = 0;
      const colors = new Set<string>();
      for (let index = 0; index < data.length; index += 4) {
        const red = data[index] ?? 0;
        const green = data[index + 1] ?? 0;
        const blue = data[index + 2] ?? 0;
        const alpha = data[index + 3] ?? 0;
        if (alpha > 0) opaque += 1;
        if (alpha > 0 && (red < 245 || green < 245 || blue < 245)) nonBackground += 1;
        colors.add(`${red >> 4}:${green >> 4}:${blue >> 4}:${alpha >> 4}`);
      }
      return { width: image.naturalWidth, height: image.naturalHeight, opaque, nonBackground, colors: colors.size };
    }, screenshot.toString("base64"));
    const totalPixels = pixels.width * pixels.height;
    expect(pixels.width).toBeGreaterThan(0);
    expect(pixels.height).toBeGreaterThan(0);
    expect(pixels.opaque).toBeGreaterThan(totalPixels * 0.95);
    expect(pixels.nonBackground).toBeGreaterThan(Math.max(100, totalPixels * 0.01));
    expect(pixels.colors).toBeGreaterThan(8);
  }
});

test("task hierarchy remains reachable at 200% page scale", async ({ page }) => {
  await serveTrajectory(page, "task-clean", "run-clean", cleanTrajectory);
  await page.setViewportSize({ width: 640, height: 900 });
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  const session = await page.context().newCDPSession(page);
  await session.send("Emulation.setPageScaleFactor", { pageScaleFactor: 2 });
  const zoom = await page.evaluate(() => ({ scale: window.visualViewport?.scale, width: window.visualViewport?.width, client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(zoom.scale).toBe(2);
  expect(zoom.width).toBe(320);
  expect(zoom.scroll).toBeLessThanOrEqual(zoom.client);
  await expect(page.getByRole("heading", { level: 1, name: "Clean publication fixture" })).toBeVisible();
  const outlineToggle = page.getByRole("button", { name: "Collapse run outline" });
  await outlineToggle.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Expand run outline" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Collapse run outline" })).toBeFocused();
});

test("artifact actions remain same-origin and return one validated redirect", async ({ request }) => {
  const response = await request.get("/api/steward/tasks/task-clean/artifact?path=steps%2F2%2Fplot.png", { maxRedirects: 0 });
  expect(response.status()).toBe(307);
  const location = response.headers()["location"];
  expect(location).toBeTruthy();
  expect(location).not.toContain("private");
  expect(location).not.toContain("attacker");
  expect(response.headers()["x-content-type-options"]).toBe("nosniff");
  expect(response.body()).resolves.toHaveLength(0);
});
