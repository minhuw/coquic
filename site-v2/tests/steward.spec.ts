import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import cleanTrajectory from "../examples/steward-cloud/complete-trajectory-clean.json";
import redactedTrajectory from "../examples/steward-cloud/complete-trajectory-redacted-multimodal.json";

type JsonObject = { [key: string]: unknown };

const ONE_PIXEL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

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
    if (path === "steps/2/plot.png") {
      await route.fulfill({ status: 200, contentType: "image/png", body: ONE_PIXEL_PNG });
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
  const calls = (steps[1]?.calls ?? []) as JsonObject[];
  if (calls[0]) calls[0].extensions = { status: "failed", error: "command failed" };
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

function problemBody(retryable: boolean) {
  return JSON.stringify({
    schemaVersion: "3.0",
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
    expect(link.href.startsWith("/") || link.href.startsWith("#")).toBeTruthy();
    expect(link.href).not.toMatch(/^https?:\/\//);
    expect(link.href).not.toContain("objects.example");
    if (link.target === "_blank") expect(link.rel).toContain("noreferrer");
  }
  await expect(trajectory.locator("[data-tool-call]")).toHaveCount(1);
  await expect(trajectory.locator("[data-tool-observation-association='call-1']")).toBeVisible();
  const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
  const localOverflow = await trajectory.locator("[class*='overflow-auto'], [class*='overflow-x-auto']").evaluateAll((nodes) => nodes.map((node) => node.scrollWidth >= node.clientWidth));
  expect(localOverflow.every(Boolean)).toBeTruthy();
});

test("failed tools open by default and remain keyboard-operable", async ({ page }) => {
  await serveTrajectory(page, "task-clean", "run-clean", failedToolTrajectory());
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  const failedTool = page.locator("details[data-tool-status='failed']");
  await expect(failedTool).toHaveAttribute("open", "");
  const summary = failedTool.locator("summary");
  await summary.focus();
  await expect(summary).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(failedTool).not.toHaveAttribute("open", "");
  await page.keyboard.press("Enter");
  await expect(failedTool).toHaveAttribute("open", "");
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

test("trajectory loading announces completion after one cancellable request", async ({ page }) => {
  const release = await holdTrajectoryResponse(page, "task-clean", "run-clean", cleanTrajectory);
  await page.goto("/steward/tasks/task-clean?pipeline=pipeline-clean&run=run-clean");
  await expect(page.locator('[data-trajectory-state="loading"]')).toBeVisible();
  await expect(page.getByRole("status", { name: "Loading complete trajectory" })).toBeVisible();
  await release();
  await expect(page.locator('[data-trajectory-state="ready"]')).toBeVisible();
  await expect(page.getByRole("status", { name: "Complete trajectory loaded" })).toBeAttached();
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
  const retry = page.getByRole("button", { name: "Retry" });
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
    const screenshot = await page.screenshot({ path: testInfo.outputPath(`trajectory-${viewport.width}.png`), fullPage: true });
    expect(screenshot.byteLength).toBeGreaterThan(1_000);
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
