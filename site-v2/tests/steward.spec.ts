import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

test("dashboard renders canonical counts, totals, coverage, and freshness", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error" && !message.text().startsWith("Failed to load resource:")) errors.push(message.text()); });
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/steward?view=tasks");
  await expect(page.getByRole("heading", { level: 1, name: "Steward" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "All canonical states" })).toBeVisible();
  await expect(page.getByText("Synthetic live task", { exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic completed task", { exact: true })).toBeVisible();
  await expect(page.getByText("1,050", { exact: true })).toBeVisible();
  await expect(page.getByText("7/111 runs", { exact: true }).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("all active tasks remain prominent while terminal history stays paginated at 50", async ({ page, request }) => {
  await page.goto("/steward?view=tasks");
  await expect(page.getByRole("link", { name: "Synthetic live task" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Second active task" })).toBeVisible();
  const first = await request.get("/api/steward/tasks");
  const payload = await first.json() as { data: { tasks: Array<{ status: string }>; nextCursor: string | null } };
  expect(payload.data.tasks).toHaveLength(50); expect(payload.data.nextCursor).toBeTruthy();
  expect(payload.data.tasks.every((task) => !["queued", "running", "reviewing", "integrating"].includes(task.status))).toBeTruthy();
});

test("global signals and planning remain explicitly disconnected", async ({ page }) => {
  for (const view of ["signals", "planning"]) {
    await page.goto(`/steward?view=${view}`);
    await expect(page.getByText("Not connected in this archive consumer. No checked-in fixture records are displayed.", { exact: true })).toBeVisible();
    await expect(page.getByText("Synthetic completed task", { exact: true })).toHaveCount(0);
  }
});

test("revision monitoring refreshes once per revision and pauses while hidden", async ({ page }) => {
  let revision = 1;
  let polls = 0;
  let refreshes = 0;
  await page.addInitScript(() => {
    const nativeTimeout = window.setTimeout.bind(window);
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => nativeTimeout(handler, timeout && timeout >= 30_000 ? 50 : timeout, ...args)) as typeof window.setTimeout;
  });
  await page.route("**/api/steward/revision", async (route) => { polls += 1; await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ data: { revision } }) }); });
  page.on("request", (request) => { const headers = request.headers(); if (headers.rsc === "1" && !headers["next-router-prefetch"] && request.url().includes("/steward?view=tasks")) refreshes += 1; });
  await page.goto("/steward?view=tasks");
  await expect.poll(() => polls).toBeGreaterThan(0);
  refreshes = 0; revision = 2;
  await expect.poll(() => refreshes).toBe(1);
  await new Promise((resolve) => setTimeout(resolve, 150));
  expect(refreshes).toBe(1);
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, value: true }); document.dispatchEvent(new Event("visibilitychange")); });
  const hiddenPolls = polls;
  await new Promise((resolve) => setTimeout(resolve, 150));
  expect(polls).toBeLessThanOrEqual(hiddenPolls + 1);
  await page.evaluate(() => { Object.defineProperty(document, "hidden", { configurable: true, value: false }); document.dispatchEvent(new Event("visibilitychange")); });
  await expect.poll(() => polls).toBeGreaterThan(hiddenPolls);
});

test("task detail preserves every pipeline run and owned review and patch evidence", async ({ page }) => {
  await page.goto("/steward/tasks/task-complete-synthetic");
  await expect(page.getByRole("heading", { level: 1, name: "Synthetic completed task" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Planning runs" })).toContainText("run-plan");
  await expect(page.locator("#attempts > div:last-child > div")).toHaveCount(2);
  await page.getByRole("button", { name: /Pipeline 01:/ }).click();
  for (const runId of ["run-plan", "run-implementation", "run-formality", "run-review", "run-repair-implementation", "run-repair-review", "run-integration"]) await expect(page.getByText(runId, { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Owned runs").first()).toBeVisible();
  await expect(page.getByText("Integration").first()).toBeVisible();
  await page.goto("/steward/tasks/task-complete-synthetic?attempt=0&artifact=review#attempt-1-evidence");
  await expect(page.getByText(/Raw evidence/).first()).toBeVisible();
  await expect(page.getByText(/Effective evidence/).first()).toBeVisible();
  await page.goto("/steward/tasks/task-complete-synthetic?attempt=0&artifact=patch#attempt-1-evidence");
  await expect(page.getByRole("link", { name: "Download raw patch" })).toHaveAttribute("href", /artifact\?path=/);
});

test("a transcript already at end discovers active append without losing loaded rows", async ({ page, request }) => {
  await page.addInitScript(() => {
    const nativeTimeout = window.setTimeout.bind(window);
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => nativeTimeout(handler, timeout && timeout >= 30_000 ? 50 : timeout, ...args)) as typeof window.setTimeout;
  });
  await page.goto("/steward/tasks/task-running-synthetic?artifact=transcript");
  const transcript = page.getByLabel("Agent transcript"); const records = transcript.locator('[id^="archive-event-"]');
  await transcript.getByRole("button", { name: "Load more" }).click(); await expect(records).toHaveCount(77);
  const before = await (await request.get("/api/steward/revision")).json() as { data: { revision: number } };
  const root = process.env.STEWARD_TEST_TASKS_ROOT!;
  await appendFile(join(root, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl"), `${JSON.stringify({ record_type: "assistant.message", text: "Active append after end" })}\n`);
  await expect.poll(async () => ((await (await request.get("/api/steward/revision")).json()) as { data: { revision: number } }).data.revision).toBeGreaterThan(before.data.revision);
  const load = transcript.getByRole("button", { name: "Load more" }); await expect(load).toBeEnabled(); await load.click();
  await expect(records).toHaveCount(78); await expect(transcript.getByText("Active append after end", { exact: true }).first()).toBeVisible();
  const ordinals = await records.evaluateAll((nodes) => nodes.map((node) => node.id)); expect(new Set(ordinals).size).toBe(78);
});

test("raw downloads stream accepted bytes with safe attachment headers", async ({ request }) => {
  const response = await request.get("/api/steward/tasks/task-running-synthetic/artifact?path=prompt.md");
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("text/markdown");
  expect(response.headers()["content-disposition"]).toMatch(/^attachment; filename="prompt\.md"; filename\*=UTF-8''prompt\.md$/);
  expect(response.headers()["x-content-type-options"]).toBe("nosniff"); expect(response.headers()["cache-control"]).toBe("no-store");
  expect(Number(response.headers()["content-length"])).toBe((await response.body()).length);
});

test("artifact bodies are fetched only after their owning evidence is selected", async ({ page }) => {
  const artifactRequests: string[] = [];
  page.on("request", (request) => { if (request.url().includes("/artifact?")) artifactRequests.push(request.url()); });
  await page.goto("/steward/tasks/task-complete-synthetic?attempt=0&artifact=transcript");
  expect(artifactRequests).toEqual([]);
  await page.getByRole("link", { name: "Validation" }).first().click();
  await expect(page.getByRole("link", { name: "Download validation log" }).first()).toBeVisible(); expect(artifactRequests).toEqual([]);
  const download = page.waitForEvent("download"); await page.getByRole("link", { name: "Download validation log" }).first().click(); await download;
  expect(artifactRequests).toHaveLength(1);
});

test("revision polling backs off, announces delay, and cleans up after unmount", async ({ page }) => {
  await page.addInitScript(() => {
    const nativeTimeout = window.setTimeout.bind(window);
    (window as typeof window & { __revisionDelays: number[] }).__revisionDelays = [];
    window.setTimeout = ((handler: TimerHandler, timeout?: number, ...args: unknown[]) => { if (timeout && timeout >= 30_000) (window as typeof window & { __revisionDelays: number[] }).__revisionDelays.push(timeout); return nativeTimeout(handler, timeout && timeout >= 30_000 ? timeout / 1000 : timeout, ...args); }) as typeof window.setTimeout;
  });
  let polls = 0;
  await page.route("**/api/steward/revision", async (route) => { polls += 1; if (polls <= 2) await route.fulfill({ status: 503, body: "unavailable" }); else await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ data: { revision: 1 } }) }); });
  await page.goto("/steward?view=tasks");
  await expect(page.getByText("Archive refresh is delayed. Retrying automatically.")).toBeAttached();
  await expect.poll(async () => page.evaluate(() => (window as typeof window & { __revisionDelays: number[] }).__revisionDelays)).toEqual(expect.arrayContaining([60_000, 120_000]));
  await expect.poll(() => polls).toBeGreaterThanOrEqual(3); await page.goto("/"); const stoppedAt = polls; await page.waitForTimeout(200); expect(polls).toBe(stoppedAt);
});

test("Steward surfaces have no serious accessibility findings across supported media", async ({ page }) => {
  for (const media of [{ colorScheme: "dark" as const, reducedMotion: "reduce" as const }, { forcedColors: "active" as const }]) {
    await page.emulateMedia(media); await page.setViewportSize({ width: 390, height: 844 }); await page.goto("/steward/tasks/task-complete-synthetic");
    const findings = (await new AxeBuilder({ page }).analyze()).violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious");
    expect(findings, findings.map((finding) => `${finding.id}: ${finding.help}`).join("\n")).toEqual([]);
    const width = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth })); expect(width.scroll).toBeLessThanOrEqual(width.client);
  }
});

test("selected transcript loads bounded chunks without duplicates and preserves focus", async ({ page }) => {
  await page.goto("/steward/tasks/task-running-synthetic?artifact=transcript");
  const transcript = page.getByLabel("Agent transcript");
  const records = transcript.locator('[id^="archive-event-"]');
  await expect(records).toHaveCount(50);
  const load = transcript.getByRole("button", { name: "Load more" });
  await load.click();
  await expect(records).toHaveCount(78);
  const transcriptButton = transcript.getByRole("button", { name: "All complete records loaded" });
  await expect(transcriptButton).toBeFocused();
  const ids = await records.evaluateAll((nodes) => nodes.map((node) => node.id));
  expect(new Set(ids).size).toBe(ids.length);
});

test("desktop and compact archive surfaces do not overflow", async ({ page }, testInfo) => {
  for (const viewport of [{ width: 1600, height: 1000 }, { width: 390, height: 844 }, { width: 320, height: 900 }]) {
    await page.setViewportSize(viewport);
    await page.goto("/steward/tasks/task-complete-synthetic");
    const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client);
    if (viewport.width !== 320) await page.screenshot({ path: testInfo.outputPath(`task-${viewport.width}.png`), fullPage: true });
  }
});

test("changed accepted transcript prefix returns a stale cursor without replacement bytes", async ({ request }) => {
  const root = process.env.STEWARD_TEST_TASKS_ROOT;
  expect(root).toBeTruthy();
  const path = "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl";
  const first = await request.get(`/api/steward/tasks/task-running-synthetic/transcript?run=run-implementation-recovery&path=${encodeURIComponent(path)}&limit=1`);
  expect(first.ok()).toBeTruthy();
  const payload = await first.json() as { data: { nextCursor: string } };
  const absolute = join(root!, "task-running", ...path.split("/"));
  const original = await readFile(absolute);
  await writeFile(absolute, `${JSON.stringify({ record_type: "assistant.message", text: "replacement must not escape" })}\n`);
  const stale = await request.get(`/api/steward/tasks/task-running-synthetic/transcript?run=run-implementation-recovery&path=${encodeURIComponent(path)}&cursor=${encodeURIComponent(payload.data.nextCursor)}`);
  expect(stale.status()).toBe(409);
  expect(await stale.text()).not.toContain("replacement must not escape");
  await writeFile(absolute, original);
  const traversal = await request.get("/api/steward/tasks/task-running-synthetic/artifact?path=..%2Fepoch.json");
  expect(traversal.status()).toBe(404);
});
