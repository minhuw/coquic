import { expect, test } from "@playwright/test";

test("Steward opens on task execution and exposes the complete control loop", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/steward");

  await expect(page).toHaveTitle("Steward | CoQUIC Observatory");
  await expect(page.getByRole("heading", { level: 1, name: "Steward" })).toBeVisible();
  await expect(page.getByLabel("Steward control loop")).toBeVisible();
  await expect(page.getByLabel("Steward control loop").getByRole("link", { name: /Tasks/ })).toHaveAttribute("href", "/steward?view=tasks");
  await expect(page.getByRole("heading", { name: "Every task, from plan to integration" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Issue #39 RFC 9001 0-RTT policy", exact: true })).toBeVisible();
  await expect(page.getByText("Investigate Test workflow run 27362846640", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Task pipeline").first()).toContainText("Code");
  await expect(page.getByRole("link", { name: /Investigate Test workflow run 27362846640/ })).toHaveAttribute("href", /steward\/tasks\/task-20260625083823-fe54560a/);
  expect(browserErrors).toEqual([]);
});

test("Signals preserve pending context and scheduled relationships", async ({ page }) => {
  await page.goto("/steward?view=signals");

  await expect(page.getByRole("heading", { name: "Evidence waiting for a decision" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Pending signals", exact: true })).toBeVisible();
  await expect(page.getByText("Interop workflow run 29308192091 failed", { exact: true })).toBeVisible();
  await expect(page.getByText("29308192091", { exact: true })).toBeVisible();
  await expect(page.getByText("Awaiting planner", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Scheduled", exact: true })).toBeVisible();
  await expect(page.getByText("Local variable shadows global in connection_send.cpp", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open alert" })).toHaveAttribute("href", "https://github.com/minhuw/coquic/security/code-scanning/6006");
  await expect(page.getByRole("heading", { name: "Providers" })).toBeVisible();
  await expect(page.getByText("provider error", { exact: true })).toBeVisible();
});

test("Planning displays proposed tasks and contradictory producer state honestly", async ({ page }) => {
  await page.goto("/steward?view=planning");

  await expect(page.getByRole("heading", { name: "How evidence becomes bounded work" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Pending wakeups" })).toBeVisible();
  await expect(page.getByText("Selected planner run", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Diagnostics" })).toBeVisible();
  await expect(page.getByText("Output proposals").first()).toBeVisible();
  await expect(page.getByText("Canonical proposed").first()).toBeVisible();
  await expect(page.getByText("Producer state.").first()).toBeVisible();
  await expect(page.getByText(/output contains two proposals/)).toBeVisible();
  await expect(page.getByRole("link", { name: /task-20260714120212-d46ab9aa/ }).first()).toHaveAttribute("href", "/steward/tasks/task-20260714120212-d46ab9aa");
});

test("Task detail connects pipeline, attempts, tools, validation, review, patch, and timeline", async ({ page }) => {
  await page.goto("/steward/tasks/task-20260625083823-fe54560a");

  await expect(page.getByRole("heading", { level: 1, name: "Investigate Test workflow run 27362846640" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Execution pipeline" })).toBeVisible();
  await expect(page.getByLabel("Task state transition graph")).toBeVisible();
  await expect(page.getByLabel("Review returned to implementation: 1 transition")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Run brief" })).toBeVisible();
  const attemptDisclosures = page.locator("#attempts > div:last-child > div");
  const attemptButton = (index: number) => attemptDisclosures.nth(index).getByRole("button", { name: /^Attempt/ });
  await expect(attemptDisclosures).toHaveCount(2);
  await expect(attemptButton(0)).toHaveAttribute("aria-expanded", "false");
  await expect(attemptButton(1)).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByLabel("Agent transcript")).toBeVisible();
  const publishedUsage = page.getByRole("region", { name: "Model usage" });
  await expect(publishedUsage.getByText("Not recorded for this attempt", { exact: true })).toBeVisible();
  const runOutline = page.getByLabel("Run outline");
  await expect(runOutline.getByText("Understand & plan", { exact: true })).toBeVisible();
  await expect(runOutline.getByText("Validate", { exact: true })).toBeVisible();
  await runOutline.getByRole("button", { name: "Collapse run outline" }).click();
  await expect(runOutline.getByRole("button", { name: "Expand run outline" })).toBeVisible();
  await runOutline.getByRole("button", { name: "Expand run outline" }).click();
  await expect(page.getByText("6 events", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Agent transcript").getByText("nix develop -c zig build test", { exact: true })).toBeVisible();
  await attemptButton(1).click();
  await expect(page.getByLabel("Agent transcript")).not.toBeVisible();
  await attemptButton(1).click();

  await attemptButton(0).click();
  await expect(attemptDisclosures.nth(0).getByText("Transcript excerpt not published", { exact: true })).toBeVisible();
  await expect(attemptDisclosures.nth(0).getByText("Tail excerpts are shown in this V2 preview; canonical run artifacts remain authoritative.", { exact: true })).toHaveCount(0);
  await expect(attemptButton(0)).not.toHaveAttribute("aria-current");
  await expect(attemptButton(1)).not.toHaveAttribute("aria-current");
  await expect(attemptDisclosures.nth(0).getByRole("link", { name: "Transcript", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(attemptDisclosures.nth(1).getByRole("link", { name: "Transcript", exact: true })).toHaveAttribute("aria-current", "page");

  await attemptDisclosures.nth(1).getByRole("link", { name: "Validation", exact: true }).click();
  await expect(page).toHaveURL(/artifact=validation/);
  await expect(page.getByText("314 tests passed, including the new bounded timer-wakeup case.")).toBeVisible();

  await page.locator("#attempt-2-evidence").getByRole("link", { name: "Review", exact: true }).click();
  await expect(page.getByText("No validation gaps recorded.")).toBeVisible();

  await page.goto("/steward/tasks/task-20260625083823-fe54560a?attempt=0&artifact=review#attempt-1-evidence");
  const firstAttempt = page.locator("#attempt-1-evidence");
  await expect(firstAttempt.getByRole("button")).toHaveAttribute("aria-expanded", "true");
  await expect(firstAttempt.getByText("Patch changes address family instead of fixing the CI hang", { exact: true })).toBeVisible();

  await page.locator("#attempt-1-evidence").getByRole("link", { name: "Patch", exact: true }).click();
  await expect(page.getByText("Structured patch not published", { exact: true })).toBeVisible();
  await page.goto("/steward/tasks/task-20260625083823-fe54560a?attempt=1&artifact=patch#attempt-2-evidence");
  await expect(page.locator("#attempt-2-evidence").getByRole("button").first()).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("4 changed files", { exact: false })).toBeVisible();
  await expect(page.getByText("+41", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Changed files").getByText("src/http09/http09_runtime.cpp", { exact: true })).toBeVisible();
  const selectedPatchFile = page.getByLabel("Changed files").getByText("tests/http09/runtime/io_test.cpp", { exact: true });
  await selectedPatchFile.scrollIntoViewIfNeeded();
  const scrollBeforeFileSelection = await page.evaluate(() => window.scrollY);
  await selectedPatchFile.click();
  await expect(page).toHaveURL(/file=tests%2Fhttp09%2Fruntime%2Fio_test.cpp/);
  expect(Math.abs((await page.evaluate(() => window.scrollY)) - scrollBeforeFileSelection)).toBeLessThan(12);
  await expect(page.getByRole("heading", { name: "tests/http09/runtime/io_test.cpp" })).toBeVisible();
  await expect(page.getByText("repeated_timer_wakeups_without_peer_input_timeout.exit_code", { exact: false })).toBeVisible();

  await expect(page.getByRole("heading", { name: "Timeline" })).not.toBeVisible();
  await page.getByRole("button", { name: "Open timeline" }).click();
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("heading", { name: "Timeline" })).not.toBeVisible();
});

test("Running task marks future evidence unavailable instead of fabricating results", async ({ page }) => {
  await page.goto("/steward/tasks/task-20260714120212-d46ab9aa?artifact=validation");

  await expect(page.getByRole("heading", { level: 1, name: "Issue #39 RFC 9001 0-RTT policy" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open GitHub issue #39" })).toHaveAttribute("href", "https://github.com/minhuw/coquic/issues/39");
  await expect(page.getByText("Worker active", { exact: true })).toBeVisible();
  await expect(page.getByText("Validation not started", { exact: true })).toBeVisible();
  await expect(page.locator("#attempt-1-evidence").getByText("Task was running at publication time.", { exact: true })).toBeVisible();
  await expect(page.getByText("23 scoped source, test, documentation, and Duvet paths.", { exact: true })).toHaveCount(0);
});

test("Real Steward trajectory preserves validation and review returns through integration", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  const taskId = "task-20260712124934-e08ef7c8";
  await page.goto(`/steward/tasks/${taskId}?attempt=0&artifact=validation#attempt-1-evidence`);

  await expect(page.getByRole("heading", { level: 1, name: "Issue #20 exact CONNECTION_CLOSE packet replay" })).toBeVisible();
  const taskHeader = page.locator("main header").first();
  await expect(taskHeader.getByText(taskId, { exact: true })).toBeVisible();
  await expect(taskHeader.getByText("Feature", { exact: true })).toBeVisible();
  await expect(taskHeader.getByText("implementation-plan-0", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Open GitHub issue #20" })).toHaveAttribute("href", "https://github.com/minhuw/coquic/issues/20");
  const validationReturn = page.getByLabel("Validation returned to implementation: 2 transitions");
  const reviewReturn = page.getByLabel("Review returned to implementation: 2 transitions");
  await expect(validationReturn).toBeVisible();
  await expect(reviewReturn).toBeVisible();
  await validationReturn.click();
  const transitionEvidence = page.getByLabel("Selected transition evidence");
  await expect(transitionEvidence.getByText("Attempts 01, 03", { exact: true })).toBeVisible();
  await expect(transitionEvidence.getByText("env COQUIC_CLANG_TIDY_IN_NIX=1 pre-commit run --all-files failed.", { exact: true }).first()).toBeVisible();
  await reviewReturn.click();
  await expect(transitionEvidence.getByText("Attempts 02, 04", { exact: true })).toBeVisible();
  await expect(transitionEvidence.getByText("Cached close replays bypass outbound observability", { exact: true })).toBeVisible();
  const attempts = page.locator("#attempts > div:last-child > div");
  await expect(attempts).toHaveCount(5);
  await expect(attempts.nth(0).getByRole("button", { name: /^Attempt/ })).toHaveAttribute("aria-expanded", "true");
  await expect(attempts.nth(0).getByText("Validation failed", { exact: true })).toBeVisible();
  await expect(attempts.nth(0).getByText("env COQUIC_CLANG_TIDY_IN_NIX=1 pre-commit run --all-files", { exact: true })).toBeVisible();
  await expect(attempts.nth(0).getByText("Failed", { exact: true })).toBeVisible();

  await page.goto(`/steward/tasks/${taskId}?attempt=0&artifact=transcript&transcript=published#attempt-1-evidence`);
  const firstMessage = page.locator("#attempt-1-event-a0-transcript");
  const messageHeader = firstMessage.locator("article > header");
  await expect(messageHeader.getByRole("heading", { name: "Published worker transcript tail" })).toBeVisible();
  await expect(messageHeader.locator("time")).toHaveText("Jul 12, 3:30 PM UTC");
  const todoLists = firstMessage.getByRole("region", { name: "Todo" });
  await expect(todoLists).toHaveCount(3);
  const todo = todoLists.first();
  await expect(todo.getByRole("checkbox")).toHaveCount(5);
  await expect(todo.getByRole("checkbox", { checked: true })).toHaveCount(4);
  await expect(todo.getByRole("checkbox", { checked: false })).toHaveCount(1);
  const transcriptCommands = firstMessage.locator("details[data-transcript-command]");
  await expect(transcriptCommands).toHaveCount(3);
  await expect(transcriptCommands.first()).not.toHaveAttribute("open");
  await transcriptCommands.first().locator("summary").click();
  await expect(transcriptCommands.first().locator("pre")).toContainText("9 files changed, 173 insertions(+), 1 deletion(-)");

  await page.goto(`/steward/tasks/${taskId}?attempt=1&artifact=review#attempt-2-evidence`);
  await expect(page.getByText("Cached close replays bypass outbound observability", { exact: true })).toBeVisible();
  await expect(page.getByText("Block", { exact: true })).toBeVisible();

  await page.goto(`/steward/tasks/${taskId}?attempt=4&artifact=validation#attempt-5-evidence`);
  const finalAttempt = page.locator("#attempt-5-evidence");
  await expect(finalAttempt.getByText("Earlier output omitted · published tail", { exact: true })).toHaveCount(1);
  const validationTail = finalAttempt.getByLabel("Published validation tail");
  await expect(validationTail).toContainText("[----------] 3 tests from AllCipherSuites/QuicProtectedCodecOneRttTest");
  await expect(validationTail).not.toHaveText(/^otal\)/);

  await page.goto(`/steward/tasks/${taskId}?attempt=4&artifact=transcript&transcript=published#attempt-5-evidence`);
  await expect(page.locator("#attempt-5-evidence").getByLabel("Published tool output tail")).toHaveCount(1);

  await page.goto(`/steward/tasks/${taskId}?attempt=4&artifact=patch#attempt-5-evidence`);
  await expect(page.getByText("9 changed files", { exact: false })).toBeVisible();
  await expect(page.getByText("+330", { exact: true })).toBeVisible();
  await expect(page.getByText("-1", { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel("Changed files").getByText("src/quic/connection/connection_send.cpp", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Raw patch" })).toHaveAttribute("href", "https://github.com/minhuw/coquic/commit/21c7b95cd6ee0f18c652a4227b0c757ff06e1a80.patch");
  expect(browserErrors).toEqual([]);
});

test("Task detail exposes planning runs separately from implementation attempts", async ({ page }) => {
  const taskId = "task-20260712124934-e08ef7c8";
  await page.goto(`/steward/tasks/${taskId}?transcript=published`);

  const planning = page.getByRole("region", { name: "Planning runs" });
  const run = planning.locator("#plan-run-1");
  const runSummary = run.locator("summary").first();
  await expect(planning.getByText("1", { exact: true })).toBeVisible();
  await expect(run).not.toHaveAttribute("open");
  await expect(run.getByText("Run 01", { exact: true })).toBeVisible();
  await expect(run.getByText("Succeeded", { exact: true })).toBeVisible();
  await expect(runSummary).toContainText("5m 41s");
  await expect(runSummary).toContainText("gpt-5.6-sol");
  await expect(runSummary).toContainText("Xhigh");
  await expect(runSummary.getByRole("link", { name: "gpt-5.6-sol" })).toHaveAttribute("href", "https://developers.openai.com/api/docs/models/gpt-5.6-sol");
  await expect(runSummary.getByLabel("Reasoning effort: xhigh")).toBeVisible();
  await expect(run.getByText("144 source events", { exact: true })).toHaveCount(0);

  await runSummary.click();
  await expect(run).toHaveAttribute("open");
  await expect(run.locator(":scope > div > dl")).toHaveCount(0);
  await expect(run.getByRole("heading", { name: "Published planner transcript tail", exact: true })).toBeVisible();
  await expect(run.getByText("Published planner transcript tail · 56.9 KB of 778 KB", { exact: true })).toBeVisible();
  await expect(run.getByRole("region", { name: "Model usage" }).getByText("Not recorded for this run", { exact: true })).toBeVisible();

  const runBrief = await page.getByRole("heading", { name: "Run brief", exact: true }).boundingBox();
  const planningRuns = await page.getByRole("heading", { name: "Planning runs", exact: true }).boundingBox();
  const attempts = await page.getByRole("heading", { name: "Attempts", exact: true }).boundingBox();
  expect(runBrief).not.toBeNull();
  expect(planningRuns).not.toBeNull();
  expect(attempts).not.toBeNull();
  expect(planningRuns!.y).toBeGreaterThan(runBrief!.y);
  expect(attempts!.y).toBeGreaterThan(planningRuns!.y);
});

test("Local planning run renders original usage and commands without cadence", async ({ page }) => {
  const taskId = "task-20260712124934-e08ef7c8";
  await page.goto(`/steward/tasks/${taskId}`);
  const run = page.locator("#plan-run-1");
  await run.locator("summary").first().click();
  const transcript = run.getByLabel("Agent transcript");
  const commands = transcript.locator("details[data-private-transcript-command]");
  test.skip(await commands.count() === 0, "ignored private planner transcript artifact is not installed");

  await expect(commands).toHaveCount(70);
  const usage = transcript.getByRole("region", { name: "Model usage" });
  await expect(usage.getByText("1 turn · 71 events · 70 commands", { exact: true })).toBeVisible();
  await expect(usage.getByText("1.46M", { exact: true })).toBeVisible();
  await expect(usage.getByText("1.45M", { exact: true })).toBeVisible();
  await expect(usage.getByText("1.30M", { exact: true })).toBeVisible();
  await expect(usage.getByText("12.5K", { exact: true })).toBeVisible();
  await expect(usage.getByText("4.1K", { exact: true })).toBeVisible();
  await expect(transcript.getByRole("region", { name: "Run cadence" })).toHaveCount(0);

  await commands.first().locator("summary").click();
  await expect(commands.first().locator("pre")).not.toBeEmpty();
});

test("local private Steward transcript renders the complete original event stream", async ({ page }) => {
  const taskId = "task-20260712124934-e08ef7c8";
  await page.goto(`/steward/tasks/${taskId}?attempt=0&artifact=transcript#attempt-1-evidence`);
  const transcript = page.locator("#attempt-1-evidence").getByLabel("Agent transcript");
  const commands = transcript.locator("details[data-private-transcript-command]");
  test.skip(await commands.count() === 0, "ignored private transcript artifact is not installed");

  await expect(page.getByRole("link", { name: "Original JSONL" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Published excerpt" })).toHaveCount(0);
  await expect(transcript.getByText("111 events", { exact: false })).toBeVisible();
  await expect(transcript.getByText("86 commands", { exact: false })).toBeVisible();
  await expect(page.getByText("Partial publication", { exact: true })).not.toBeVisible();
  await expect(page.getByText("Sanitized public transcript tails are excerpted", { exact: false })).not.toBeVisible();

  await expect(commands).toHaveCount(86);
  await commands.first().locator("summary").click();
  await expect(commands.first().locator("pre")).toContainText("No such file or directory");
  await expect(page.getByText("Steward execution evidence. Missing artifacts remain missing.", { exact: true })).toBeVisible();
  const usage = transcript.getByRole("region", { name: "Model usage" });
  await expect(usage.getByText("1 turn · 111 events · 86 commands", { exact: true })).toBeVisible();
  await expect(usage.getByText("8.31M", { exact: true })).toBeVisible();
  await expect(usage.getByText("8.28M", { exact: true })).toBeVisible();
  await expect(usage.getByText("8.01M", { exact: true })).toBeVisible();
  await expect(usage.getByText("31.8K", { exact: true })).toBeVisible();
  await expect(usage.getByText("15.8K", { exact: true })).toBeVisible();
  await expect(usage.getByText("272K uncached", { exact: true })).toHaveCount(0);
  await expect(usage.getByText("96.7% of input", { exact: true })).toHaveCount(0);
  await expect(usage.getByText("Cost", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Complete publication", { exact: true })).toHaveCount(0);

  const cadence = transcript.getByRole("region", { name: "Run cadence" });
  await expect(cadence.getByText("15 message intervals · 15m 17s", { exact: true })).toBeVisible();
  const messageIntervals = cadence.getByLabel("Message interval timeline").getByRole("link");
  await expect(messageIntervals).toHaveCount(15);
  await expect(messageIntervals.first()).toHaveAttribute("href", "#attempt-1-event-item_0");
  await expect(messageIntervals.first()).toHaveAttribute("aria-label", "Message 1: 9.8s");
  await expect(messageIntervals.nth(4)).toHaveAttribute("aria-label", "Message 5: 5m 30s");
  await messageIntervals.nth(4).hover();
  const cadenceTooltip = messageIntervals.nth(4).locator("[data-cadence-tooltip]");
  await expect(cadenceTooltip).toBeVisible();
  await expect(cadenceTooltip).toContainText("05 · 5m 30s");
  await expect(cadenceTooltip).toContainText("The close path has a clean insertion point");
  const fifthMessageHref = await messageIntervals.nth(4).getAttribute("href");
  expect(fifthMessageHref).not.toBeNull();
  await messageIntervals.nth(4).click();
  await expect(page.locator(fifthMessageHref!)).toBeInViewport();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
});

test("all retained attempts render their original local worker transcripts", async ({ page }) => {
  test.slow();
  const taskId = "task-20260712124934-e08ef7c8";
  const expectedCommands = [86, 15, 111, 15, 26];

  for (let attempt = 0; attempt < expectedCommands.length; attempt += 1) {
    await page.goto(`/steward/tasks/${taskId}?attempt=${attempt}&artifact=transcript#attempt-${attempt + 1}-evidence`);
    const evidence = page.locator(`#attempt-${attempt + 1}-evidence`);
    const transcript = evidence.getByLabel("Agent transcript");
    const commands = transcript.locator("details[data-private-transcript-command]");
    test.skip(await commands.count() === 0, "ignored private worker transcripts are not installed");

    await expect(commands).toHaveCount(expectedCommands[attempt]);
    await expect(evidence.getByText("Partial publication", { exact: true })).toHaveCount(0);
    const attemptSummary = evidence.locator(":scope > div").first();
    await expect(attemptSummary).toContainText("gpt-5.6-luna");
    await expect(attemptSummary).toContainText("Xhigh");
    await expect(attemptSummary.getByRole("link", { name: "gpt-5.6-luna" })).toHaveAttribute("href", "https://developers.openai.com/api/docs/models/gpt-5.6-luna");
    await expect(attemptSummary.getByLabel("Reasoning effort: xhigh")).toBeVisible();
  }
});

test("Steward pipeline has a static mobile transition view", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/steward/tasks/task-20260712124934-e08ef7c8");

  await expect(page.getByLabel("Task state transition graph")).not.toBeVisible();
  const transitions = page.getByLabel("Task state transitions");
  await expect(transitions).toBeVisible();
  await expect(transitions.getByRole("listitem").filter({ hasText: "Implementation to validation" })).toContainText("5");
  await expect(transitions.getByRole("listitem").filter({ hasText: "Review returned to implementation" })).toContainText("Attempts 02, 04");
});

test("desktop Steward views use parallel dashboard panes", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 1000 });

  await page.goto("/steward");
  const queue = await page.getByRole("heading", { name: "Execution queue" }).boundingBox();
  const selected = await page.getByText("Selected execution · active", { exact: true }).boundingBox();
  const evidence = await page.getByRole("heading", { name: "Current evidence" }).boundingBox();
  expect(queue).not.toBeNull();
  expect(selected).not.toBeNull();
  expect(evidence).not.toBeNull();
  expect(Math.abs(queue!.y - selected!.y)).toBeLessThan(30);
  expect(selected!.x).toBeGreaterThan(queue!.x);
  expect(evidence!.x).toBeGreaterThan(selected!.x);

  await page.goto("/steward?view=signals");
  const providers = await page.getByRole("heading", { name: "Providers" }).boundingBox();
  const pending = await page.getByRole("heading", { name: "Pending signals" }).boundingBox();
  const scheduled = await page.getByRole("heading", { name: "Scheduled" }).boundingBox();
  expect(Math.abs(providers!.y - pending!.y)).toBeLessThan(30);
  expect(pending!.x).toBeGreaterThan(providers!.x);
  expect(scheduled!.x).toBeGreaterThan(pending!.x);

  await page.goto("/steward/tasks/task-20260714120212-d46ab9aa");
  const plan = await page.getByRole("heading", { name: "Run brief", exact: true }).boundingBox();
  const attempts = await page.getByRole("heading", { name: "Attempts" }).boundingBox();
  expect(plan).not.toBeNull();
  expect(attempts).not.toBeNull();
  expect(attempts!.y).toBeGreaterThan(plan!.y);

  const transcript = await page.getByLabel("Agent transcript").boundingBox();
  expect(transcript).not.toBeNull();
  expect(transcript!.width).toBeGreaterThan(1200);

  const timelineTrigger = page.getByRole("button", { name: "Open timeline" });
  await expect(timelineTrigger).toHaveAttribute("aria-expanded", "false");
  await timelineTrigger.hover();
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
});

for (const width of [320, 390, 768, 1440, 1920]) {
  test(`Steward has no document overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const path of [
      "/steward",
      "/steward?view=signals",
      "/steward?view=planning",
      "/steward/tasks/task-20260714120212-d46ab9aa",
      "/steward/tasks/task-20260625083823-fe54560a?artifact=patch",
      "/steward/tasks/task-20260712124934-e08ef7c8",
    ]) {
      await page.goto(path);
      const dimensions = await page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      }));
      expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
    }
  });
}
