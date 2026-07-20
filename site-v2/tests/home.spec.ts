import { expect, test } from "@playwright/test";

test("home leads with the Steward publication", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");

  await expect(page).toHaveTitle("CoQUIC Observatory");
  await expect(
    page.getByRole("heading", { level: 1, name: "CoQUIC" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "CoQUIC", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "An experimental open-source QUIC and HTTP/3 implementation exploring how far Codex can build a full-featured transport stack under minimal direction.",
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Steward growth report" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "From packet behavior to project history",
    }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Measure transport behavior, run protocol experiments, and follow the implementation through source, revisions, and public development sessions.",
    ),
  ).toBeVisible();
  await expect(page.getByText("222,966,844")).toBeVisible();
  await expect(page.getByText("1,907")).toBeVisible();
  await expect(page.getByText("24,216")).toBeVisible();
  await expect(page.getByText("Issues resolved")).toBeVisible();
  await expect(page.getByText("Validation pass rate")).toBeVisible();
  await expect(page.getByText("66.7%")).toBeVisible();
  const report = page
    .getByRole("heading", { name: "Steward growth report" })
    .locator("xpath=ancestor::section");
  await expect(
    report.locator("dd").filter({ hasText: "+420,858 / min" }),
  ).toBeVisible();
  await expect(
    report.locator("dd").filter({ hasText: "1 active" }),
  ).toBeVisible();
  await expect(
    report.locator("dd").filter({ hasText: "+3 / min" }),
  ).toBeVisible();
  await expect(report.locator("dd").filter({ hasText: "+" })).toHaveCount(6);
  await expect(
    report.getByLabel("420,858 additional model tokens in the last 60 seconds"),
  ).toBeVisible();
  await expect(
    report.getByText("July 19, 2026", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Live snapshot")).toBeVisible();

  const day = report.getByRole("button", { name: "Day", exact: true });
  const sevenDays = report.getByRole("button", { name: "7 days" });
  const thirtyDays = report.getByRole("button", { name: "30 days" });
  const allTime = report.getByRole("button", { name: "All time" });
  await expect(day).toHaveAttribute("aria-pressed", "true");

  await sevenDays.click();
  await expect(sevenDays).toHaveAttribute("aria-pressed", "true");
  await expect(report.getByText("5,893,128,126")).toBeVisible();
  await expect(report.getByText("152,860")).toBeVisible();
  await expect(report.getByText("55.6%")).toBeVisible();
  await expect(report.getByText("+420,858 / min")).toBeVisible();
  await expect(
    report.getByText("Jul 13 - Jul 19, 2026", { exact: true }),
  ).toBeVisible();

  await thirtyDays.click();
  await expect(report.getByText("10,020,833,577")).toBeVisible();
  await expect(
    report.getByText("Jun 20 - Jul 19, 2026", { exact: true }),
  ).toBeVisible();
  await expect(report.getByText("87.7%")).toBeVisible();

  await allTime.click();
  await expect(allTime).toHaveAttribute("aria-pressed", "true");
  await expect(report.getByText("1,546")).toBeVisible();
  await expect(report.getByText("1,291,144")).toBeVisible();
  await expect(report.getByText("80.5%")).toBeVisible();
  await expect(
    report.getByText("Mar 17 - Jul 19, 2026", { exact: true }),
  ).toBeVisible();

  const stewardBox = await page
    .getByRole("heading", { name: "Steward growth report" })
    .locator("xpath=ancestor::section")
    .boundingBox();
  expect(stewardBox?.y).toBeLessThan(500);
  expect(browserErrors).toEqual([]);
});

for (const width of [320, 375, 414, 768, 1024, 1440, 1920]) {
  test(`home has no document overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.getByRole("button", { name: "All time" }).click();
    if (width < 640) {
      await expect(page.getByText("10.021B")).toBeVisible();
    }

    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  });
}

test("mobile navigation restores focus after Escape", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");

  const trigger = page.getByRole("button", { name: "Open navigation" });
  await trigger.focus();
  await trigger.press("Enter");
  await expect(page.getByRole("navigation", { name: "Mobile" })).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Steward", exact: true }).last(),
  ).toBeFocused();
  const mobileNavigation = page.getByRole("navigation", { name: "Mobile" });
  await expect(
    mobileNavigation.getByText("Evidence", { exact: true }),
  ).toBeVisible();
  await expect(
    mobileNavigation.getByText("Tools", { exact: true }),
  ).toBeVisible();
  await expect(
    mobileNavigation.getByRole("link", {
      name: "Documentation",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    mobileNavigation.getByRole("link", { name: "Journal", exact: true }),
  ).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByRole("navigation", { name: "Mobile" })).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toBeFocused();
});

test("desktop navigation groups destinations", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");

  const navigation = page.getByRole("navigation", { name: "Primary" });
  await expect(
    navigation.getByRole("link", { name: "Steward", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Documentation", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Journal", exact: true }),
  ).toBeVisible();

  const evidenceBox = await navigation
    .getByText("Evidence", { exact: true })
    .boundingBox();
  expect(evidenceBox?.x).toBeGreaterThan(900);

  await navigation.getByText("Evidence", { exact: true }).hover();
  await expect(
    navigation.getByRole("link", { name: "Performance", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "RFC traceability", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Dataset", exact: true }),
  ).toBeVisible();
  await navigation.getByText("Evidence", { exact: true }).click();
  await expect(
    navigation.getByRole("link", { name: "Performance", exact: true }),
  ).toBeVisible();

  await navigation.getByText("Tools", { exact: true }).hover();
  await expect(
    navigation.getByRole("link", { name: "Workbench", exact: true }),
  ).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Performance", exact: true }),
  ).toBeHidden();

  const repositoryLink = navigation.getByRole("link", {
    name: /minhuw\/coquic on GitHub/,
  });
  await expect(repositoryLink).toBeVisible();
  await expect(repositoryLink).toHaveAttribute(
    "href",
    "https://github.com/minhuw/coquic",
  );
  await expect(repositoryLink.getByText(/^\d+$/)).toBeVisible();
});
