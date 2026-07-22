import { expect, test } from "@playwright/test";

const previewPassword = process.env.COQUIC_V2_PREVIEW_PASSWORD;

test.describe("V2 preview access", () => {
  test.skip(!previewPassword, "preview password is not configured");

  test("explains the preview and returns to the requested route", async ({ page }) => {
    await page.goto("/steward?view=signals");

    await expect(page).toHaveURL(/\/preview\?next=/);
    await expect(
      page.getByRole("heading", { name: "CoQUIC V2 is under construction" }),
    ).toBeVisible();
    await expect(page.getByText("Preview in progress")).toBeVisible();

    const password = page.getByLabel("Shared preview password");
    await password.fill("incorrect-preview-password");
    await page.getByRole("button", { name: "Enter preview" }).click();
    await expect(page.locator("#preview-error")).toHaveText(
      "That preview password did not match.",
    );

    await password.fill(previewPassword!);
    await page.getByRole("button", { name: "Enter preview" }).click();
    await expect(page).toHaveURL(/\/steward\?view=signals$/);
    await expect(page.getByRole("heading", { level: 1, name: "Steward" })).toBeVisible();

    await page.reload();
    await expect(page).toHaveURL(/\/steward\?view=signals$/);
  });

  test("fits compact screens and rejects external return paths", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 720 });
    await page.goto("/preview?next=https://example.com/");

    const dimensions = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);

    await page.getByLabel("Shared preview password").fill(previewPassword!);
    await page.getByRole("button", { name: "Enter preview" }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page).not.toHaveURL(/example\.com/);
  });
});
