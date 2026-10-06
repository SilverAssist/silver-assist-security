import { expect, test } from "@playwright/test";
import { collectErrors } from "./utils/wp";

const SETTINGS_URL = "/wp-admin/admin.php?page=silver-assist-security";

test.describe("Security Essentials settings screen", () => {
  test("Login Page Branding shows only on the Login Protection tab @smoke", async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto(SETTINGS_URL);
    await expect(page.locator(".silver-nav-tab").first()).toBeVisible();

    const branding = page.getByRole("heading", { name: "Login Page Branding" });
    const tabIds = await page.locator(".silver-nav-tab").evaluateAll((tabs) =>
      tabs.map((t) => (t.getAttribute("href") ?? "").replace("#", ""))
    );
    expect(tabIds).toContain("login-security");
    expect(tabIds.length).toBeGreaterThan(1);

    for (const id of tabIds) {
      await page.locator(`#${id}-tab`).click();
      await expect(page.locator(`#${id}-content`)).toBeVisible();
      if (id === "login-security") {
        await expect(branding, "branding card on its own tab").toBeVisible();
      } else {
        await expect(branding, `branding card must be hidden on the ${id} tab`).toBeHidden();
      }
    }

    expect(errors, errors.join("\n")).toEqual([]);
  });
});
