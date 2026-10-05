import { expect, test } from "@playwright/test";

test.describe("Login hardening", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  test("bad credentials show a generic message @smoke", async ({ page }) => {
    await page.goto("/wp-login.php");
    await page.fill("#user_login", "admin");
    await page.fill("#user_pass", "definitely-wrong");
    await page.click("#wp-submit");

    const error = page.locator("#login_error");
    await expect(error).toBeVisible();
    await expect(error).toContainText(/invalid login credentials/i);
  });
});
