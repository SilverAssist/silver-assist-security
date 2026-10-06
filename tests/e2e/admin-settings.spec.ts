import { expect, test } from "@playwright/test";
import { collectErrors } from "./utils/wp";
import { wp } from "./utils/wp-cli";

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

/**
 * The Save buttons must persist what the form shows (#159). Five of them posted neither the gate field
 * nor the nonce the server checks, so they saved nothing. Auto-save is aborted here so the button is the
 * only thing that can persist the value, and the page is reloaded to read it back from the server.
 */
test.describe("Save buttons persist the settings", () => {
  const cases = [
    { tab: "login-security", field: "silver_assist_login_attempts", value: "12", button: "login-settings-submit", option: "silver_assist_login_attempts" },
    { tab: "ip-management", field: "silver_assist_ip_blacklist_threshold", value: "9", button: "ip-management-submit", option: "silver_assist_ip_blacklist_threshold" },
  ];

  test.afterAll(() => {
    for (const { option } of cases) wp("option", "delete", option);
  });

  for (const { tab, field, value, button } of cases) {
    test(`${tab}: edit, Save, reload @smoke`, async ({ page }) => {
      const errors = collectErrors(page);
      await page.route("**/admin-ajax.php", (route) =>
        route.request().postData()?.includes("silver_assist_auto_save") ? route.abort() : route.continue()
      );

      await page.goto(SETTINGS_URL);
      await page.locator(`#${tab}-tab`).click();
      await page.locator(`#${field}`).fill(value);
      await page.locator(`#${button}`).click();

      await expect(page.locator(".notice-success")).toContainText("saved successfully");

      await page.goto(SETTINGS_URL);
      await page.locator(`#${tab}-tab`).click();
      await expect(page.locator(`#${field}`)).toHaveValue(value);

      expect(errors, errors.join("\n")).toEqual([]);
    });
  }

  test("every Save button has an id of its own", async ({ page }) => {
    await page.goto(SETTINGS_URL);
    const ids = await page.locator("form input[type=submit]").evaluateAll((buttons) => buttons.map((b) => b.id));
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.every((id) => id !== "" && id !== "submit")).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
