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
 * Explicit save, one Save per tab (#160). Each tab is one form with one Save in a sticky bar; the bar shows
 * unsaved changes with Discard, leaving the page with unsaved changes warns, and nothing is saved in the
 * background. The page is reloaded to read the value back from the server.
 */
test.describe("Explicit save per tab", () => {
  const cases = [
    { tab: "login-security", field: "silver_assist_login_attempts", value: "12", option: "silver_assist_login_attempts" },
    { tab: "ip-management", field: "silver_assist_ip_blacklist_threshold", value: "9", option: "silver_assist_ip_blacklist_threshold" },
  ];

  const bar = (tab: string) => `#${tab}-form .silver-save-bar`;

  test.afterAll(() => {
    for (const { option } of cases) wp("option", "delete", option);
  });

  for (const { tab, field, value } of cases) {
    test(`${tab}: edit, dirty bar, Save, reload @smoke`, async ({ page }) => {
      const errors = collectErrors(page);
      await page.goto(SETTINGS_URL);
      await page.locator(`#${tab}-tab`).click();

      await expect(page.locator(bar(tab))).toHaveAttribute("data-dirty", "false");
      await expect(page.locator(`#${tab}-save-status`)).toHaveText("");

      await page.locator(`#${field}`).fill(value);

      await expect(page.locator(bar(tab))).toHaveAttribute("data-dirty", "true");
      await expect(page.locator(`#${tab}-save-status`)).toContainText("unsaved changes");
      await expect(page.locator(`${bar(tab)} .silver-discard`)).toBeVisible();

      // The page may leave now: the submit below is not "leaving with unsaved changes".
      await page.locator(`#${tab}-submit`).click();
      await expect(page.locator(".notice-success")).toContainText("saved successfully");

      await page.goto(SETTINGS_URL);
      await page.locator(`#${tab}-tab`).click();
      await expect(page.locator(`#${field}`)).toHaveValue(value);
      await expect(page.locator(bar(tab))).toHaveAttribute("data-dirty", "false");

      expect(errors, errors.join("\n")).toEqual([]);
    });
  }

  test("Discard restores the saved values and clears the bar @smoke", async ({ page }) => {
    await page.goto(SETTINGS_URL);
    await page.locator("#ip-management-tab").click();
    const field = page.locator("#silver_assist_ip_blacklist_threshold");
    const saved = await field.inputValue();

    await field.fill(saved === "17" ? "4" : "17");
    await expect(page.locator(bar("ip-management"))).toHaveAttribute("data-dirty", "true");

    await page.locator(`${bar("ip-management")} .silver-discard`).click();

    await expect(field).toHaveValue(saved);
    await expect(page.locator(bar("ip-management"))).toHaveAttribute("data-dirty", "false");
    await expect(page.locator(`${bar("ip-management")} .silver-discard`)).toBeHidden();
    await expect(page.locator("#ip-blacklist-threshold-value")).toHaveText(saved);
  });

  test("leaving with unsaved changes warns, and a clean page does not @smoke", async ({ page }) => {
    const dialogs: string[] = [];
    page.on("dialog", (dialog) => {
      dialogs.push(dialog.type());
      void dialog.accept();
    });

    await page.goto(SETTINGS_URL);
    await page.locator("#ip-management-tab").click();
    await page.goto("/wp-admin/");
    expect(dialogs, "a clean settings page leaves silently").toEqual([]);

    await page.goto(SETTINGS_URL);
    await page.locator("#ip-management-tab").click();
    await page.locator("#silver_assist_ip_blacklist_threshold").fill("5");
    await page.goto("/wp-admin/");
    expect(dialogs).toEqual(["beforeunload"]);
  });

  test("nothing is saved in the background @smoke", async ({ page }) => {
    const autoSaves: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("admin-ajax.php") && (request.postData() ?? "").includes("auto_save")) autoSaves.push(request.url());
    });

    await page.goto(SETTINGS_URL);
    await page.locator("#rest-api-security-tab").click();
    const field = page.locator("#silver_assist_rest_rate_limit_requests");
    const before = wp("eval", "echo (int) get_option('silver_assist_rest_rate_limit_requests', 0);");
    await field.fill("777");
    await expect(page.locator(bar("rest-api-security"))).toHaveAttribute("data-dirty", "true");

    // The removed debounce was 2 seconds.
    await page.waitForTimeout(3000);

    expect(autoSaves).toEqual([]);
    expect(wp("eval", "echo (int) get_option('silver_assist_rest_rate_limit_requests', 0);")).toBe(before);
    // Do not leave the dirty page to the leave-warning of the next test.
    await page.locator(`${bar("rest-api-security")} .silver-discard`).click();
  });

  test("a rejected admin path is shown next to its field and keeps what was typed @smoke", async ({ page }) => {
    await page.goto(SETTINGS_URL);
    await page.locator("#login-security-tab").click();
    await page.locator("#silver_assist_admin_hide_path").fill("wp-json");
    await page.locator("#login-security-submit").click();

    await page.locator("#login-security-tab").click();
    const message = page.locator("#silver_assist_admin_hide_path-message");
    await expect(message).toBeVisible();
    await expect(message).toHaveAttribute("role", "alert");
    await expect(page.locator("#silver_assist_admin_hide_path")).toHaveValue("wp-json");
    await expect(page.locator("#silver_assist_admin_hide_path")).toHaveAttribute("aria-invalid", "true");
    expect(wp("eval", "echo get_option('silver_assist_admin_hide_path', '');")).not.toBe("wp-json");
  });

  test("Admin Hide needs the URL confirmed before it takes effect @smoke", async ({ page }) => {
    await page.goto(SETTINGS_URL);
    await page.locator("#login-security-tab").click();
    const confirm = page.locator("#silver_assist_admin_hide_confirm");
    const confirmationRequired = () => confirm.evaluate((el: HTMLInputElement) => el.validity.valueMissing);

    expect(await confirmationRequired(), "no confirmation is needed while nothing changes").toBe(false);

    await page.locator("#silver_assist_admin_hide_path").fill("e2e-private-door");
    await expect(page.locator("#admin-hide-url-preview")).toContainText("/e2e-private-door");
    await page.locator("label.toggle-switch:has(#silver_assist_admin_hide_enabled)").click();
    expect(await confirmationRequired(), "turning it on makes the confirmation required").toBe(true);

    // Send it anyway, as a client without the script would: the server refuses and says so at the toggle.
    await page.locator("#login-security-form").evaluate((form: HTMLFormElement) => {
      form.noValidate = true;
      (form.querySelector("#silver_assist_admin_hide_confirm") as HTMLInputElement).setCustomValidity("");
    });
    await page.locator("#login-security-submit").click();

    await page.locator("#login-security-tab").click();
    const message = page.locator("#silver_assist_admin_hide_enabled-message");
    await expect(message).toContainText("confirm");
    await expect(page.locator("#silver_assist_admin_hide_enabled")).toBeChecked();
    expect(wp("eval", "echo (int) get_option('silver_assist_admin_hide_enabled', 0);")).toBe("0");
    expect(wp("eval", "echo get_option('silver_assist_admin_hide_path', '');")).not.toBe("e2e-private-door");
  });

  test("every tab has one form and one Save button with an id of its own", async ({ page }) => {
    await page.goto(SETTINGS_URL);

    const tabs = await page.locator(".silver-tab-content").evaluateAll((panels) => panels.map((p) => p.id));
    for (const id of tabs.filter((panel) => panel !== "dashboard-content")) {
      const panel = page.locator(`#${id}`);
      if ((await panel.locator("form").count()) === 0) continue;
      expect(await panel.locator("form").count(), `${id} must have one form`).toBe(1);
      expect(await panel.locator("form input[type=submit]").count(), `${id} must have one Save`).toBe(1);
    }

    const ids = await page.locator("form input[type=submit]").evaluateAll((buttons) => buttons.map((b) => b.id));
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.every((id) => id !== "" && id !== "submit")).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
