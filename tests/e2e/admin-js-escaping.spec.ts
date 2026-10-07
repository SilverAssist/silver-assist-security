import { expect, test, type Page, type Route } from "@playwright/test";
import { wp } from "./utils/wp-cli";

/**
 * Admin scripts must treat every value they put into the DOM as text (#177).
 *
 * Each case feeds the markup below through a mocked AJAX response or a localized string, then asserts
 * that nothing executed (window.__xss stays undefined), that no element was created from it, and that
 * the text is shown literally. The values come from the plugin's own strings and handlers today, so
 * this is defense in depth: one translation file or one handler that echoes input must not become
 * stored XSS on an admin screen.
 */

const SETTINGS_URL = "/wp-admin/admin.php?page=silver-assist-security";
const PAYLOAD = "<img src=x onerror=window.__xss=1>";
const JS_URL = "javascript:window.__xss=1";

type Strings = Record<string, string>;
type Handler = (route: Route) => Promise<void> | void;

/**
 * Overlay localized strings before the plugin script reads them, and optionally add the markup of a
 * panel that is only rendered when its feature is active (Contact Form 7), so its code path runs.
 */
async function arm(page: Page, strings: Strings, fixtures = ""): Promise<void> {
  await page.addInitScript(
    ({ strings, fixtures }) => {
      let current: any;
      Object.defineProperty(window, "silverAssistSecurity", {
        configurable: true,
        get: () => current,
        set: (value) => {
          current = value;
          if (value && typeof value === "object") value.strings = { ...(value.strings ?? {}), ...strings };
        },
      });
      if (fixtures) {
        // Registered before jQuery's own listener, so the markup exists when the plugin initializes.
        document.addEventListener("DOMContentLoaded", () => {
          if (!document.querySelector("#cf7-blocked-ips-content")) {
            document.body.insertAdjacentHTML("beforeend", fixtures);
          }
        });
      }
    },
    { strings, fixtures },
  );
}

/** Answer admin-ajax by action; every action without a handler gets an empty failure so the page stays quiet. */
async function mockAjax(page: Page, handlers: Record<string, Handler>): Promise<void> {
  await page.route("**/admin-ajax.php", async (route) => {
    const body = route.request().postData() ?? "";
    const action = new URLSearchParams(body).get("action") ?? "";
    const handler = handlers[action];
    if (handler) return handler(route);
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ success: false, data: {} }) });
  });
}

const json = (body: unknown): Handler => (route) =>
  route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });

const serverError: Handler = (route) => route.fulfill({ status: 500, body: "boom" });

/** Nothing ran, no element came out of the text, and the text is on screen as typed. */
async function expectLiteral(page: Page, locator: ReturnType<Page["locator"]>): Promise<void> {
  await expect(locator).toContainText(PAYLOAD);
  await expect(locator.locator("img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
}

test.describe("Admin scripts escape what they render (#177)", () => {
  test("dashboard fallbacks show localized strings as text @smoke", async ({ page }) => {
    await arm(page, { error: PAYLOAD, noThreats: PAYLOAD });
    await mockAjax(page, { silver_assist_get_blocked_ips: serverError });
    await page.goto(SETTINGS_URL);
    await expectLiteral(page, page.locator("#blocked-ips-list .error"));

    await page.unroute("**/admin-ajax.php");
    await mockAjax(page, { silver_assist_get_blocked_ips: json({ success: true, data: { blocked_ips: [] } }) });
    await page.reload();
    await expectLiteral(page, page.locator("#blocked-ips-list .no-threats"));
    await expectLiteral(page, page.locator("#ip-mgmt-blocked-ips-list .no-threats"));
  });

  test("a rejected request shows the localized fallback as text @smoke", async ({ page }) => {
    await arm(page, { noThreats: PAYLOAD });
    await mockAjax(page, { silver_assist_get_blocked_ips: json({ success: false, data: {} }) });
    await page.goto(SETTINGS_URL);
    await expectLiteral(page, page.locator("#blocked-ips-list .no-threats"));
  });

  test("the update notice shows version, label and link safely @smoke", async ({ page }) => {
    await arm(page, { newVersionAvailable: `New ${PAYLOAD} %s`, updateNow: PAYLOAD, updateUrl: JS_URL });
    await mockAjax(page, {
      silver_assist_security_check_version: json({ success: true, data: { update_available: true, latest_version: PAYLOAD } }),
    });
    await page.goto(SETTINGS_URL);

    const notice = page.locator(".notice-info").filter({ hasText: "Silver Assist Security Essentials" });
    await expectLiteral(page, notice);
    // A javascript: URL from a string must not become a live link.
    const hrefs = await notice.locator("a").evaluateAll((links) => links.map((a) => a.getAttribute("href") ?? ""));
    for (const href of hrefs) expect(href.toLowerCase()).not.toContain("javascript:");
  });

  test("form validation errors show localized text literally @smoke", async ({ page }) => {
    await arm(page, { loginAttemptsError: PAYLOAD });
    await page.goto(SETTINGS_URL);
    await page.locator("#login-security-tab").click();
    // The field is a range slider, so set the out-of-range value directly and submit the form like Save does.
    await page.locator("#silver_assist_login_attempts").evaluate((el: HTMLInputElement) => {
      el.removeAttribute("max");
      el.value = "999";
      el.form!.requestSubmit();
    });

    await expectLiteral(page, page.locator(".notice-error"));
  });

  test("the admin path indicator shows a server error as text @smoke", async ({ page }) => {
    await mockAjax(page, {
      silver_assist_validate_admin_path: json({ success: false, data: { error: PAYLOAD } }),
    });
    await page.goto(SETTINGS_URL);
    await page.locator("#silver_assist_admin_hide_path").evaluate((el: HTMLInputElement) => {
      el.value = "e2e-escape-path";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await expectLiteral(page, page.locator("#admin-path-validation"));
  });

  test("the Contact Form 7 panel shows error and fallback strings as text @smoke", async ({ page }) => {
    const panel = `<div id="cf7-blocked-ips-content"></div><span id="cf7-threat-count"></span>`;
    await arm(page, { errorLoadingCF7IPs: PAYLOAD }, panel);

    await mockAjax(page, {
      silver_assist_get_cf7_blocked_ips: json({ success: false, data: { error: PAYLOAD } }),
    });
    await page.goto(SETTINGS_URL);
    await expectLiteral(page, page.locator("#cf7-blocked-ips-content .error"));

    await page.unroute("**/admin-ajax.php");
    await mockAjax(page, { silver_assist_get_cf7_blocked_ips: serverError });
    await page.reload();
    await expectLiteral(page, page.locator("#cf7-blocked-ips-content .error"));
  });

  test("the GraphQL API key panel shows server and localized text literally @smoke", async ({ page }) => {
    await arm(page, {
      apiKeyActive: PAYLOAD,
      apiKeyConfigured: PAYLOAD,
      apiKeyRegenerateConfirm: `"><img src=x onerror=window.__xss=1>`,
      regenerateApiKey: PAYLOAD,
      revokeApiKey: PAYLOAD,
      usageExample: PAYLOAD,
      usageExampleDesc: PAYLOAD,
      error: PAYLOAD,
    });
    await mockAjax(page, {
      silver_assist_generate_graphql_api_key: json({
        success: true,
        data: { api_key: PAYLOAD, message: PAYLOAD, needs_service_user: true, warning: PAYLOAD },
      }),
      silver_assist_revoke_graphql_api_key: json({ success: false, data: { error: PAYLOAD } }),
    });
    await page.goto(SETTINGS_URL);

    // The panel is only rendered with WPGraphQL; its handlers are delegated, so a minimal fixture drives them.
    await page.evaluate(() => {
      document.body.insertAdjacentHTML(
        "beforeend",
        `<div id="graphql-api-key-result" style="display:none"></div><div id="graphql-api-key-status"></div>` +
          `<table><tbody><tr><td><p id="graphql-api-key-actions">` +
          `<button type="button" id="graphql-generate-api-key">Generate</button></p></td></tr></tbody></table>`,
      );
    });

    await page.locator("#graphql-generate-api-key").dispatchEvent("click");
    await expectLiteral(page, page.locator("#graphql-api-key-result"));
    await expectLiteral(page, page.locator("#graphql-api-key-status"));
    await expectLiteral(page, page.locator("#graphql-api-key-actions"));
    // The confirm text sits in an attribute: it must stay one attribute value.
    await expect(page.locator("#graphql-regenerate-api-key")).toHaveAttribute("data-confirm", `"><img src=x onerror=window.__xss=1>`);
    await expect(page.locator("#graphql-api-key-actions img")).toHaveCount(0);

    page.once("dialog", (dialog) => dialog.accept());
    await page.locator("#graphql-revoke-api-key").dispatchEvent("click");
    await expectLiteral(page, page.locator("#graphql-api-key-result"));
  });
});

test.describe("Password validation escapes localized messages (#177)", () => {
  test.afterAll(() => {
    wp("option", "delete", "silver_assist_password_strength_enforcement");
  });

  test("the profile screen shows the localized message as text @smoke", async ({ page }) => {
    wp("option", "update", "silver_assist_password_strength_enforcement", "1");
    // password-validation.js reads passwordError and passwordSuccess from the same localized object.
    await page.addInitScript(
      ({ payload }) => {
        let current: any;
        Object.defineProperty(window, "silverAssistSecurity", {
          configurable: true,
          get: () => current,
          set: (value) => {
            current = value && typeof value === "object" ? { ...value, passwordError: payload, passwordSuccess: payload } : value;
          },
        });
      },
      { payload: PAYLOAD },
    );
    await page.goto("/wp-admin/profile.php");

    const field = page.locator("#pass1");
    // WordPress hides the field until "Set New Password" is pressed on the profile screen.
    const toggle = page.locator(".wp-generate-pw");
    if (await toggle.isVisible()) await toggle.click();
    for (const value of ["abc", "Str0ng-Passw0rd!x"]) {
      await field.fill(value);
      await expectLiteral(page, page.locator("#silver-assist-password-validation"));
    }
  });
});
