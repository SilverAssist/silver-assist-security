import { expect, test, type Page, type Route } from "@playwright/test";
import { collectErrors } from "./utils/wp";

/**
 * Result messages of the admin AJAX handlers (#186).
 *
 * admin.js calls showMessage() from every success and error path of the IP handlers. It used to be
 * undefined, so each call threw a ReferenceError and the admin never saw the result. These specs drive
 * the manual IP block with a mocked admin-ajax response and check the persistent live regions
 * (role="status" for success, role="alert" for errors), the plain-text rendering, and that nothing throws.
 */

const SETTINGS_URL = "/wp-admin/admin.php?page=silver-assist-security";
const PAYLOAD = "<img src=x onerror=window.__xss=1>";
const STATUS = "#silver-assist-messages-status";
const ALERT = "#silver-assist-messages-alert";

type Handler = (route: Route) => Promise<void> | void;

/** Answer admin-ajax by action; every action without a handler gets an empty failure so the page stays quiet. */
async function mockAjax(page: Page, handlers: Record<string, Handler>): Promise<void> {
  await page.route("**/admin-ajax.php", async (route) => {
    const action = new URLSearchParams(route.request().postData() ?? "").get("action") ?? "";
    const handler = handlers[action];
    if (handler) return handler(route);
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ success: false, data: {} }) });
  });
}

const json = (body: unknown): Handler => (route) =>
  route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });

/** Open the IP Management tab and submit the manual block form with the given address. */
async function blockIp(page: Page, ip: string): Promise<void> {
  await page.goto(SETTINGS_URL);
  await page.locator("#ip-management-tab").click();
  await page.locator("#manual-ip-address").fill(ip);
  await page.locator("#add-manual-ip").click();
}

/** Nothing ran, no element came out of the text, and the text is on screen as typed. */
async function expectLiteral(page: Page, region: string): Promise<void> {
  await expect(page.locator(region)).toContainText(PAYLOAD);
  await expect(page.locator(`${region} img`)).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
}

test.describe("Admin result messages (#186)", () => {
  test("a blocked IP shows the success message in the status region @smoke", async ({ page }) => {
    const errors = collectErrors(page);
    await mockAjax(page, { silver_assist_add_manual_ip: json({ success: true, data: { message: `Blocked ${PAYLOAD}` } }) });
    await blockIp(page, "192.168.1.100");

    await expect(page.locator(STATUS)).toHaveAttribute("role", "status");
    await expect(page.locator(`${STATUS} .notice-success`)).toBeVisible();
    await expectLiteral(page, STATUS);
    await expect(page.locator(`${ALERT} .notice`)).toHaveCount(0);
    // The form is cleared by the success handler right after the message, so the call did not throw.
    await expect(page.locator("#manual-ip-address")).toHaveValue("");
    expect(errors, errors.join("\n")).toEqual([]);
  });

  test("a rejected block shows the server error in the alert region and keeps it @smoke", async ({ page }) => {
    const errors = collectErrors(page);
    await page.clock.install();
    await mockAjax(page, { silver_assist_add_manual_ip: json({ success: false, data: { error: PAYLOAD } }) });
    await blockIp(page, "192.168.1.100");

    await expect(page.locator(ALERT)).toHaveAttribute("role", "alert");
    await expect(page.locator(`${ALERT} .notice-error`)).toBeVisible();
    await expectLiteral(page, ALERT);

    // Errors do not auto-dismiss, however long the page stays open.
    await page.clock.fastForward(60_000);
    await expect(page.locator(`${ALERT} .notice-error`)).toBeVisible();
    expect(errors, errors.join("\n")).toEqual([]);
  });

  test("a success message dismisses itself and the dismiss button works @smoke", async ({ page }) => {
    const errors = collectErrors(page);
    await page.clock.install();
    await mockAjax(page, { silver_assist_add_manual_ip: json({ success: true, data: { message: "IP blocked" } }) });
    await blockIp(page, "192.168.1.100");

    await expect(page.locator(`${STATUS} .notice-success`)).toHaveText(/IP blocked/);
    await page.clock.fastForward(15_000);
    await expect(page.locator(`${STATUS} .notice`)).toHaveCount(0);

    // Same region, now dismissed by hand.
    await page.locator("#manual-ip-address").fill("192.168.1.101");
    await page.locator("#add-manual-ip").click();
    await expect(page.locator(`${STATUS} .notice-success`)).toBeVisible();
    await page.locator(`${STATUS} .notice-dismiss`).click();
    await expect(page.locator(`${STATUS} .notice`)).toHaveCount(0);
    expect(errors, errors.join("\n")).toEqual([]);
  });

  test("an invalid address and a failed request both reach the alert region @smoke", async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));
    await mockAjax(page, { silver_assist_add_manual_ip: (route) => route.fulfill({ status: 500, body: "boom" }) });
    await blockIp(page, "not-an-ip");

    await expect(page.locator(`${ALERT} .notice-error`)).toContainText(/valid IP address/i);

    await page.locator("#manual-ip-address").fill("192.168.1.100");
    await page.locator("#add-manual-ip").click();
    await expect(page.locator(`${ALERT} .notice-error`)).toContainText(/Error blocking IP/i);
    // The form is usable again after the failure.
    await expect(page.locator("#add-manual-ip")).toBeEnabled();
    expect(pageErrors, pageErrors.join("\n")).toEqual([]);
  });
});
