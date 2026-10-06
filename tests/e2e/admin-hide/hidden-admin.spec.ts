import { expect, test } from "@playwright/test";
import { resetLoginState, wp } from "../utils/wp-cli";
import { ADMIN_PASS, ADMIN_USER, HIDDEN_PATH, loginThroughHiddenPath, openHiddenLogin, visitor } from "./support";

test.describe("Admin hiding: anonymous visitors", () => {
  test.use(visitor(11));

  test("wp-login.php and wp-admin answer 404 without a session @smoke", async ({ request }) => {
    for (const path of ["/wp-login.php", "/wp-admin/", "/wp-admin/index.php", "/wp-admin/plugins.php"]) {
      const res = await request.get(path, { maxRedirects: 0 });
      expect(res.status(), path).toBe(404);
    }
  });

  test("the secret path leads to the login form, and a login lands on the dashboard @smoke", async ({ page }) => {
    await openHiddenLogin(page);
    expect(new URL(page.url()).pathname).toBe("/wp-login.php");

    await page.fill("#user_login", ADMIN_USER);
    await page.fill("#user_pass", ADMIN_PASS);
    await page.click("#wp-submit");
    await expect(page).toHaveURL(/wp-admin/);
    await expect(page.locator("#wpadminbar")).toBeVisible();
  });

  test("public pages, REST, cron and AJAX keep working @smoke", async ({ request }) => {
    expect((await request.get("/")).status()).toBe(200);
    expect((await request.get("/wp-json/")).status()).toBe(200);
    expect((await request.get("/wp-cron.php")).status()).toBe(200);

    const heartbeat = await request.post("/wp-admin/admin-ajax.php", { form: { action: "heartbeat", _nonce: "x" } });
    expect(heartbeat.status(), "admin-ajax.php must not 404 for visitors").not.toBe(404);
  });

  test("a public page whose slug starts with wp-admin is not treated as the admin area", async ({ request }) => {
    wp("post", "create", "--post_type=page", "--post_status=publish", "--post_title=Guide to wp-admin", "--post_name=wp-admin-guide");
    const res = await request.get("/wp-admin-guide/");
    expect(res.status()).toBe(200);
    expect(await res.text()).toContain("Guide to wp-admin");
  });

  test("a front-end form posting to admin-post.php still reaches its handler", async ({ request }) => {
    const res = await request.post("/wp-admin/admin-post.php", { form: { action: "e2e_public_form" } });
    expect(res.status()).toBe(200);
    expect(await res.text()).toContain("e2e-public-form-ok");
  });
});

test.describe("Admin hiding: signed-in administrator", () => {
  test.use(visitor(12));

  test.beforeEach(async ({ page }) => {
    // A login costs two login-page requests, and the limit is 15 per minute per IP.
    resetLoginState();
    await loginThroughHiddenPath(page);
  });

  test("REST with cookie authentication works @smoke", async ({ page }) => {
    await page.goto("/wp-admin/");
    await page.waitForFunction(() => Boolean((window as any).wpApiSettings?.nonce));
    const me = await page.evaluate(async () => {
      const settings = (window as any).wpApiSettings;
      const res = await fetch(`${settings.root}wp/v2/users/me`, { headers: { "X-WP-Nonce": settings.nonce }, credentials: "same-origin" });
      return { status: res.status, body: await res.json() };
    });
    expect(me.status).toBe(200);
    expect(me.body.slug).toBe(ADMIN_USER);
  });

  test("admin-ajax.php answers a logged-in request", async ({ page }) => {
    const res = await page.request.post("/wp-admin/admin-ajax.php", { form: { action: "generate-password" } });
    expect(res.status()).toBe(200);
    expect((await res.text()).length, "logged-in AJAX returns the generated password").toBeGreaterThan(8);
  });

  test("update screens and the update AJAX endpoint are reachable", async ({ page }) => {
    for (const path of ["/wp-admin/plugins.php", "/wp-admin/themes.php", "/wp-admin/update-core.php"]) {
      const res = await page.goto(path);
      expect(res?.status(), path).toBe(200);
      await expect(page.locator("#wpadminbar"), path).toBeVisible();
    }

    // Without a nonce WordPress itself refuses; what matters is that it is WordPress answering.
    const update = await page.request.post("/wp-admin/admin-ajax.php", { form: { action: "update-plugin", plugin: "hello.php", slug: "hello" } });
    expect(update.status()).not.toBe(404);
    expect(await update.text()).toMatch(/success|error|-1|nonce|invalid/i);
  });

  test("logging out lands on the login form, and the session is gone", async ({ page }) => {
    await page.goto("/wp-login.php?action=logout");
    await page.getByRole("link", { name: /log out/i }).click();
    await expect(page.locator("#loginform")).toBeVisible();
    expect(new URL(page.url()).searchParams.get("loggedout")).toBe("true");

    await page.goto("/wp-admin/");
    await expect(page.locator("#loginform")).toBeVisible();
    expect(page.url()).toContain("wp-login.php");
  });

  test("the hidden path sends an already signed-in administrator to the dashboard", async ({ page }) => {
    await page.goto(`/${HIDDEN_PATH}`);
    await expect(page).toHaveURL(/wp-admin/);
  });
});
