import { expect, test, type APIRequestContext } from "@playwright/test";
import { ageUserSession, resetLoginState, wp } from "../utils/wp-cli";
import {
  ADMIN_PASS,
  ADMIN_USER,
  BROWSER_UA,
  MEMBER_PASS,
  MEMBER_USER,
  TOKEN_QUERY,
  loginThroughHiddenPath,
  submitLogin,
  visitor,
} from "./support";

/**
 * Thresholds documented in the README ("Login protection behind a shared IP"), with defaults:
 * 5 failed logins lock an IP for 15 minutes (900 s); the 16th login-page request within a
 * minute from one IP is answered with 404. Every limit is per IP, so people behind one
 * address (office, VPN) share it.
 */

interface Attempt {
  status: number;
  location: string;
  html: string;
}

/** POST the login form the way a browser does and return what came back, without following redirects. */
async function attempt(request: APIRequestContext, user: string, pass: string, ip?: string): Promise<Attempt> {
  const res = await request.post(`/wp-login.php?${TOKEN_QUERY}`, {
    form: { log: user, pwd: pass, "wp-submit": "Log In", redirect_to: "/wp-admin/" },
    maxRedirects: 0,
    // Fresh connection each time: the specs below pause for seconds, long enough for the server to drop an idle one.
    headers: { Connection: "close", ...(ip ? { "X-Forwarded-For": ip } : {}) },
  });
  return { status: res.status(), location: res.headers()["location"] ?? "", html: await res.text() };
}

const succeeded = (a: Attempt) => a.status === 302 && /wp-admin/.test(a.location);

test.describe("Login protection: messages", () => {
  test.use(visitor(21));
  test.beforeEach(() => resetLoginState());

  test("wrong credentials show one generic message, for real and unknown users alike @smoke", async ({ page }) => {
    await submitLogin(page, ADMIN_USER, "definitely-wrong");
    const realUser = (await page.locator("#login_error").innerText()).trim();

    await submitLogin(page, "no_such_user_at_all", "definitely-wrong");
    const unknownUser = (await page.locator("#login_error").innerText()).trim();

    expect(realUser).toMatch(/invalid login credentials/i);
    expect(unknownUser).toBe(realUser);
    expect(realUser).not.toContain(ADMIN_USER);
  });

  test("the login form offers no Remember Me, and the session cookie follows the session timeout @smoke", async ({ page, context }) => {
    await page.goto(`/wp-login.php?${TOKEN_QUERY}`);
    await expect(page.locator(".forgetmenot")).toBeHidden();

    // Even a request that insists on "remember me" gets the configured 30 minutes, not 14 days.
    const res = await page.request.post(`/wp-login.php?${TOKEN_QUERY}`, {
      form: { log: ADMIN_USER, pwd: ADMIN_PASS, rememberme: "forever", "wp-submit": "Log In" },
      maxRedirects: 0,
    });
    expect(res.status()).toBe(302);

    const cookie = (await context.cookies()).find((c) => c.name.startsWith("wordpress_logged_in_"));
    expect(cookie, "the logged-in cookie").toBeTruthy();
    // The cookie value is "user|expiration|token|hmac". The browser cookie itself lives 12 hours
    // longer (core adds that margin), so the session length is the embedded expiration.
    const expiration = Number(decodeURIComponent(cookie!.value).split("|")[1]);
    const lifetime = expiration - Date.now() / 1000;
    expect(lifetime).toBeGreaterThan(29 * 60);
    expect(lifetime).toBeLessThan(31 * 60);
  });
});

test.describe("Login protection: lockout", () => {
  test.use(visitor(22));
  test.beforeEach(() => {
    resetLoginState();
    wp("option", "update", "silver_assist_lockout_duration", "900");
  });
  test.afterAll(() => wp("option", "update", "silver_assist_lockout_duration", "900"));

  test("five failed logins lock the IP out, even for the right password @smoke", async ({ request }) => {
    for (let i = 1; i <= 4; i++) {
      const a = await attempt(request, ADMIN_USER, `wrong-${i}`);
      expect(a.html, `attempt ${i}`).toMatch(/invalid login credentials/i);
    }
    const fifth = await attempt(request, ADMIN_USER, "wrong-5");
    expect(fifth.html).toMatch(/invalid login credentials/i);

    const locked = await attempt(request, ADMIN_USER, ADMIN_PASS);
    expect(succeeded(locked), "the correct password is refused while locked out").toBe(false);
    // The notice says why and for how long, instead of "Invalid login credentials".
    expect(locked.html).toMatch(/too many failed login attempts/i);
    expect(locked.html).not.toMatch(/invalid login credentials/i);
  });

  test("a successful login before the limit resets the count", async ({ request }) => {
    for (let i = 0; i < 4; i++) await attempt(request, ADMIN_USER, "wrong");
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS))).toBe(true);

    for (let i = 0; i < 4; i++) await attempt(request, ADMIN_USER, "wrong");
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS)), "four more failures are still below the limit").toBe(true);
  });

  test("the lockout ends on time even when the locked-out person keeps trying", async ({ request }) => {
    test.setTimeout(120_000);
    wp("option", "update", "silver_assist_lockout_duration", "12");

    for (let i = 0; i < 5; i++) await attempt(request, ADMIN_USER, "wrong");
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS))).toBe(false);

    // Retries while locked out must not push the unlock time back.
    await new Promise((r) => setTimeout(r, 5_000));
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS))).toBe(false);

    await new Promise((r) => setTimeout(r, 8_000));
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS)), "unlocked after the configured duration").toBe(true);
  });
});

test.describe("Login protection: shared IP", () => {
  test.use(visitor(23));
  test.beforeEach(() => resetLoginState());

  test("colleagues behind one IP share the failed-login budget, other IPs are unaffected", async ({ request }) => {
    // Two colleagues mistype: three and two failures from the same address.
    for (let i = 0; i < 3; i++) await attempt(request, ADMIN_USER, "typo");
    for (let i = 0; i < 2; i++) await attempt(request, MEMBER_USER, "typo");

    // The address is now locked for both, whatever the password.
    expect(succeeded(await attempt(request, MEMBER_USER, MEMBER_PASS))).toBe(false);
    expect(succeeded(await attempt(request, ADMIN_USER, ADMIN_PASS))).toBe(false);

    // Someone on another address logs in normally.
    expect(succeeded(await attempt(request, MEMBER_USER, MEMBER_PASS, "203.0.113.99"))).toBe(true);
  });

  test("the login page answers 404 from the 16th request in a minute, per IP", async ({ playwright }) => {
    const origin = process.env.WP_BASE_URL ?? "http://localhost:8890";
    const noisy = await playwright.request.newContext({ baseURL: origin, userAgent: BROWSER_UA, extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.31" } });
    const quiet = await playwright.request.newContext({ baseURL: origin, userAgent: BROWSER_UA, extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.32" } });

    for (let i = 1; i <= 15; i++) {
      expect((await noisy.get(`/wp-login.php?${TOKEN_QUERY}`)).status(), `request ${i}`).toBe(200);
    }
    expect((await noisy.get(`/wp-login.php?${TOKEN_QUERY}`)).status(), "the 16th request in a minute").toBe(404);

    // Another IP is not affected.
    expect((await quiet.get(`/wp-login.php?${TOKEN_QUERY}`)).status()).toBe(200);

    await noisy.dispose();
    await quiet.dispose();
  });
});

test.describe("Login protection: session timeout", () => {
  test.use(visitor(24));
  test.beforeEach(() => resetLoginState());

  test("an idle session ends with a login screen, not a 404, even without the admin access cookie @smoke", async ({ page, context }) => {
    await loginThroughHiddenPath(page, MEMBER_USER, MEMBER_PASS);
    const userId = wp("user", "get", MEMBER_USER, "--field=ID");

    // Idle for 31 minutes (limit 30), and the one-hour admin access cookie is gone.
    ageUserSession(userId, 31 * 60);
    const cookies = await context.cookies();
    await context.clearCookies();
    await context.addCookies(cookies.filter((c) => !c.name.startsWith("silver_admin_session_")));

    await page.goto("/wp-admin/");
    await expect(page.locator("#loginform")).toBeVisible();
    expect(page.url()).toContain("session_expired=1");

    // And the session really ended: the dashboard is not reachable any more.
    await page.goto("/wp-admin/");
    await expect(page.locator("#wpadminbar")).toHaveCount(0);
  });

  test("an active session is not logged out", async ({ page }) => {
    await loginThroughHiddenPath(page, MEMBER_USER, MEMBER_PASS);
    const userId = wp("user", "get", MEMBER_USER, "--field=ID");

    ageUserSession(userId, 5 * 60);
    await page.goto("/wp-admin/");
    await expect(page.locator("#wpadminbar")).toBeVisible();
  });
});
