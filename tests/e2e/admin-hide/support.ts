import { expect, type Page } from "@playwright/test";

/** Custom admin path configured by global-setup. */
export const HIDDEN_PATH = "silver-admin";
/** The query parameter admin hiding uses to let a request reach wp-login.php. */
export const TOKEN_QUERY = `silver_auth=${HIDDEN_PATH}`;

export const ADMIN_USER = process.env.WP_ADMIN_USER ?? "admin";
export const ADMIN_PASS = process.env.WP_ADMIN_PASS ?? "password";

/** A role-less test account created by global-setup (password meets the strength rules). */
export const MEMBER_USER = "e2e_hidden_member";
export const MEMBER_PASS = "Member-Pass-123!";

/** Chrome-like user agent: the login screen treats unknown or tool-like agents as bots. */
export const BROWSER_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

/**
 * Settings for a describe block: its own visitor identity.
 *
 * The per-IP limits (failed logins, login page requests per minute) key on the client IP,
 * which behind wp-env's private Docker address is the last X-Forwarded-For entry. Giving
 * every block its own address keeps blocks from locking each other out.
 */
export function visitor(lastOctet: number) {
  return {
    storageState: { cookies: [], origins: [] },
    userAgent: BROWSER_UA,
    extraHTTPHeaders: { "X-Forwarded-For": `203.0.113.${lastOctet}` },
  };
}

/** Open the login form the way a person with the secret URL does: through /silver-admin. */
export async function openHiddenLogin(page: Page): Promise<void> {
  await page.goto(`/${HIDDEN_PATH}`);
  await expect(page.locator("#loginform")).toBeVisible();
}

/** Log in through /silver-admin and land on the dashboard. */
export async function loginThroughHiddenPath(page: Page, user = ADMIN_USER, pass = ADMIN_PASS): Promise<void> {
  await openHiddenLogin(page);
  await page.fill("#user_login", user);
  await page.fill("#user_pass", pass);
  await page.click("#wp-submit");
  await expect(page).toHaveURL(/wp-admin/);
}

/** Submit wrong or right credentials through the form and return without asserting the outcome. */
export async function submitLogin(page: Page, user: string, pass: string): Promise<void> {
  await page.goto(`/wp-login.php?${TOKEN_QUERY}`);
  await page.fill("#user_login", user);
  await page.fill("#user_pass", pass);
  await page.click("#wp-submit");
  await page.waitForLoadState("domcontentloaded");
}
