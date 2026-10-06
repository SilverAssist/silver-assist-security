import { chromium, type Browser, type FullConfig } from "@playwright/test";
import { ADMIN_PASS, ADMIN_STATE, ADMIN_USER, EDITOR_PASS, EDITOR_STATE, EDITOR_USER } from "./utils/wp";

async function loginAndSave(browser: Browser, baseURL: string, user: string, pass: string, path: string): Promise<void> {
  const context = await browser.newContext({ baseURL });
  const page = await context.newPage();
  await page.goto("/wp-login.php");
  await page.fill("#user_login", user);
  await page.fill("#user_pass", pass);
  await page.click("#wp-submit");
  await page.waitForURL(/wp-admin/);
  await context.storageState({ path });
  await context.close();
}

/**
 * Log in once per role and reuse the sessions. The plugin treats more than 15
 * login-page hits per minute from one IP as bot traffic (404), so per-test logins
 * would trip its own hardening. The editor account lets specs verify role-specific
 * behavior instead of relying on administrator-only access.
 */
export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL = config.projects[0].use.baseURL as string;
  const browser = await chromium.launch();

  await loginAndSave(browser, baseURL, ADMIN_USER, ADMIN_PASS, ADMIN_STATE);

  // Create the editor through the REST API as the administrator (idempotent).
  const adminContext = await browser.newContext({ baseURL, storageState: ADMIN_STATE });
  const page = await adminContext.newPage();
  await page.goto("/wp-admin/");
  const nonce = await page.evaluate(() => (window as any).wpApiSettings?.nonce as string);
  const created = await adminContext.request.post("/wp-json/wp/v2/users", {
    headers: { "X-WP-Nonce": nonce },
    data: { username: EDITOR_USER, email: `${EDITOR_USER}@example.test`, password: EDITOR_PASS, roles: ["editor"] },
  });
  // An existing editor answers 500 or 400 (existing_user_login); a password that breaks the
  // plugin's policy answers 400 weak_password and must fail the setup, not be mistaken for it.
  const body = created.ok() ? "" : await created.text();
  if (!created.ok() && (body.includes("weak_password") || (created.status() !== 500 && created.status() !== 400))) {
    throw new Error(`Could not create the E2E editor: ${created.status()} ${body}`);
  }
  await adminContext.close();

  await loginAndSave(browser, baseURL, EDITOR_USER, EDITOR_PASS, EDITOR_STATE);
  await browser.close();
}
