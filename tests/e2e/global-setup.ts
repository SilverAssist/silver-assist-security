import { chromium, type FullConfig } from "@playwright/test";
import { ADMIN_PASS, ADMIN_USER } from "./utils/wp";

/**
 * Log in once and reuse the session. The plugin treats more than 15 login-page
 * hits per minute from one IP as bot traffic (404), so per-test logins would
 * trip its own hardening.
 */
export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL = config.projects[0].use.baseURL as string;
  const browser = await chromium.launch();
  const page = await browser.newPage({ baseURL });
  await page.goto("/wp-login.php");
  await page.fill("#user_login", ADMIN_USER);
  await page.fill("#user_pass", ADMIN_PASS);
  await page.click("#wp-submit");
  await page.waitForURL(/wp-admin/);
  await page.context().storageState({ path: "tests/e2e/.auth/admin.json" });
  await browser.close();
}
