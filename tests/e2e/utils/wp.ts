import { expect, type Page } from "@playwright/test";

export const ADMIN_USER = process.env.WP_ADMIN_USER ?? "admin";
export const ADMIN_PASS = process.env.WP_ADMIN_PASS ?? "password";
export const EDITOR_USER = "e2e_editor";
export const EDITOR_PASS = process.env.WP_EDITOR_PASS ?? "E2e-Editor-Passw0rd!";
export const ADMIN_STATE = "tests/e2e/.auth/admin.json";
export const EDITOR_STATE = "tests/e2e/.auth/editor.json";

/** Log in through the standard login form (admin hiding is off by default). */
export async function login(page: Page): Promise<void> {
  await page.goto("/wp-login.php");
  await page.fill("#user_login", ADMIN_USER);
  await page.fill("#user_pass", ADMIN_PASS);
  await page.click("#wp-submit");
  await expect(page).toHaveURL(/wp-admin/);
}

/**
 * Collect JS errors for the lifetime of a page. Third-party resource failures
 * (fonts, gravatar) are not plugin regressions, so they are ignored.
 */
export function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    const text = msg.text();
    if (/Failed to load resource/.test(text) && !text.includes("localhost")) return;
    errors.push(`console.error: ${text}`);
  });
  return errors;
}

/** Call a REST route from inside the editor, the way Gutenberg does. */
export async function apiFetch<T = unknown>(
  page: Page,
  path: string,
): Promise<{ ok: boolean; status?: number; code?: string; data?: T }> {
  return page.evaluate(async (p) => {
    try {
      // @ts-expect-error wp is a browser global provided by WordPress
      const data = await window.wp.apiFetch({ path: p });
      return { ok: true, data };
    } catch (e: any) {
      return { ok: false, code: e?.code, status: e?.data?.status };
    }
  }, path);
}

/** Dismiss the block editor welcome guide when it appears. */
export async function closeWelcomeGuide(page: Page): Promise<void> {
  await page.evaluate(() => {
    // @ts-expect-error wp is a browser global provided by WordPress
    window.wp.data.dispatch("core/preferences").set("core/edit-post", "welcomeGuide", false);
    // @ts-expect-error wp is a browser global provided by WordPress
    window.wp.data.dispatch("core/preferences").set("core/edit-post", "fullscreenMode", false);
  });
}
