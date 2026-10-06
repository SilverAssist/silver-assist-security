import { defineConfig, devices } from "@playwright/test";

/**
 * E2E tests with admin hiding enabled (`silver_assist_admin_hide_enabled`), same wp-env instance.
 *
 * The global setup turns the option on and the teardown restores it, so the default suite
 * (playwright.config.ts) keeps running against a site with the standard login URLs.
 * Run: npm run test:e2e:admin-hide (smoke subset: npm run test:e2e:admin-hide:smoke).
 *
 * Specs isolate themselves with a unique X-Forwarded-For per describe block. wp-env serves PHP
 * from a private Docker address, which the plugin trusts as a proxy, so each block is a
 * different visitor for the per-IP login limits.
 */
export default defineConfig({
  testDir: "./tests/e2e/admin-hide",
  timeout: 90_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  globalSetup: "./tests/e2e/admin-hide/global-setup.ts",
  globalTeardown: "./tests/e2e/admin-hide/global-teardown.ts",
  reporter: process.env.CI ? [["github"], ["html", { open: "never", outputFolder: "playwright-report-admin-hide" }]] : "list",
  use: {
    baseURL: process.env.WP_BASE_URL ?? "http://localhost:8890",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "admin-hide", use: { ...devices["Desktop Chrome"] } }],
});
