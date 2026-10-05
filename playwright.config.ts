import { defineConfig, devices } from "@playwright/test";

/**
 * E2E tests run the real plugin inside @wordpress/env (npm run wp-env:start).
 * Smoke subset: npm run test:e2e:smoke
 */
export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  globalSetup: "./tests/e2e/global-setup.ts",
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.WP_BASE_URL ?? "http://localhost:8890",
    storageState: "tests/e2e/.auth/admin.json",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
