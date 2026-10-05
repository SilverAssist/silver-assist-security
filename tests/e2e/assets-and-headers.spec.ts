import { expect, test } from "@playwright/test";

test.describe("Asset versioning and hardening", () => {
  test.describe("anonymous front end", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  test("front end hides plugin asset versions but keeps core versions", async ({ request }) => {
    const html = await (await request.get("/")).text();

    // Assets enqueued by tests/e2e/mu-plugins/e2e-assets.php with version 9.9.9.
    const style = html.match(/<link[^>]+id=['"]e2e-known-style-css['"][^>]*href=['"]([^'"]+)['"]/)?.[1]
      ?? html.match(/<link[^>]+href=['"]([^'"]+e2e-assets\.css[^'"]*)['"]/)?.[1];
    const script = html.match(/<script[^>]+src=['"]([^'"]+e2e-assets\.js[^'"]*)['"]/)?.[1];
    expect(style, "known plugin stylesheet must be on the page").toBeTruthy();
    expect(script, "known plugin script must be on the page").toBeTruthy();
    expect(style).not.toMatch(/[?&]ver=/);
    expect(script).not.toMatch(/[?&]ver=/);

    const coreJs = [...html.matchAll(/<script[^>]+src=['"]([^'"]*\/wp-includes\/[^'"]+)['"]/g)].map((m) => m[1]);
    expect(coreJs.length, "expected the front end to load at least one core script").toBeGreaterThan(0);
    for (const src of coreJs) expect(src, src).toMatch(/[?&]ver=/);
  });

  test("front end does not print the generator tag or WP version @smoke", async ({ request }) => {
    const html = await (await request.get("/")).text();
    expect(html).not.toMatch(/<meta name=["']generator["']/i);
  });

  test("security headers are present @smoke", async ({ request }) => {
    const res = await request.get("/");
    const h = res.headers();
    expect(h["x-content-type-options"]).toBe("nosniff");
    expect(h["x-frame-options"]).toBe("SAMEORIGIN");
  });

  });

  test("wp-admin core scripts load without 404s", async ({ page }) => {
    const failed: string[] = [];
    page.on("response", (res) => {
      if (res.status() >= 400 && /\/wp-(includes|admin)\//.test(res.url())) failed.push(`${res.status()} ${res.url()}`);
    });
    await page.goto("/wp-admin/edit.php");
    expect(failed, failed.join("\n")).toEqual([]);
  });
});
