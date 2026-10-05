import { expect, test } from "@playwright/test";

test.describe("Asset versioning and hardening", () => {
  test.describe("anonymous front end", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  test("front end hides theme asset versions but keeps core versions", async ({ request }) => {
    const html = await (await request.get("/")).text();

    const themeCss = [...html.matchAll(/<link[^>]+href=['"]([^'"]*\/themes\/[^'"]+\.css[^'"]*)['"]/g)].map((m) => m[1]);
    for (const href of themeCss) expect(href, href).not.toMatch(/[?&]ver=/);

    const coreJs = [...html.matchAll(/<script[^>]+src=['"]([^'"]*\/wp-includes\/[^'"]+)['"]/g)].map((m) => m[1]);
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
