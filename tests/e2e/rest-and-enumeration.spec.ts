import { expect, test } from "@playwright/test";
import { apiFetch, EDITOR_STATE } from "./utils/wp";

test.describe("REST hardening vs. editor needs", () => {
  const anonymous = { storageState: { cookies: [], origins: [] } };
  test.describe("anonymous", () => {
  test.use(anonymous);
  test("anonymous visitors cannot enumerate users @smoke", async ({ request }) => {
    const res = await request.get("/wp-json/wp/v2/users");
    expect([401, 403, 404]).toContain(res.status());

    const byId = await request.get("/wp-json/wp/v2/users/1");
    expect([401, 403, 404]).toContain(byId.status());
  });

  test("?author=1 does not reveal the author archive @smoke", async ({ request }) => {
    const res = await request.get("/?author=1", { maxRedirects: 0 });
    expect([301, 302]).toContain(res.status());
    expect(res.headers()["location"] ?? "").not.toMatch(/author/);
  });

  test("anonymous oEmbed provider route is hidden", async ({ request }) => {
    const res = await request.get("/wp-json/oembed/1.0/embed?url=http://localhost:8890/");
    expect(res.status()).toBe(404);
  });

  });

  test.describe("editor role", () => {
  test.use({ storageState: EDITOR_STATE });

  test("editor can load users and use the oEmbed proxy @smoke", async ({ page }) => {
    await page.goto("/wp-admin/");
    expect(await page.locator("#wp-admin-bar-my-account").textContent()).toContain("e2e_editor");
    await page.goto("/wp-admin/post-new.php");
    await page.waitForFunction(() => Boolean((window as any).wp?.apiFetch));

    const users = await apiFetch(page, "/wp/v2/users?who=authors");
    expect(users.ok, JSON.stringify(users)).toBe(true);

    const proxy = await apiFetch(page, "/oembed/1.0/proxy?url=https%3A%2F%2Fexample.com%2F");
    expect(proxy.code, "route must exist").not.toBe("rest_no_route");
  });
  });
});
