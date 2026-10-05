import { expect, test } from "@playwright/test";
import { closeWelcomeGuide, collectErrors } from "./utils/wp";

test.describe("Block editor with Silver Assist Security active", () => {
  test("admin creates, saves and publishes a post without JS errors @smoke", async ({ page }) => {
    const errors = collectErrors(page);

    await page.goto("/wp-admin/post-new.php");
    await page.waitForFunction(() => Boolean((window as any).wp?.data?.select("core/editor")));
    await closeWelcomeGuide(page);

    const title = `E2E post ${Date.now()}`;
    // The post canvas lives in an iframe in current WordPress versions.
    await page.frameLocator('iframe[name="editor-canvas"]').getByRole("textbox", { name: /add title/i }).fill(title);

    await page.getByRole("button", { name: /save draft/i }).click();
    await expect(page.getByText(/^saved$/i).first()).toBeVisible();

    await page.getByRole("button", { name: "Publish", exact: true }).first().click();
    await page.getByRole("region", { name: /editor publish/i }).getByRole("button", { name: "Publish", exact: true }).click();
    await expect(page.getByText(/is now live|published/i).first()).toBeVisible();

    expect(errors, errors.join("\n")).toEqual([]);
  });

  test("editor bundles keep their cache-buster in wp-admin @smoke", async ({ page }) => {
    const bundles: string[] = [];
    page.on("request", (req) => {
      if (/\/wp-includes\/js\/dist\/(data|editor)(\.min)?\.js/.test(req.url())) bundles.push(req.url());
    });
    await page.goto("/wp-admin/post-new.php");
    await page.waitForFunction(() => Boolean((window as any).wp?.data));

    expect(bundles.length).toBeGreaterThan(0);
    for (const url of bundles) expect(url, url).toMatch(/[?&]ver=/);
  });
  test("Embed block can be inserted and resolves through the oEmbed proxy @smoke", async ({ page }) => {
    const errors = collectErrors(page);
    const proxyCalls: string[] = [];
    page.on("response", async (res) => {
      if (!/oembed(\/|%2F)1\.0(\/|%2F)proxy/.test(res.url())) return;
      const body = await res.json().catch(() => ({}));
      proxyCalls.push(String(body?.code ?? "ok"));
    });

    await page.goto("/wp-admin/post-new.php");
    await page.waitForFunction(() => Boolean((window as any).wp?.data?.select("core/block-editor")));
    await closeWelcomeGuide(page);

    await page.evaluate(() => {
      const { createBlock } = (window as any).wp.blocks;
      (window as any).wp.data
        .dispatch("core/block-editor")
        .insertBlocks(createBlock("core/embed", { url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ" }));
    });

    const names = await page.evaluate(() =>
      (window as any).wp.data.select("core/block-editor").getBlocks().map((b: any) => b.name)
    );
    expect(names).toContain("core/embed");

    // The block asks the proxy for the embed. Without network the provider lookup may fail
    // (oembed_invalid_url), but the route itself must exist for an editor (rest_no_route was WEB-1222).
    await expect.poll(() => proxyCalls.length, { timeout: 15000 }).toBeGreaterThan(0);
    expect(proxyCalls, "proxy route must exist").not.toContain("rest_no_route");
    expect(errors, errors.join("\n")).toEqual([]);
  });
});
