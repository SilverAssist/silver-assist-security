<?php
/**
 * Asset Versioning Behavior Tests
 *
 * Verifies that the "remove ?ver=" hardening never touches assets where the
 * cache-buster is required for correctness (wp-admin, block editor, core dist
 * bundles), which caused stale data.min.js / editor.min.js pairs (WEB-1222).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.3
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test asset version query string handling per request context
 */
class AssetVersioningTest extends WP_UnitTestCase
{
    /**
     * Set up: register the GeneralSecurity filters for this test
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        // Other tests define DOING_AJAX globally; pin the context for isolation.
        add_filter("wp_doing_ajax", "__return_false");
        new GeneralSecurity();
    }

    /**
     * Reset screen context
     *
     * @return void
     */
    protected function tearDown(): void
    {
        unset($GLOBALS["current_screen"]);
        parent::tearDown();
    }

    /**
     * Front end still hides the version of theme and plugin assets
     *
     * @return void
     */
    public function test_front_end_theme_asset_version_is_removed(): void
    {
        $src = content_url("/themes/mytheme/style.css?ver=1.2.3");

        $this->assertSame(
            content_url("/themes/mytheme/style.css"),
            apply_filters("style_loader_src", $src, "mytheme-style")
        );
    }

    /**
     * Core dist bundles keep ver= on the front end
     *
     * @return void
     */
    public function test_core_dist_asset_keeps_version_on_front_end(): void
    {
        $src = includes_url("js/dist/data.min.js?ver=abc123");

        $this->assertSame($src, apply_filters("script_loader_src", $src, "wp-data"));
    }

    /**
     * Block editor bundles keep ver= in wp-admin (the WEB-1222 case)
     *
     * @return void
     */
    public function test_editor_bundles_keep_version_in_admin(): void
    {
        set_current_screen("post");

        foreach (["editor", "data", "block-editor", "element"] as $name) {
            $src = includes_url("js/dist/{$name}.min.js?ver=deadbeef");
            $this->assertSame(
                $src,
                apply_filters("script_loader_src", $src, "wp-{$name}"),
                "wp-{$name} must keep its cache-buster in admin"
            );
        }
    }

    /**
     * Plugin and theme assets keep ver= inside wp-admin
     *
     * @return void
     */
    public function test_third_party_admin_asset_keeps_version(): void
    {
        set_current_screen("dashboard");
        $src = plugins_url("someplugin/admin.js?ver=9.9");

        $this->assertSame($src, apply_filters("script_loader_src", $src, "someplugin-admin"));
    }

    /**
     * Admin AJAX requests keep ver=
     *
     * @return void
     */
    public function test_version_kept_during_ajax(): void
    {
        add_filter("wp_doing_ajax", "__return_true");
        $src = plugins_url("someplugin/app.js?ver=2.0");

        $this->assertSame($src, apply_filters("script_loader_src", $src, "someplugin-app"));
    }

    /**
     * Sites can opt an asset out through the filter
     *
     * @return void
     */
    public function test_filter_can_keep_version(): void
    {
        add_filter("silver_assist_security_strip_asset_version", "__return_false");
        $src = content_url("/themes/mytheme/style.css?ver=1.2.3");

        $this->assertSame($src, apply_filters("style_loader_src", $src, "mytheme-style"));
    }

    /**
     * Other query args survive when ver= is removed
     *
     * @return void
     */
    public function test_other_query_args_preserved(): void
    {
        $src = content_url("/themes/mytheme/app.js?foo=bar&ver=1.0&baz=1");
        $filtered = apply_filters("script_loader_src", $src, "mytheme-app");

        $this->assertStringNotContainsString("ver=1.0", $filtered);
        $this->assertStringContainsString("foo=bar", $filtered);
        $this->assertStringContainsString("baz=1", $filtered);
    }
}
