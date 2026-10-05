<?php
/**
 * Block Editor Compatibility Tests
 *
 * The plugin hardens many core behaviors. These tests assert that the REST
 * routes the block editor depends on keep working for an editing user, while
 * anonymous exposure stays closed (WEB-1222).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.3
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test REST routes required by the block editor with security hooks active
 */
class EditorCompatibilityTest extends WP_UnitTestCase
{
    /**
     * Activate the hardening hooks the way a real request would
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $general = new GeneralSecurity();
        $general->remove_unnecessary_headers();
        $general->disable_user_enumeration();
        $GLOBALS["wp_rest_server"] = null;
        do_action("rest_api_init", rest_get_server());
    }

    /**
     * Reset REST server and user
     *
     * @return void
     */
    protected function tearDown(): void
    {
        $GLOBALS["wp_rest_server"] = null;
        wp_set_current_user(0);
        parent::tearDown();
    }

    /**
     * Routes the editor calls on load and while editing
     *
     * @return array<string, array{string}>
     */
    public static function editor_routes(): array
    {
        return [
            "types"       => ["/wp/v2/types"],
            "taxonomies"  => ["/wp/v2/taxonomies"],
            "settings"    => ["/wp/v2/settings"],
            "media"       => ["/wp/v2/media"],
            "block types" => ["/wp/v2/block-types"],
            "oembed proxy" => ["/oembed/1.0/proxy"],
        ];
    }

    /**
     * An editor sees every route the block editor needs
     *
     * @dataProvider editor_routes
     * @param string $route REST route.
     * @return void
     */
    public function test_editor_has_required_route(string $route): void
    {
        wp_set_current_user(self::factory()->user->create(["role" => "editor"]));
        $GLOBALS["wp_rest_server"] = null;

        $this->assertArrayHasKey($route, rest_get_server()->get_routes());
    }

    /**
     * The anonymous oEmbed provider route stays hidden (author disclosure)
     *
     * @return void
     */
    public function test_anonymous_oembed_provider_route_is_hidden(): void
    {
        wp_set_current_user(0);
        $GLOBALS["wp_rest_server"] = null;

        $this->assertArrayNotHasKey("/oembed/1.0/embed", rest_get_server()->get_routes());
    }

    /**
     * Author links never disclose a user archive URL
     *
     * @return void
     */
    public function test_author_link_does_not_disclose_user_archive(): void
    {
        $user_id = self::factory()->user->create(["role" => "author"]);

        $this->assertSame(home_url(), get_author_posts_url($user_id));
    }

    /**
     * The WordPress generator tag stays removed from the front end
     *
     * @return void
     */
    public function test_generator_tag_is_not_printed(): void
    {
        ob_start();
        do_action("wp_head");
        $head = ob_get_clean();

        $this->assertStringNotContainsString('name="generator"', $head);
    }
}
