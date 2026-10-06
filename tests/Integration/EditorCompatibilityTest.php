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
     * Routes the editor calls on load and while editing, with the role that calls them
     *
     * @return array<string, array{string, string}>
     */
    public static function editor_routes(): array
    {
        return [
            "types"        => ["/wp/v2/types", "editor"],
            "taxonomies"   => ["/wp/v2/taxonomies", "editor"],
            "settings"     => ["/wp/v2/settings", "administrator"],
            "media"        => ["/wp/v2/media", "editor"],
            "block types"  => ["/wp/v2/block-types", "editor"],
            "oembed proxy" => ["/oembed/1.0/proxy", "editor"],
        ];
    }

    /**
     * The editor gets a real answer from every route the block editor needs
     *
     * A request, not a look at the route table: a route that exists but refuses
     * the editor would break the editor just the same. The proxy is called
     * without a url, so it answers 400 (missing parameter); what matters is that
     * it is neither missing (404 rest_no_route) nor forbidden.
     *
     * @dataProvider editor_routes
     * @param string $route REST route.
     * @param string $role  Role that uses the route in the editor.
     * @return void
     */
    public function test_editor_has_required_route(string $route, string $role): void
    {
        wp_set_current_user(self::factory()->user->create(["role" => $role]));
        $GLOBALS["wp_rest_server"] = null;

        $response = rest_do_request(new \WP_REST_Request("GET", $route));
        $data     = $response->get_data();
        $code     = is_array($data) && isset($data["code"]) ? $data["code"] : "";

        $this->assertNotSame("rest_no_route", $code, "$route must exist for the $role.");
        $this->assertNotContains($response->get_status(), [401, 403], "$route must not refuse the $role.");
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

        $request = new \WP_REST_Request("GET", "/oembed/1.0/embed");
        $request->set_param("url", home_url("/"));
        $response = rest_do_request($request);

        $this->assertSame(404, $response->get_status());
        $this->assertSame("rest_no_route", $response->get_data()["code"]);
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
