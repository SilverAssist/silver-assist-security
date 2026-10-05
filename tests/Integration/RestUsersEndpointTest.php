<?php
/**
 * REST Users Endpoint Behavior Tests
 *
 * Anonymous visitors must not be able to enumerate users, while logged-in
 * editors still need /wp/v2/users for the block editor (WEB-1222).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.3
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test /wp/v2/users availability per user role
 */
class RestUsersEndpointTest extends WP_UnitTestCase
{
    /**
     * Register hooks and rebuild the REST server for each test
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        (new GeneralSecurity())->disable_user_enumeration();
    }

    /**
     * Drop the cached REST server so route filters re-run
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
     * Get registered REST routes for the current user
     *
     * @return array<string, mixed>
     */
    private function routes(): array
    {
        $GLOBALS["wp_rest_server"] = null;
        return rest_get_server()->get_routes();
    }

    /**
     * Anonymous visitors cannot see the users routes
     *
     * @return void
     */
    public function test_anonymous_cannot_enumerate_users(): void
    {
        wp_set_current_user(0);
        $routes = $this->routes();

        $this->assertArrayNotHasKey("/wp/v2/users", $routes);
        $this->assertArrayNotHasKey("/wp/v2/users/(?P<id>[\\d]+)", $routes);
    }

    /**
     * Subscribers (no editing capability) cannot see the users routes
     *
     * @return void
     */
    public function test_subscriber_cannot_enumerate_users(): void
    {
        wp_set_current_user(self::factory()->user->create(["role" => "subscriber"]));

        $this->assertArrayNotHasKey("/wp/v2/users", $this->routes());
    }

    /**
     * Editors and authors keep the routes the block editor depends on
     *
     * @dataProvider editing_roles
     * @param string $role Role slug.
     * @return void
     */
    public function test_editing_roles_keep_users_endpoint(string $role): void
    {
        wp_set_current_user(self::factory()->user->create(["role" => $role]));
        $routes = $this->routes();

        $this->assertArrayHasKey("/wp/v2/users", $routes);
        $this->assertArrayHasKey("/wp/v2/users/(?P<id>[\\d]+)", $routes);
    }

    /**
     * Roles that can edit posts
     *
     * @return array<string, array{string}>
     */
    public static function editing_roles(): array
    {
        return [
            "administrator" => ["administrator"],
            "editor"        => ["editor"],
            "author"        => ["author"],
        ];
    }

    /**
     * An editor can actually query authors the way Gutenberg does
     *
     * @return void
     */
    public function test_editor_can_query_authors_via_rest(): void
    {
        // Gutenberg still sends who=authors; WP_User_Query logs its own deprecation.
        $this->setExpectedDeprecated("WP_User_Query");
        wp_set_current_user(self::factory()->user->create(["role" => "editor"]));
        $GLOBALS["wp_rest_server"] = null;

        $request = new \WP_REST_Request("GET", "/wp/v2/users");
        $request->set_query_params(["who" => "authors"]);
        $response = rest_get_server()->dispatch($request);

        $this->assertSame(200, $response->get_status());
    }

    /**
     * Anonymous request to the users route gets a 404
     *
     * @return void
     */
    public function test_anonymous_rest_request_to_users_is_not_found(): void
    {
        wp_set_current_user(0);
        $GLOBALS["wp_rest_server"] = null;

        $response = rest_get_server()->dispatch(new \WP_REST_Request("GET", "/wp/v2/users"));

        $this->assertSame(404, $response->get_status());
    }
}
