<?php
/**
 * The plugin's `plugins_loaded` loading tiers, observed during the real boot sequence
 *
 * The main file loads login and general protection at `plugins_loaded` priority 1, GraphQL API-key
 * authentication at priority 5 and the rest at `init`. API-key authentication has to be registered
 * before WordPress works out the current user (which happens before `init`) and after WPGraphQL has
 * defined its class, or a request carrying a key would be treated as anonymous. `tests/bootstrap.php`
 * records the state at those moments (`$GLOBALS['silver_assist_boot_probe']`); these tests read it and
 * then authenticate a real request with an API key (#154, G9).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Tests\Helpers\HeadlessTestSupport;
use WP_UnitTestCase;

/**
 * Loading tier tests
 */
class PluginLoadingTiersTest extends WP_UnitTestCase {

	use HeadlessTestSupport;

	/**
	 * What the bootstrap probes recorded
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function probe(): array {
		$probe = $GLOBALS['silver_assist_boot_probe'] ?? null;
		$this->assertIsArray( $probe, 'tests/bootstrap.php records the boot probes' );

		return $probe;
	}

	/**
	 * Login protection is ready after the first tier, and GraphQL key auth waits for its own tier
	 *
	 * @return void
	 */
	public function test_tiers_register_in_their_own_priority_order(): void {
		$probe = $this->probe();

		$this->assertTrue( $probe['after_p1']['login_hooks'], 'login protection is hooked at plugins_loaded priority 1, before wp-login.php can act' );
		$this->assertFalse( $probe['after_p1']['api_key_auth'], 'API-key auth is not registered yet at priority 2: it belongs to the priority 5 tier' );
	}

	/**
	 * API-key auth is registered after WPGraphQL exists and before the user is resolved
	 *
	 * @return void
	 */
	public function test_api_key_auth_is_registered_before_the_user_is_resolved(): void {
		$this->require_wpgraphql();
		$probe = $this->probe();

		$this->assertTrue( $probe['after_p5']['wpgraphql_loaded'], 'WPGraphQL had defined its class when the tier ran' );
		$this->assertTrue( $probe['after_p5']['api_key_auth'], 'the priority 5 tier registered determine_current_user' );
		$this->assertSame( 0, $probe['after_p5']['init_done'], 'and it did so before init' );

		$this->assertTrue( $probe['first_user_resolution']['api_key_auth'], 'the key callback existed the first time WordPress resolved the user' );
		$this->assertSame( 0, $probe['first_user_resolution']['init_done'], 'which happens before init' );
	}

	/**
	 * A request carrying an API key is authenticated as the service user
	 *
	 * @return void
	 */
	public function test_api_key_request_authenticates(): void {
		$this->require_wpgraphql();
		$this->snapshot_server();

		$service_user = $this->create_api_key_service_user( 'tier-test-key', 'editor' );
		$_SERVER['HTTP_HOST']      = 'example.org';
		$_SERVER['REQUEST_URI']    = '/graphql';
		$_SERVER['HTTP_X_API_KEY'] = 'tier-test-key';

		try {
			$this->assertSame( $service_user, $this->resolve_current_user() );

			$_SERVER['HTTP_X_API_KEY'] = 'wrong-key';
			$this->assertSame( 0, $this->resolve_current_user(), 'a wrong key stays anonymous' );
		} finally {
			$this->restore_headless_state();
		}
	}
}
