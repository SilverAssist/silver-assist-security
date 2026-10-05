<?php
/**
 * Shared support for the headless (REST and GraphQL) behavior tests
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Helpers;

use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\GraphQL\GraphQLSecurity;

/**
 * Helpers shared by tests that run requests through the real WordPress and WPGraphQL code paths.
 *
 * Use it in a `WP_UnitTestCase` and call `restore_headless_state()` from `tearDown()`.
 *
 * @since 1.5.4
 */
trait HeadlessTestSupport {

	/**
	 * `$_SERVER` as it was before the test faked a request
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $server_snapshot = null;

	/**
	 * Remember `$_SERVER` so `restore_headless_state()` can put it back
	 *
	 * Call it before the test sets request headers (host, URI, API key, client IP).
	 *
	 * @return void
	 */
	protected function snapshot_server(): void {
		if ( null === $this->server_snapshot ) {
			$this->server_snapshot = $_SERVER;
		}
	}

	/**
	 * Make sure WPGraphQL is present
	 *
	 * The GraphQL tests must not vanish silently. In CI (the `CI` environment variable is set) a
	 * missing WPGraphQL fails the test instead of skipping it, so a broken installer step cannot turn
	 * the GraphQL coverage into a green run that tested nothing.
	 *
	 * @return void
	 */
	protected function require_wpgraphql(): void {
		if ( \class_exists( 'WPGraphQL' ) ) {
			return;
		}

		$message = 'WPGraphQL is not installed: run scripts/install-wpgraphql-for-tests.sh';

		if ( false !== \getenv( 'CI' ) && '' !== \getenv( 'CI' ) ) {
			$this->fail( $message . ' (CI must not skip GraphQL tests).' );
		}

		$this->markTestSkipped( $message . '.' );
	}

	/**
	 * Set the environment type the plugin sees for the current test
	 *
	 * `wp_get_environment_type()` caches its first answer for the whole PHPUnit process and a defined
	 * `WP_ENVIRONMENT_TYPE` constant cannot be changed or removed, so neither can switch environments
	 * between tests. The plugin reads the type through the `silver_assist_security_environment_type`
	 * filter, which WordPress restores between tests.
	 *
	 * @param string $type One of local, development, staging, production.
	 * @return void
	 */
	protected function set_environment_type( string $type ): void {
		\add_filter(
			'silver_assist_security_environment_type',
			static function () use ( $type ): string {
				return $type;
			}
		);
	}

	/**
	 * Configure WPGraphQL's own settings and refresh the plugin's cached view of them
	 *
	 * @param array<string, string> $settings Values for `graphql_general_settings`.
	 * @return void
	 */
	protected function set_graphql_settings( array $settings ): void {
		\update_option( 'graphql_general_settings', $settings );
		$this->clear_graphql_config_caches();
	}

	/**
	 * Clear the cached GraphQL configuration the plugin works from
	 *
	 * `GraphQLSecurity` keeps the config manager it was built with, which can differ from the current
	 * singleton when another test replaced it, so both are cleared.
	 *
	 * @return void
	 */
	protected function clear_graphql_config_caches(): void {
		GraphQLConfigManager::get_instance()->clear_cache();

		$reflection = new \ReflectionProperty( GraphQLSecurity::class, 'config_manager' );
		$reflection->setAccessible( true );
		$held = $reflection->getValue( GraphQLSecurity::instance() );
		if ( $held instanceof GraphQLConfigManager ) {
			$held->clear_cache();
		}
	}

	/**
	 * Create a service user and store an API key for it, as the plugin settings do
	 *
	 * @param string $api_key Plain API key the headless client will send.
	 * @param string $role    Role of the service account.
	 * @return int Service user ID.
	 */
	protected function create_api_key_service_user( string $api_key, string $role = 'editor' ): int {
		$service_user_id = self::factory()->user->create( array( 'role' => $role ) );

		\update_option( 'silver_assist_graphql_service_user_id', $service_user_id );
		\update_option( 'silver_assist_graphql_api_key', \wp_hash_password( $api_key ) );

		return (int) $service_user_id;
	}

	/**
	 * Make WordPress work out the current user again, the way it does at the start of a request
	 *
	 * Runs `determine_current_user` (cookie, application password and API key callbacks) against the
	 * current `$_SERVER` instead of calling the plugin method directly.
	 *
	 * @return int Resolved user ID (0 for a guest).
	 */
	protected function resolve_current_user(): int {
		$GLOBALS['current_user'] = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Forces WordPress to run determine_current_user again.

		return (int) \get_current_user_id();
	}

	/**
	 * Reset the state a headless test can leak into the next one
	 *
	 * @return void
	 */
	protected function restore_headless_state(): void {
		// GraphQLSecurity is a singleton that remembers a successful API key login for the request.
		$reflection = new \ReflectionProperty( GraphQLSecurity::class, 'api_key_authenticated' );
		$reflection->setAccessible( true );
		$reflection->setValue( GraphQLSecurity::instance(), false );

		if ( null !== $this->server_snapshot ) {
			$_SERVER               = $this->server_snapshot; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Undo the request headers the test faked.
			$this->server_snapshot = null;
		}

		\delete_option( 'graphql_general_settings' );
		\delete_option( 'silver_assist_graphql_api_key' );
		\delete_option( 'silver_assist_graphql_service_user_id' );
		\delete_option( 'silver_assist_graphql_headless_mode' );
		$this->clear_graphql_config_caches();
		\wp_set_current_user( 0 );
	}
}
