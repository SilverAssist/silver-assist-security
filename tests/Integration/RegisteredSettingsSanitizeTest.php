<?php
/**
 * Registered settings sanitize callbacks
 *
 * Options written outside SettingsSaver (core's options.php, the REST settings route, WP-CLI, import)
 * reach update_option() directly; the sanitize callbacks registered from SettingsRegistry clamp them (#153).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Sanitizing through update_option and the REST settings route
 */
class RegisteredSettingsSanitizeTest extends WP_UnitTestCase {

	/**
	 * Every registry option is registered with a sanitize callback
	 *
	 * @return void
	 */
	public function test_every_registry_option_has_a_sanitize_callback(): void {
		$registered = \get_registered_settings();

		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			$this->assertArrayHasKey( $option, $registered, "{$option} is not registered." );
			$this->assertIsCallable( $registered[ $option ]['sanitize_callback'] ?? null, "{$option} has no sanitize callback." );
		}
	}

	/**
	 * Out-of-range integers are clamped by update_option
	 *
	 * @return array<string, array{string, mixed, int}>
	 */
	public function int_cases(): array {
		return array(
			'attempts zero'      => array( 'silver_assist_login_attempts', '0', 1 ),
			'attempts huge'      => array( 'silver_assist_login_attempts', '99999999999', 20 ),
			'attempts negative'  => array( 'silver_assist_login_attempts', -5, 1 ),
			'attempts text'      => array( 'silver_assist_login_attempts', 'abc', 1 ),
			'lockout low'        => array( 'silver_assist_lockout_duration', 1, 60 ),
			'lockout high'       => array( 'silver_assist_lockout_duration', 9999999, 3600 ),
			'session low'        => array( 'silver_assist_session_timeout', 0, 5 ),
			'rest requests high' => array( 'silver_assist_rest_rate_limit_requests', 100000, 1000 ),
			'rest window low'    => array( 'silver_assist_rest_rate_limit_window', 1, 30 ),
			'graphql depth high' => array( 'silver_assist_graphql_query_depth', 500, 20 ),
			'graphql complexity' => array( 'silver_assist_graphql_query_complexity', 1, 10 ),
			'cf7 limit high'     => array( 'silver_assist_cf7_rate_limit', 50, 10 ),
			'ip threshold low'   => array( 'silver_assist_ip_blacklist_threshold', 0, 3 ),
			'ip duration high'   => array( 'silver_assist_ip_blacklist_duration', 99999999, 604800 ),
			'in range untouched' => array( 'silver_assist_login_attempts', '7', 7 ),
		);
	}

	/**
	 * Writing an out-of-range integer stores the clamped one
	 *
	 * @dataProvider int_cases
	 * @param string $option   Option.
	 * @param mixed  $written  Written value.
	 * @param int    $expected Stored value.
	 * @return void
	 */
	public function test_update_option_clamps_integers( string $option, $written, int $expected ): void {
		\update_option( $option, $written );

		$this->assertSame( $expected, (int) \get_option( $option ) );
	}

	/**
	 * Booleans are stored as 0 or 1
	 *
	 * @return void
	 */
	public function test_update_option_normalizes_booleans(): void {
		\update_option( 'silver_assist_bot_protection', 'yes please' );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_bot_protection' ) );

		\update_option( 'silver_assist_bot_protection', '1' );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_bot_protection' ) );

		\update_option( 'silver_assist_bot_protection', true );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_bot_protection' ) );

		// A value that is not a scalar is refused and the stored one stays.
		\update_option( 'silver_assist_bot_protection', array( 'x' ) );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_bot_protection' ) );
	}

	/**
	 * URL, color and user id are sanitized
	 *
	 * @return void
	 */
	public function test_update_option_sanitizes_url_color_and_user(): void {
		\update_option( 'silver_assist_login_branding_logo_url', 'javascript:alert(1)' );
		$this->assertSame( '', \get_option( 'silver_assist_login_branding_logo_url' ) );

		\update_option( 'silver_assist_login_branding_logo_url', ' https://example.com/logo.png ' );
		$this->assertSame( 'https://example.com/logo.png', \get_option( 'silver_assist_login_branding_logo_url' ) );

		\update_option( 'silver_assist_login_branding_bg_color', 'red; background:url(x)' );
		$this->assertSame( '', \get_option( 'silver_assist_login_branding_bg_color' ) );

		\update_option( 'silver_assist_login_branding_bg_color', '#0A1628' );
		$this->assertSame( '#0A1628', \get_option( 'silver_assist_login_branding_bg_color' ) );

		\update_option( 'silver_assist_graphql_service_user_id', 999999 );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_graphql_service_user_id' ) );

		$user_id = self::factory()->user->create();
		\update_option( 'silver_assist_graphql_service_user_id', (string) $user_id );
		$this->assertSame( $user_id, (int) \get_option( 'silver_assist_graphql_service_user_id' ) );
	}

	/**
	 * A bad admin path written outside the saver keeps the previous path
	 *
	 * @return void
	 */
	public function test_update_option_refuses_bad_admin_path(): void {
		\update_option( 'silver_assist_admin_hide_path', 'my-private-door' );

		foreach ( array( 'wp-json', 'feed', 'ab', '!!!', '' ) as $bad ) {
			\update_option( 'silver_assist_admin_hide_path', $bad );
			$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ), "'{$bad}' must not replace the path." );
		}

		\update_option( 'silver_assist_admin_hide_path', 'Another Door' );
		$this->assertSame( 'another-door', \get_option( 'silver_assist_admin_hide_path' ) );
	}

	/**
	 * A bad admin path on first write falls back to the default path
	 *
	 * @return void
	 */
	public function test_bad_admin_path_without_previous_value_uses_default(): void {
		\delete_option( 'silver_assist_admin_hide_path' );

		\add_option( 'silver_assist_admin_hide_path', 'wp-json' );

		$this->assertSame( 'silver-admin', \get_option( 'silver_assist_admin_hide_path' ) );
	}

	/**
	 * The REST settings route, when an option is exposed to it, runs the same callbacks
	 *
	 * The plugin does not expose its options to REST; this proves a site or plugin that does cannot write
	 * unclamped values through it.
	 *
	 * @return void
	 */
	public function test_rest_settings_route_clamps(): void {
		$option = 'silver_assist_login_attempts';
		$args   = \get_registered_settings()[ $option ] ?? array();
		$group  = (string) ( $args['group'] ?? 'silver_assist_security_login' );
		\unregister_setting( $group, $option );
		$args['show_in_rest'] = true;
		$args['type']         = 'integer';
		\register_setting( $group, $option, $args );

		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		global $wp_rest_server;
		$wp_rest_server = new \WP_REST_Server();
		\do_action( 'rest_api_init' );

		$request = new WP_REST_Request( 'POST', '/wp/v2/settings' );
		$request->set_header( 'content-type', 'application/json' );
		$request->set_body( \wp_json_encode( array( 'silver_assist_login_attempts' => 0 ) ) );
		$response = $wp_rest_server->dispatch( $request );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_login_attempts' ) );

		$wp_rest_server = null;
	}

	/**
	 * Registering again does not stack a second callback
	 *
	 * @return void
	 */
	public function test_registering_twice_keeps_one_callback(): void {
		\SilverAssist\Security\Admin\Settings\SettingsSanitizer::register();
		\SilverAssist\Security\Admin\Settings\SettingsSanitizer::register();

		global $wp_filter;
		$this->assertCount( 1, $wp_filter['sanitize_option_silver_assist_login_attempts']->callbacks[10] );
	}

	/**
	 * Core's options.php accepts the plugin options only after they are registered in a group
	 *
	 * @return void
	 */
	public function test_options_are_allowed_in_a_group(): void {
		global $new_allowed_options;
		$allowed = array();
		foreach ( (array) $new_allowed_options as $options ) {
			$allowed = array_merge( $allowed, $options );
		}

		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			$this->assertContains( $option, $allowed, "{$option} is not in an options.php group." );
		}
	}
}
