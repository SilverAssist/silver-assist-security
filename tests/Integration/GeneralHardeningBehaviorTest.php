<?php
/**
 * General Hardening Behavior Tests
 *
 * Asserts what a visitor, a logged-in user or an integration actually
 * experiences with the general hardening active: which security headers are
 * sent in each request context, the cookie flags, what stays in wp_head,
 * whether XML-RPC is really off, and what the login screens say. Part of the
 * audit in #124 (WEB-1222 showed that hook-registration tests miss regressions).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * GeneralSecurity subclass that records headers instead of sending them
 *
 * PHPUnit has already sent output, so header() is a no-op there; capturing the
 * lines lets the tests assert what each request context would send.
 */
class CapturingGeneralSecurity extends GeneralSecurity {

	/**
	 * Header lines that would have been sent, in order
	 *
	 * @var array<int, string>
	 */
	public array $sent = array();

	/**
	 * Record the headers instead of sending them
	 *
	 * @param array<string, string> $headers Header name => value.
	 * @return void
	 */
	protected function send_headers_now( array $headers ): void {
		foreach ( $headers as $name => $value ) {
			$this->sent[] = $name . ': ' . $value;
		}
	}
}

/**
 * Behavior tests for GeneralSecurity
 */
class GeneralHardeningBehaviorTest extends WP_UnitTestCase {

	/**
	 * Server globals changed by a test
	 *
	 * @var array<string, mixed>
	 */
	private array $server_backup = array();

	/**
	 * Back up request globals
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->server_backup = $_SERVER;
		unset( $GLOBALS['show_admin_bar'] );
	}

	/**
	 * Restore request globals
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		unset( $_REQUEST['action'], $GLOBALS['show_admin_bar'] );
		wp_set_current_user( 0 );
		parent::tearDown();
	}

	/**
	 * Build a capturing instance and the lines a context sends
	 *
	 * @param callable $trigger Fires the request context's hook.
	 * @return array<int, string> Header lines.
	 */
	private function headers_sent_by( callable $trigger ): array {
		// Core and other components hook these too; PHPUnit has already sent output, so
		// their own header() calls would fail. Only this component is under test.
		remove_all_actions( 'admin_init' );
		remove_all_actions( 'login_init' );
		remove_all_actions( 'send_headers' );
		remove_all_filters( 'rest_pre_serve_request' );
		$general = new CapturingGeneralSecurity();
		$trigger();
		return $general->sent;
	}

	/**
	 * Request contexts: name => callable that fires the context's real hook
	 *
	 * @return array<string, array{callable}>
	 */
	public static function request_contexts(): array {
		return array(
			'front end'    => array( static fn() => do_action( 'send_headers' ) ),
			'wp-admin'     => array( static fn() => do_action( 'admin_init' ) ),
			'login screen' => array( static fn() => do_action( 'login_init' ) ),
			'REST API'     => array( static fn() => apply_filters( 'rest_pre_serve_request', false, null, new \WP_REST_Request(), rest_get_server() ) ),
		);
	}

	/**
	 * Every request context gets the baseline security headers
	 *
	 * @dataProvider request_contexts
	 * @param callable $trigger Fires the request context's hook.
	 * @return void
	 */
	public function test_baseline_headers_are_sent_in_every_context( callable $trigger ): void {
		$lines = $this->headers_sent_by( $trigger );

		$this->assertContains( 'X-Content-Type-Options: nosniff', $lines );
		$this->assertContains( 'X-Frame-Options: SAMEORIGIN', $lines );
		$this->assertContains( 'Referrer-Policy: strict-origin-when-cross-origin', $lines );
	}

	/**
	 * The REST filter must hand the "already served" flag back untouched
	 *
	 * Returning anything else would make core skip or double-serve the response.
	 *
	 * @return void
	 */
	public function test_rest_header_hook_does_not_change_served_flag(): void {
		new CapturingGeneralSecurity();

		$this->assertFalse( apply_filters( 'rest_pre_serve_request', false, null, new \WP_REST_Request(), rest_get_server() ) );
		$this->assertTrue( apply_filters( 'rest_pre_serve_request', true, null, new \WP_REST_Request(), rest_get_server() ) );
	}

	/**
	 * Headers keep the editor preview, media modals and embeds working
	 *
	 * The editor renders previews and the media modal in same-origin iframes, which
	 * SAMEORIGIN allows; DENY or a CSP frame-ancestors of none would break them.
	 *
	 * @return void
	 */
	public function test_headers_do_not_forbid_same_origin_framing(): void {
		$lines = $this->headers_sent_by( static fn() => do_action( 'send_headers' ) );

		$this->assertNotContains( 'X-Frame-Options: DENY', $lines );
		foreach ( $lines as $line ) {
			$this->assertStringNotContainsString( 'frame-ancestors', strtolower( $line ) );
		}
	}

	/**
	 * Sites can relax a header an integration needs (store locator, mic recorder)
	 *
	 * @return void
	 */
	public function test_headers_can_be_adjusted_with_a_filter(): void {
		add_filter(
			'silver_assist_security_headers',
			static function ( array $headers ): array {
				$headers['Permissions-Policy'] = 'geolocation=(self)';
				unset( $headers['X-XSS-Protection'] );
				return $headers;
			}
		);

		$lines = $this->headers_sent_by( static fn() => do_action( 'send_headers' ) );

		$this->assertContains( 'Permissions-Policy: geolocation=(self)', $lines );
		$this->assertNotContains( 'X-XSS-Protection: 1; mode=block', $lines );
		$this->assertContains( 'X-Frame-Options: SAMEORIGIN', $lines );
	}

	/**
	 * HSTS is sent on SSL in production, and only there
	 *
	 * @return void
	 */
	public function test_hsts_only_on_ssl_outside_development(): void {
		add_filter( 'silver_assist_security_is_development_environment', '__return_false' );

		$_SERVER['HTTPS'] = 'on';
		$ssl              = $this->headers_sent_by( static fn() => do_action( 'send_headers' ) );
		$this->assertContains( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', $ssl );

		unset( $_SERVER['HTTPS'] );
		$plain = $this->headers_sent_by( static fn() => do_action( 'send_headers' ) );
		foreach ( $plain as $line ) {
			$this->assertStringStartsNotWith( 'Strict-Transport-Security', $line, 'HSTS over plain HTTP is ignored by browsers and misleading' );
		}
	}

	/**
	 * HSTS stays off in development even on SSL
	 *
	 * @return void
	 */
	public function test_hsts_not_sent_in_development(): void {
		add_filter( 'silver_assist_security_is_development_environment', '__return_true' );
		$_SERVER['HTTPS'] = 'on';

		$lines = $this->headers_sent_by( static fn() => do_action( 'send_headers' ) );

		$this->assertNotEmpty( $lines, 'the other headers are still sent' );
		foreach ( $lines as $line ) {
			$this->assertStringStartsNotWith( 'Strict-Transport-Security', $line );
		}
	}

	/**
	 * The auth cookie is Secure exactly when the request is HTTPS
	 *
	 * A Secure cookie over plain HTTP would never come back and lock the user out.
	 *
	 * @return void
	 */
	public function test_auth_cookies_are_secure_only_over_https(): void {
		new GeneralSecurity();

		unset( $_SERVER['HTTPS'] );
		$this->assertFalse( apply_filters( 'secure_auth_cookie', false, 1 ) );
		$this->assertFalse( apply_filters( 'secure_logged_in_cookie', false, 1, false ) );

		$_SERVER['HTTPS'] = 'on';
		$this->assertTrue( apply_filters( 'secure_auth_cookie', false, 1 ) );
	}

	/**
	 * A site whose home URL is http keeps the logged-in cookie readable on the front end
	 *
	 * Core marks the logged-in cookie Secure only when home is https (the
	 * wp-admin side may be https while the public site is not). Forcing Secure
	 * whenever the request is SSL dropped the cookie on the http front end, so
	 * logged-in users lost the admin bar and previews there.
	 *
	 * @return void
	 */
	public function test_logged_in_cookie_follows_core_home_scheme_rule(): void {
		new GeneralSecurity();
		$_SERVER['HTTPS'] = 'on';

		update_option( 'home', 'http://example.org' );
		$this->assertFalse( apply_filters( 'secure_logged_in_cookie', false, 1, true ) );

		update_option( 'home', 'https://example.org' );
		$this->assertTrue( apply_filters( 'secure_logged_in_cookie', true, 1, true ) );
	}

	/**
	 * Cookie lifetime is the configured session timeout, with or without "Remember me"
	 *
	 * Intentional (LoginSecurity): the cookie never outlives the session timeout
	 * setting, and the "Remember me" checkbox is hidden because it would be a lie.
	 *
	 * @return void
	 */
	public function test_auth_cookie_expiration_is_the_session_timeout(): void {
		new \SilverAssist\Security\Security\LoginSecurity();
		$expected = (int) \SilverAssist\Security\Core\DefaultConfig::get_option( 'silver_assist_session_timeout' ) * 60;

		$this->assertGreaterThan( 0, $expected );
		$this->assertSame( $expected, apply_filters( 'auth_cookie_expiration', 2 * DAY_IN_SECONDS, 1, false ) );
		$this->assertSame( $expected, apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, 1, true ) );
	}

	/**
	 * Put core's default wp_head hooks back
	 *
	 * The plugin is already active in the test site and removed them at init, so
	 * the tests re-register core's defaults to see what removal changes.
	 *
	 * @return void
	 */
	private function restore_core_head_hooks(): void {
		add_action( 'wp_head', 'feed_links', 2 );
		add_action( 'wp_head', 'feed_links_extra', 3 );
		add_action( 'wp_head', 'rsd_link' );
		add_action( 'wp_head', 'wp_generator' );
		add_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
		add_action( 'wp_head', 'wp_oembed_add_discovery_links' );
	}

	/**
	 * Capture the markup wp_head prints for a single post
	 *
	 * @return string
	 */
	private function head_markup(): string {
		add_theme_support( 'automatic-feed-links' );
		$post_id = self::factory()->post->create( array( 'post_status' => 'publish' ) );
		$this->go_to( get_permalink( $post_id ) );

		ob_start();
		do_action( 'wp_head' );
		return (string) ob_get_clean();
	}

	/**
	 * Discovery tags that leak the stack are removed
	 *
	 * @return void
	 */
	public function test_wp_head_drops_generator_rsd_shortlink_and_oembed_discovery(): void {
		$this->restore_core_head_hooks();
		$before = $this->head_markup();
		$this->assertStringContainsString( 'application/json+oembed', $before, 'control: core prints oEmbed discovery by default' );

		$general = new GeneralSecurity();
		$general->remove_unnecessary_headers();
		$after = $this->head_markup();

		$this->assertStringNotContainsString( 'application/json+oembed', $after );
		$this->assertStringNotContainsString( 'EditURI', $after );
		$this->assertStringNotContainsString( "rel='shortlink'", $after );
		$this->assertStringNotContainsString( 'name="generator"', $after );
	}

	/**
	 * REST discovery stays so mobile apps, Jetpack and the editor can find the API
	 *
	 * @return void
	 */
	public function test_wp_head_keeps_rest_discovery(): void {
		$general = new GeneralSecurity();
		$general->remove_unnecessary_headers();

		$this->assertStringContainsString( 'https://api.w.org/', $this->head_markup() );
	}

	/**
	 * Feed autodiscovery is removed by default but the feeds still answer
	 *
	 * @return void
	 */
	public function test_feed_discovery_removed_but_feed_urls_still_exist(): void {
		$this->restore_core_head_hooks();
		$this->assertStringContainsString( 'application/rss+xml', $this->head_markup(), 'control: core prints feed discovery by default' );

		$general = new GeneralSecurity();
		$general->remove_unnecessary_headers();

		$this->assertStringNotContainsString( 'application/rss+xml', $this->head_markup() );
		$this->assertNotEmpty( get_feed_link(), 'feeds remain reachable at their URL for readers that were given it' );
	}

	/**
	 * A site that relies on feed autodiscovery (RSS readers) can keep it
	 *
	 * @return void
	 */
	public function test_feed_discovery_can_be_kept_with_a_filter(): void {
		$this->restore_core_head_hooks();
		add_filter( 'silver_assist_security_remove_feed_links', '__return_false' );

		$general = new GeneralSecurity();
		$general->remove_unnecessary_headers();

		$this->assertStringContainsString( 'application/rss+xml', $this->head_markup() );
	}

	/**
	 * XML-RPC answers nothing: the method table is empty and calls are refused
	 *
	 * @return void
	 */
	public function test_xmlrpc_is_disabled(): void {
		new GeneralSecurity();
		require_once ABSPATH . WPINC . '/class-IXR.php';
		require_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';

		$server = new \wp_xmlrpc_server();

		$this->assertSame( array(), $server->methods, 'no method (including pingback.ping) is exposed' );
		$this->assertFalse( apply_filters( 'xmlrpc_enabled', true ) );
	}

	/**
	 * A site that needs XML-RPC (Jetpack, the mobile apps) can switch it back on
	 *
	 * @return void
	 */
	public function test_xmlrpc_can_be_reenabled_with_a_filter(): void {
		add_filter( 'silver_assist_security_disable_xmlrpc', '__return_false' );
		new GeneralSecurity();
		require_once ABSPATH . WPINC . '/class-IXR.php';
		require_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';

		$server = new \wp_xmlrpc_server();

		$this->assertArrayHasKey( 'wp.getPosts', $server->methods );
		$this->assertTrue( apply_filters( 'xmlrpc_enabled', true ) );
	}

	/**
	 * No code in this plugin calls XML-RPC (nothing first-party depends on it)
	 *
	 * @return void
	 */
	public function test_plugin_has_no_first_party_xmlrpc_client(): void {
		$root  = dirname( __DIR__, 2 );
		$files = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . '/src', \FilesystemIterator::SKIP_DOTS ) );

		foreach ( $files as $file ) {
			if ( 'php' !== $file->getExtension() || str_ends_with( $file->getPathname(), 'GeneralSecurity.php' ) ) {
				continue;
			}
			$source = (string) file_get_contents( $file->getPathname() );
			$this->assertDoesNotMatchRegularExpression( '/xmlrpc\.php|IXR_Client|wp_xmlrpc_server/i', $source, $file->getFilename() . ' must not depend on XML-RPC' );
		}
	}

	/**
	 * Login screens: a wrong password does not reveal whether the account exists
	 *
	 * @return void
	 */
	public function test_wrong_credentials_get_the_generic_message(): void {
		new GeneralSecurity();
		$_SERVER['REMOTE_ADDR'] = '203.0.113.50';

		$message = apply_filters( 'login_errors', '<p><strong>Error:</strong> The password you entered for the username <strong>admin</strong> is incorrect.</p>' );

		$this->assertStringNotContainsString( 'admin', $message );
		$this->assertStringContainsString( 'Invalid login credentials', $message );
	}

	/**
	 * Lost-password lookups do not reveal whether an account exists either
	 *
	 * @return void
	 */
	public function test_lost_password_lookup_gets_the_generic_message(): void {
		new GeneralSecurity();
		$_REQUEST['action'] = 'lostpassword';

		$message = apply_filters( 'login_errors', '<p><strong>Error:</strong> There is no account with that username or email address.</p>' );

		$this->assertStringNotContainsString( 'no account', $message );
	}

	/**
	 * A locked-out visitor is told they are locked out, not that the password is wrong
	 *
	 * Replacing the lockout message made a user who typed the right password
	 * during a lockout believe the credentials were rejected.
	 *
	 * @return void
	 */
	public function test_lockout_message_is_not_replaced_by_the_generic_one(): void {
		new GeneralSecurity();
		$_SERVER['REMOTE_ADDR'] = '203.0.113.51';
		set_transient( \SilverAssist\Security\Core\SecurityHelper::generate_ip_transient_key( 'lockout', '203.0.113.51' ), true, 600 );

		$locked = '<p>Too many failed login attempts. Try again in 10 minutes.</p>';

		$this->assertSame( $locked, apply_filters( 'login_errors', $locked ) );
	}

	/**
	 * Password reset screens keep core's actionable messages
	 *
	 * "The passwords do not match" and "reset link expired" are not credential
	 * oracles; replacing them left users stuck on a screen that told them nothing.
	 *
	 * @return void
	 */
	public function test_password_reset_errors_stay_actionable(): void {
		new GeneralSecurity();

		foreach ( array( 'resetpass', 'rp' ) as $action ) {
			$_REQUEST['action'] = $action;
			$message            = '<p><strong>Error:</strong> The passwords do not match.</p>';

			$this->assertSame( $message, apply_filters( 'login_errors', $message ), "action={$action}" );
		}
	}

	/**
	 * The admin bar is hidden on the front end for non-admins and kept for admins
	 *
	 * @return void
	 */
	public function test_admin_bar_front_end_visibility_by_role(): void {
		$general = new GeneralSecurity();

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		unset( $GLOBALS['show_admin_bar'] );
		$general->remove_admin_bar_for_non_admins();
		$this->assertTrue( is_admin_bar_showing(), 'administrator keeps the admin bar' );

		foreach ( array( 'editor', 'author', 'subscriber' ) as $role ) {
			wp_set_current_user( self::factory()->user->create( array( 'role' => $role ) ) );
			unset( $GLOBALS['show_admin_bar'] );
			$general->remove_admin_bar_for_non_admins();
			$this->assertFalse( is_admin_bar_showing(), "{$role} does not get the admin bar on the front end" );
		}
	}

	/**
	 * Core's file editor is off and the admin footer is branded
	 *
	 * @return void
	 */
	public function test_file_editing_is_disallowed_and_footer_branded(): void {
		new GeneralSecurity();

		$this->assertTrue( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->assertFalse( current_user_can( 'edit_themes' ) );
		$this->assertStringContainsString( 'Silver Assist Security Essentials', apply_filters( 'admin_footer_text', '' ) );
	}
}
