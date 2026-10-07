<?php
/**
 * Behavior tests for the residual audit gaps (#154)
 *
 * Each test drives a real WordPress flow (a rendered admin bar, a request routed through
 * `template_redirect`, a form scan, a translation lookup) and asserts what a visitor or an
 * administrator experiences, not that a hook is registered.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\AdminHideSecurity;
use SilverAssist\Security\Security\FormProtection;
use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Extension filters, admin bar, plugin links, password scripts and routing residuals
 */
class AuditResidualsBehaviorTest extends WP_UnitTestCase {

	/**
	 * Server globals changed by a test
	 *
	 * @var array<string, mixed>
	 */
	private array $server_backup = array();

	/**
	 * Temporary directories to remove
	 *
	 * @var array<int, string>
	 */
	private array $temp_dirs = array();

	/**
	 * Back up request globals
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->server_backup = $_SERVER;
		$_POST               = array();
		$_GET                = array();
	}

	/**
	 * Restore request globals and the default translations
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_POST   = array();
		$_GET    = array();
		wp_set_current_user( 0 );
		unset( $GLOBALS['wp_admin_bar'], $GLOBALS['show_admin_bar'] );

		foreach ( $this->temp_dirs as $dir ) {
			foreach ( (array) glob( $dir . '/*' ) as $file ) {
				if ( is_string( $file ) && is_file( $file ) ) {
					unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Test cleanup of a temp file.
				}
			}
			rmdir( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Test cleanup of a temp dir.
		}

		unload_textdomain( 'silver-assist-security' );
		parent::tearDown();
	}

	// ---------------------------------------------------------------------
	// G1: cleanup cron.
	// ---------------------------------------------------------------------

	/**
	 * The daily cleanup is scheduled once and, when it fires, removes expired lockout rows
	 *
	 * @return void
	 */
	public function test_cleanup_cron_is_scheduled_once_and_purges_expired_rows(): void {
		global $wpdb;

		wp_clear_scheduled_hook( 'silver_assist_security_cleanup' );
		\SilverAssist\Security\Security\IPBlacklist::init_cron_cleanup();
		\SilverAssist\Security\Security\IPBlacklist::init_cron_cleanup();

		$crons = array_filter(
			_get_cron_array(),
			static fn( $events ) => isset( $events['silver_assist_security_cleanup'] )
		);
		$this->assertCount( 1, $crons, 'calling the initializer twice schedules one event' );
		$event = wp_get_scheduled_event( 'silver_assist_security_cleanup' );
		$this->assertIsObject( $event );
		$this->assertSame( 'daily', $event->schedule );

		$key = 'lockout_' . md5( '198.51.100.90' );
		set_transient( $key, time() - 10, HOUR_IN_SECONDS );
		$wpdb->update( $wpdb->options, array( 'option_value' => (string) ( time() - 5 ) ), array( 'option_name' => '_transient_timeout_' . $key ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Age the row.
		wp_cache_flush();

		do_action( 'silver_assist_security_cleanup' );

		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s", '_transient_timeout_' . $key ) ), 'the expired row is gone' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Check the row.
	}

	// ---------------------------------------------------------------------
	// G2: extension filters.
	// ---------------------------------------------------------------------

	/**
	 * A site can add its own SQL injection signature
	 *
	 * @return void
	 */
	public function test_sql_pattern_filter_adds_a_signature(): void {
		$_POST = array( 'your-message' => 'please run secret_proc for me' );
		$this->assertFalse( FormProtection::has_sql_injection_attempt(), 'control: an ordinary sentence passes' );

		add_filter(
			'silver_assist_security_sql_injection_patterns',
			static function ( array $patterns ): array {
				$patterns[] = 'secret_proc';
				return $patterns;
			}
		);

		$this->assertTrue( FormProtection::has_sql_injection_attempt(), 'the added signature now blocks the submission' );
	}

	/**
	 * A site can drop a signature that produces false positives
	 *
	 * @return void
	 */
	public function test_sql_pattern_filter_removes_a_signature(): void {
		$_POST = array( 'your-message' => "x' UNION SELECT user_pass FROM wp_users" );
		$this->assertTrue( FormProtection::has_sql_injection_attempt(), 'control: blocked by default' );

		add_filter(
			'silver_assist_security_sql_injection_patterns',
			static function ( array $patterns ): array {
				return array_values( array_diff( $patterns, array( 'UNION SELECT' ) ) );
			}
		);

		$this->assertFalse( FormProtection::has_sql_injection_attempt(), 'the removed signature no longer matches' );
	}

	/**
	 * The translations folder can be moved and the strings come from the new place
	 *
	 * @return void
	 */
	public function test_languages_directory_filter_moves_the_translations(): void {
		$source = SILVER_ASSIST_SECURITY_PATH . 'languages/silver-assist-security-es_ES.mo';
		$this->assertFileExists( $source );

		// fr_FR has no file in the plugin's own folder, so a French string can only come from the new one.
		$dir = sys_get_temp_dir() . '/sas-lang-' . wp_generate_password( 8, false );
		mkdir( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Temp dir for the test.
		$this->temp_dirs[] = $dir;
		copy( $source, $dir . '/silver-assist-security-fr_FR.mo' );

		$msgid = 'Settings';
		add_filter( 'plugin_locale', static fn() => 'fr_FR' );

		unload_textdomain( 'silver-assist-security' );
		$this->load_plugin_textdomain_like_the_plugin();
		$this->assertSame( $msgid, __( $msgid, 'silver-assist-security' ), 'control: the default folder has no fr_FR file' ); // phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText -- Test lookup.

		add_filter(
			'silver_assist_security_languages_directory',
			static function () use ( $dir ): string {
				return $dir . '/';
			}
		);
		unload_textdomain( 'silver-assist-security' );
		$this->load_plugin_textdomain_like_the_plugin();

		$this->assertNotSame( $msgid, __( $msgid, 'silver-assist-security' ), 'the string is translated from the filtered folder' ); // phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText -- Test lookup.
	}

	/**
	 * Run the plugin's own textdomain loader
	 *
	 * @return void
	 */
	private function load_plugin_textdomain_like_the_plugin(): void {
		$plugin = \SilverAssist\Security\Core\Plugin::instance();
		$method = new \ReflectionMethod( $plugin, 'load_textdomain' );
		$method->setAccessible( true );
		$method->invoke( $plugin );
	}

	// ---------------------------------------------------------------------
	// G7: admin bar.
	// ---------------------------------------------------------------------

	/**
	 * Render the admin bar as an administrator on the front end
	 *
	 * @return string Admin bar HTML.
	 */
	private function render_admin_bar(): string {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->go_to( home_url( '/' ) );

		// wp_admin_bar_render() renders once per PHP process (static guard), so build the bar the way it does.
		require_once ABSPATH . WPINC . '/class-wp-admin-bar.php';
		$bar = new \WP_Admin_Bar();
		$bar->initialize();
		$bar->add_menus();
		$GLOBALS['wp_admin_bar'] = $bar; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Same global core fills.
		ob_start();
		do_action_ref_array( 'admin_bar_menu', array( &$bar ) );
		do_action( 'wp_before_admin_bar_render' );
		$bar->render();
		return (string) ob_get_clean();
	}

	/**
	 * The W menu is gone for an administrator and the rest of the bar stays
	 *
	 * @return void
	 */
	public function test_admin_bar_has_no_wordpress_logo_menu(): void {
		$callback = array( GeneralSecurity::instance(), 'remove_wp_logo' );
		$this->assertNotFalse( has_action( 'wp_before_admin_bar_render', $callback ) );

		// Control: without the plugin's callback core prints the W menu.
		remove_action( 'wp_before_admin_bar_render', $callback );
		$without_plugin = $this->render_admin_bar();
		$this->assertStringContainsString( 'wp-admin-bar-wp-logo', $without_plugin, 'control: core prints the W menu' );

		add_action( 'wp_before_admin_bar_render', $callback );
		$with_plugin = $this->render_admin_bar();

		$this->assertStringNotContainsString( 'wp-admin-bar-wp-logo', $with_plugin );
		$this->assertStringContainsString( 'wp-admin-bar-site-name', $with_plugin, 'the rest of the bar still renders' );
	}

	// ---------------------------------------------------------------------
	// G8: Plugins screen link and password scripts.
	// ---------------------------------------------------------------------

	/**
	 * The Plugins screen gets a Settings link in front of core's links
	 *
	 * @return void
	 */
	public function test_plugins_screen_shows_a_settings_link(): void {
		$links = apply_filters( 'plugin_action_links_' . SILVER_ASSIST_SECURITY_BASENAME, array( '<a href="#">Deactivate</a>' ) );

		$this->assertCount( 2, $links );
		$this->assertStringContainsString( 'page=silver-assist-security', $links[0] );
		$this->assertStringContainsString( 'Settings', $links[0] );
		$this->assertStringContainsString( 'Deactivate', $links[1], "core's own links are kept" );

		$other = apply_filters( 'plugin_action_links_other/other.php', array( '<a href="#">Deactivate</a>' ) );
		$this->assertCount( 1, $other, 'other plugins are not touched' );
	}

	/**
	 * The password strength script loads on the profile screens only, and only when enforced
	 *
	 * @return void
	 */
	public function test_password_scripts_load_on_profile_screens_only(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		update_option( 'silver_assist_password_strength_enforcement', 1 );

		set_current_screen( 'dashboard' );
		do_action( 'admin_enqueue_scripts', 'index.php' );
		$this->assertFalse( wp_script_is( 'silver-assist-password-validation', 'enqueued' ), 'not on the dashboard' );

		set_current_screen( 'profile' );
		do_action( 'admin_enqueue_scripts', 'profile.php' );
		$this->assertTrue( wp_script_is( 'silver-assist-password-validation', 'enqueued' ), 'on the profile screen' );
		$this->assertTrue( wp_script_is( 'password-strength-meter', 'enqueued' ) );

		wp_dequeue_script( 'silver-assist-password-validation' );
		wp_dequeue_script( 'password-strength-meter' );
		update_option( 'silver_assist_password_strength_enforcement', 0 );

		set_current_screen( 'user' );
		do_action( 'admin_enqueue_scripts', 'user-new.php' );
		$this->assertFalse( wp_script_is( 'silver-assist-password-validation', 'enqueued' ), 'nothing loads when enforcement is off' );
	}

	// ---------------------------------------------------------------------
	// G11: PHP session cookie parameters.
	// ---------------------------------------------------------------------

	/**
	 * Run `configure_secure_cookies()` in a fresh PHP process and read the session cookie parameters
	 *
	 * The method does nothing once output has started (`headers_sent()`), and PHPUnit has printed
	 * its banner by the time a test runs, so it can only be observed in a clean process.
	 *
	 * @param bool $https Whether the request is HTTPS.
	 * @return array{before: array<string, mixed>, after: array<string, mixed>} Cookie parameters before and after.
	 */
	private function session_cookie_params_after_configuring( bool $https ): array {
		$autoload = var_export( SILVER_ASSIST_SECURITY_PATH . 'vendor/autoload.php', true );
		$script   = '<?php function is_ssl() { return ' . ( $https ? 'true' : 'false' ) . '; }'
			. ' require ' . $autoload . ';'
			. ' $before = session_get_cookie_params();'
			. ' $general = ( new ReflectionClass( \\SilverAssist\\Security\\Security\\GeneralSecurity::class ) )->newInstanceWithoutConstructor();'
			. ' $general->configure_secure_cookies();'
			. ' echo json_encode( array( "before" => $before, "after" => session_get_cookie_params() ) );';

		$file = tempnam( sys_get_temp_dir(), 'sas-cookie-' );
		file_put_contents( (string) $file, $script ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_put_contents_file_put_contents -- Test fixture.
		$output = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' -d session.cookie_httponly=0 -d session.cookie_samesite= ' . escapeshellarg( (string) $file ) . ' 2>&1' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec -- Needs a clean process.
		unlink( (string) $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Test cleanup.

		$decoded = json_decode( $output, true );
		$this->assertIsArray( $decoded, 'the child process answered: ' . $output );

		return $decoded;
	}

	/**
	 * PHP sessions get HttpOnly and SameSite=Lax cookies, Secure only over HTTPS
	 *
	 * @return void
	 */
	public function test_session_cookies_are_httponly_and_samesite_lax(): void {
		$plain = $this->session_cookie_params_after_configuring( false );
		$this->assertFalse( $plain['before']['httponly'], 'control: PHP starts without HttpOnly' );
		$this->assertTrue( $plain['after']['httponly'] );
		$this->assertSame( 'Lax', $plain['after']['samesite'] );
		$this->assertFalse( $plain['after']['secure'], 'a Secure cookie over plain HTTP would never come back' );

		$secure = $this->session_cookie_params_after_configuring( true );
		$this->assertTrue( $secure['after']['secure'] );
	}

	// ---------------------------------------------------------------------
	// G12: residuals.
	// ---------------------------------------------------------------------

	/**
	 * Previous and next post links are not printed in the head of a single post
	 *
	 * @return void
	 */
	public function test_head_has_no_adjacent_post_relation_links(): void {
		$first  = self::factory()->post->create( array( 'post_date' => '2024-01-01 10:00:00' ) );
		$second = self::factory()->post->create( array( 'post_date' => '2024-02-01 10:00:00' ) );
		$third  = self::factory()->post->create( array( 'post_date' => '2024-03-01 10:00:00' ) );
		unset( $first, $third );

		// Control: core's own hook prints them for a post that has neighbours.
		add_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10, 0 );
		$this->go_to( get_permalink( $second ) );
		ob_start();
		do_action( 'wp_head' );
		$control = (string) ob_get_clean();
		$this->assertMatchesRegularExpression( "/rel='(prev|next)'/", $control, 'control: core prints prev and next links' );

		( new GeneralSecurity() )->remove_unnecessary_headers();
		ob_start();
		do_action( 'wp_head' );
		$head = (string) ob_get_clean();

		$this->assertDoesNotMatchRegularExpression( "/rel='(prev|next|start|up|index)'/", $head );
	}

	/**
	 * A pretty author archive URL sends the visitor home
	 *
	 * @return void
	 */
	public function test_pretty_author_archive_redirects_home(): void {
		$this->set_permalink_structure( '/%postname%/' );
		$author = self::factory()->user->create( array( 'user_login' => 'maria-lopez', 'role' => 'author' ) );
		self::factory()->post->create( array( 'post_author' => $author ) );

		$this->go_to( home_url( '/author/maria-lopez/' ) );
		$this->assertTrue( is_author(), 'control: the request is an author archive' );

		$redirect = $this->capture_redirect(
			static function (): void {
				do_action( 'template_redirect' );
			}
		);

		$this->assertSame( home_url(), $redirect );
	}

	/**
	 * Logging out clears the lockout counters of the visitor's IP
	 *
	 * @return void
	 */
	public function test_logout_clears_the_login_counters(): void {
		$_SERVER['REMOTE_ADDR'] = '198.51.100.55';
		$attempts_key           = SecurityHelper::generate_ip_transient_key( 'login_attempts', '198.51.100.55' );
		$lockout_key            = SecurityHelper::generate_ip_transient_key( 'lockout', '198.51.100.55' );
		set_transient( $attempts_key, 3, HOUR_IN_SECONDS );
		set_transient( $lockout_key, time() + 600, HOUR_IN_SECONDS );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		wp_logout();

		$this->assertFalse( get_transient( $attempts_key ) );
		$this->assertFalse( get_transient( $lockout_key ) );
	}

	/**
	 * With admin hiding on, the short URLs /login and /admin no longer lead to the real admin
	 *
	 * @return void
	 */
	public function test_short_urls_do_not_reveal_the_admin_when_hiding_is_on(): void {
		$this->set_permalink_structure( '/%postname%/' );

		// Control: core redirects /login and /admin to the real screens.
		add_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
		foreach ( array( 'login', 'admin' ) as $slug ) {
			$this->go_to( home_url( '/' . $slug . '/' ) );
			$this->assertNotNull(
				$this->capture_redirect(
					static function (): void {
						do_action( 'template_redirect' );
					}
				),
				"control: core redirects /{$slug}/"
			);
		}

		update_option( 'silver_assist_admin_hide_enabled', 1 );
		update_option( 'silver_assist_admin_hide_path', 'silver-admin' );
		new AdminHideSecurity();

		foreach ( array( 'login', 'admin' ) as $slug ) {
			$this->go_to( home_url( '/' . $slug . '/' ) );
			$this->assertTrue( is_404(), "/{$slug}/ is a normal 404" );
			$this->assertNull(
				$this->capture_redirect(
					static function (): void {
						do_action( 'template_redirect' );
					}
				),
				"/{$slug}/ does not redirect to the admin"
			);
		}
	}

	/**
	 * Run code and return the URL it tried to redirect to
	 *
	 * @param callable $run Code to run.
	 * @return string|null Redirect location, or null when nothing redirected.
	 */
	private function capture_redirect( callable $run ): ?string {
		$location = null;
		$catcher  = static function ( $url ) {
			throw new \RuntimeException( 'redirect:' . $url ); // Stops the exit() that follows the redirect.
		};
		add_filter( 'wp_redirect', $catcher );

		try {
			$run();
		} catch ( \RuntimeException $e ) {
			$location = substr( $e->getMessage(), strlen( 'redirect:' ) );
		}

		remove_filter( 'wp_redirect', $catcher );
		return $location;
	}
}
