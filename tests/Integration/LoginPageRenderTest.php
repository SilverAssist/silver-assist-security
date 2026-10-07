<?php
/**
 * Rendered wp-login.php with and without the plugin's login branding
 *
 * Renders the real core `wp-login.php` (a copy next to an empty `wp-load.php`, because WordPress is
 * already loaded by the test bootstrap and the test installation has no `wp-config.php`) and asserts
 * the HTML a visitor receives: branding stylesheet, body classes, logo link and text, page title,
 * illustration panel, custom logo and background color; and none of it when branding is off (#154, G6).
 *
 * `wp-login.php` declares functions, so every render runs in its own PHP process.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\LoginBranding;
use WP_UnitTestCase;

/**
 * Login page rendering tests
 */
class LoginPageRenderTest extends WP_UnitTestCase {

	/**
	 * Directory holding the copy of wp-login.php
	 *
	 * @var string
	 */
	private string $dir = '';

	/**
	 * Remove the temporary copy
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		if ( '' !== $this->dir ) {
			foreach ( array( 'wp-login.php', 'wp-load.php' ) as $file ) {
				if ( file_exists( $this->dir . '/' . $file ) ) {
					unlink( $this->dir . '/' . $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Test cleanup.
				}
			}
			rmdir( $this->dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Test cleanup.
		}
		parent::tearDown();
	}

	/**
	 * Render the login form and return the page HTML
	 *
	 * @return string
	 */
	private function render_login_page(): string {
		$this->dir = sys_get_temp_dir() . '/sas-login-' . wp_generate_password( 8, false );
		mkdir( $this->dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Temp dir for the test.
		copy( ABSPATH . 'wp-login.php', $this->dir . '/wp-login.php' );
		file_put_contents( $this->dir . '/wp-load.php', "<?php\n// WordPress is already loaded.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_put_contents_file_put_contents -- Test fixture.

		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['REQUEST_URI']    = '/wp-login.php';
		$_SERVER['REMOTE_ADDR']    = '198.51.100.20';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
		// A browser sends these; without them the plugin's login bot protection answers 404.
		$_SERVER['HTTP_ACCEPT']          = 'text/html,application/xhtml+xml';
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
		$_REQUEST                  = array();
		$_GET                      = array();
		$_POST                     = array();
		wp_set_current_user( 0 );

		// wp-login.php is top-level code that expects the global scope and reads variables it never
		// defines on a plain GET; the include below shares this method's scope, so bind them to globals.
		global $user_login, $error, $interim_login, $action;
		$user_login    = '';
		$error         = '';
		$interim_login = false;
		$action        = '';

		ob_start();
		include $this->dir . '/wp-login.php';
		return (string) ob_get_clean();
	}

	/**
	 * Remove the hooks the booted plugin registered for branding (it started with the default setting)
	 *
	 * @return void
	 */
	private function unhook_booted_branding(): void {
		$booted = LoginBranding::instance();
		$map    = array(
			'login_enqueue_scripts' => 'enqueue_login_assets',
			'login_head'            => 'inject_login_head',
			'login_footer'          => 'inject_login_footer',
			'login_headerurl'       => 'custom_login_url',
			'login_headertext'      => 'custom_login_text',
			'login_body_class'      => 'add_body_classes',
			'login_title'           => 'custom_login_title',
		);
		foreach ( $map as $hook => $method ) {
			remove_filter( $hook, array( $booted, $method ), 10 );
		}
	}

	/**
	 * With branding on, the page carries the plugin's styles, layout and logo link
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_login_page_is_branded_by_default(): void {
		$html = $this->render_login_page();

		$this->assertStringContainsString( '<form name="loginform"', $html, 'the login form is still there' );
		$this->assertMatchesRegularExpression( '/<body[^>]*class="[^"]*silver-assist-branded-login/', $html );
		$this->assertMatchesRegularExpression( '/<body[^>]*class="[^"]*silver-assist-split-layout/', $html );
		$this->assertStringContainsString( 'login-branding', $html, 'the branding stylesheet is linked' );
		$this->assertStringContainsString( 'silver-login-illustration-panel', $html, 'the illustration panel is printed' );
		$this->assertStringContainsString( '<a href="' . home_url( '/' ) . '">' . get_bloginfo( 'name' ), $html, 'the logo links to the site home with the site name' );
		$this->assertStringContainsString( '<title>Log In — Silver Assist', html_entity_decode( $html ), 'the page title carries the brand' );
	}

	/**
	 * A configured logo and background color reach the page
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_custom_logo_and_color_are_applied(): void {
		update_option( 'silver_assist_login_branding_logo_url', 'https://cdn.example.org/brand/logo.png' );
		update_option( 'silver_assist_login_branding_bg_color', '#123abc' );
		// The booted plugin read the options before they were set; hook a fresh instance in its place.
		$this->unhook_booted_branding();
		new LoginBranding();

		$html = $this->render_login_page();

		$this->assertStringContainsString( 'background-image: url("https://cdn.example.org/brand/logo.png")', $html );
		$this->assertStringContainsString( '.silver-login-illustration-panel {background: #123abc;}', $html );
	}

	/**
	 * With branding off the page is plain WordPress
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_login_page_is_stock_when_branding_is_off(): void {
		update_option( 'silver_assist_login_branding_enabled', 0 );
		$this->unhook_booted_branding();
		new LoginBranding();

		$html = $this->render_login_page();

		$this->assertStringContainsString( '<form name="loginform"', $html );
		$this->assertStringNotContainsString( 'silver-assist-branded-login', $html );
		$this->assertStringNotContainsString( 'silver-login-illustration-panel', $html );
		$this->assertStringNotContainsString( 'login-branding', $html );
		$this->assertStringNotContainsString( 'Silver Assist', html_entity_decode( (string) preg_replace( '/<title>.*?<\/title>/s', '', $html ) ), 'no brand text outside the title' );
	}
}
