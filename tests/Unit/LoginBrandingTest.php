<?php
/**
 * Login Branding Unit Tests
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.4.0
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Security\LoginBranding;
use WP_UnitTestCase;

/**
 * Test LoginBranding class
 */
class LoginBrandingTest extends WP_UnitTestCase {

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();

		// Set default options for branding enabled.
		update_option( 'silver_assist_login_branding_enabled', 1 );
		update_option( 'silver_assist_login_branding_logo_url', '' );
		update_option( 'silver_assist_login_branding_bg_color', '' );
		update_option( 'silver_assist_login_branding_show_illustration', 1 );
	}

	/**
	 * Clean up after tests
	 */
	protected function tearDown(): void {
		// Remove all hooks that may have been registered.
		remove_all_filters( 'login_headerurl' );
		remove_all_filters( 'login_headertext' );
		remove_all_filters( 'login_body_class' );
		remove_all_filters( 'login_title' );
		remove_all_actions( 'login_enqueue_scripts' );
		remove_all_actions( 'login_head' );
		remove_all_actions( 'login_footer' );

		parent::tearDown();
	}

	/**
	 * Test constructor initializes properly when enabled
	 */
	public function test_constructor_initializes_when_enabled(): void {
		$branding = new LoginBranding();

		$this->assertInstanceOf( LoginBranding::class, $branding );
		$this->assertTrue( $branding->is_enabled() );
	}

	/**
	 * Test constructor does not register hooks when disabled
	 */
	public function test_hooks_not_registered_when_disabled(): void {
		update_option( 'silver_assist_login_branding_enabled', 0 );

		$branding = new LoginBranding();

		$this->assertFalse( $branding->is_enabled() );
		$this->assertFalse( has_action( 'login_enqueue_scripts', array( $branding, 'enqueue_login_assets' ) ) );
		$this->assertFalse( has_filter( 'login_headerurl', array( $branding, 'custom_login_url' ) ) );
		$this->assertFalse( has_filter( 'login_headertext', array( $branding, 'custom_login_text' ) ) );
	}

	/**
	 * Test hooks registered when enabled
	 */
	public function test_hooks_registered_when_enabled(): void {
		$branding = new LoginBranding();

		$this->assertNotFalse( has_action( 'login_enqueue_scripts', array( $branding, 'enqueue_login_assets' ) ) );
		$this->assertNotFalse( has_filter( 'login_headerurl', array( $branding, 'custom_login_url' ) ) );
		$this->assertNotFalse( has_filter( 'login_headertext', array( $branding, 'custom_login_text' ) ) );
		$this->assertNotFalse( has_action( 'login_head', array( $branding, 'inject_login_head' ) ) );
		$this->assertNotFalse( has_action( 'login_footer', array( $branding, 'inject_login_footer' ) ) );
		$this->assertNotFalse( has_filter( 'login_body_class', array( $branding, 'add_body_classes' ) ) );
		$this->assertNotFalse( has_filter( 'login_title', array( $branding, 'custom_login_title' ) ) );
	}

	/**
	 * Test custom login URL returns home URL
	 */
	public function test_custom_login_url_returns_home_url(): void {
		$branding = new LoginBranding();

		$this->assertEquals( home_url( '/' ), $branding->custom_login_url() );
	}

	/**
	 * Test custom login text contains SVG logo
	 */
	public function test_custom_login_text_contains_svg(): void {
		$branding = new LoginBranding();
		$text     = $branding->custom_login_text();

		$this->assertStringContainsString( '<svg', $text );
		$this->assertStringContainsString( 'silver-logo-icon', $text );
		$this->assertStringContainsString( 'silver-logo-text', $text );
	}

	/**
	 * Test body classes include branded login class
	 */
	public function test_add_body_classes_includes_branded_class(): void {
		$branding = new LoginBranding();
		$classes  = $branding->add_body_classes( array( 'login' ) );

		$this->assertContains( 'silver-assist-branded-login', $classes );
	}

	/**
	 * Test body classes include split layout when illustration enabled
	 */
	public function test_add_body_classes_includes_split_layout(): void {
		update_option( 'silver_assist_login_branding_show_illustration', 1 );

		$branding = new LoginBranding();
		$classes  = $branding->add_body_classes( array( 'login' ) );

		$this->assertContains( 'silver-assist-split-layout', $classes );
	}

	/**
	 * Test body classes exclude split layout when illustration disabled
	 */
	public function test_add_body_classes_excludes_split_layout_when_disabled(): void {
		update_option( 'silver_assist_login_branding_show_illustration', 0 );

		$branding = new LoginBranding();
		$classes  = $branding->add_body_classes( array( 'login' ) );

		$this->assertContains( 'silver-assist-branded-login', $classes );
		$this->assertNotContains( 'silver-assist-split-layout', $classes );
	}

	/**
	 * Test custom login title format
	 */
	public function test_custom_login_title(): void {
		$branding = new LoginBranding();
		$title    = $branding->custom_login_title( 'Log In &lsaquo; Test Site', 'Log In' );

		$this->assertEquals( 'Log In &mdash; Silver Assist', $title );
	}

	/**
	 * Test get_logo_svg returns valid SVG
	 */
	public function test_get_logo_svg_returns_svg(): void {
		$branding = new LoginBranding();
		$svg      = $branding->get_logo_svg();

		$this->assertStringContainsString( '<svg', $svg );
		$this->assertStringContainsString( '</svg>', $svg );
		$this->assertStringContainsString( '#00D1FF', $svg );
	}

	/**
	 * Test inject_login_footer outputs illustration panel
	 */
	public function test_inject_login_footer_outputs_illustration(): void {
		update_option( 'silver_assist_login_branding_show_illustration', 1 );

		$branding = new LoginBranding();

		ob_start();
		$branding->inject_login_footer();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'silver-login-illustration-panel', $output );
		$this->assertStringContainsString( 'silver-login-illustration-watermark', $output );
	}

	/**
	 * Test inject_login_footer does not output when illustration disabled
	 */
	public function test_inject_login_footer_empty_when_illustration_disabled(): void {
		update_option( 'silver_assist_login_branding_show_illustration', 0 );

		$branding = new LoginBranding();

		ob_start();
		$branding->inject_login_footer();
		$output = ob_get_clean();

		$this->assertStringNotContainsString( 'silver-login-illustration-panel', $output );
	}

	/**
	 * Test inject_login_head is a no-op (dynamic styles via wp_add_inline_style)
	 */
	public function test_inject_login_head_outputs_nothing_with_custom_logo(): void {
		update_option( 'silver_assist_login_branding_logo_url', 'https://example.com/logo.png' );

		$branding = new LoginBranding();

		ob_start();
		$branding->inject_login_head();
		$output = ob_get_clean();

		$this->assertEmpty( trim( $output ) );
	}

	/**
	 * Test inject_login_head outputs nothing when no custom logo
	 */
	public function test_inject_login_head_empty_without_custom_logo(): void {
		update_option( 'silver_assist_login_branding_logo_url', '' );

		$branding = new LoginBranding();

		ob_start();
		$branding->inject_login_head();
		$output = ob_get_clean();

		$this->assertEmpty( trim( $output ) );
	}

	/**
	 * Test custom background color is applied via wp_add_inline_style
	 */
	public function test_custom_bg_color_applied(): void {
		update_option( 'silver_assist_login_branding_bg_color', '#1a2b3c' );
		update_option( 'silver_assist_login_branding_show_illustration', 1 );

		$branding = new LoginBranding();

		// Footer no longer contains inline style; bg color is in wp_add_inline_style.
		ob_start();
		$branding->inject_login_footer();
		$output = ob_get_clean();

		// Footer should have the panel markup but NOT the color inline.
		$this->assertStringContainsString( 'silver-login-illustration-panel', $output );
		$this->assertStringNotContainsString( 'style=', $output );
	}
}
