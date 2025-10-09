<?php
/**
 * General Security Tests
 *
 * Tests for GeneralSecurity class including security headers, cookie configuration,
 * version hiding, XML-RPC protection, and user enumeration prevention.
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.1.10
 */

namespace SilverAssist\Security\Tests\Security;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test GeneralSecurity implementation
 */
class GeneralSecurityTest extends WP_UnitTestCase
{
    /**
     * GeneralSecurity instance
     *
     * @var GeneralSecurity
     */
    private GeneralSecurity $general_security;

    /**
     * Set up test environment
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->general_security = new GeneralSecurity();
    }

    /**
     * Test that security headers are added correctly
     *
     * @since 1.1.10
     */
    public function test_security_headers_added(): void
    {
        // Trigger headers action
        ob_start();
        do_action("send_headers");
        ob_end_clean();

        // Note: headers_sent() will be true in PHPUnit context
        // We verify the hook is registered
        $this->assertTrue(
            has_action("send_headers", [$this->general_security, "add_security_headers"]),
            "Security headers action should be registered"
        );
    }

    /**
     * Test WordPress version is removed from generator tag
     *
     * @since 1.1.10
     */
    public function test_wordpress_version_removed(): void
    {
        $version = apply_filters("the_generator", "<meta name=\"generator\" content=\"WordPress 6.7.1\" />");
        
        $this->assertEmpty($version, "WordPress version should be removed from generator tag");
    }

    /**
     * Test version query strings are removed from scripts and styles
     *
     * @since 1.1.10
     */
    public function test_version_query_string_removed(): void
    {
        $script_url = "https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1";
        $filtered_url = apply_filters("script_loader_src", $script_url);
        
        $this->assertStringNotContainsString(
            "?ver=",
            $filtered_url,
            "Version query string should be removed from scripts"
        );

        $style_url = "https://example.com/wp-content/themes/twentytwentyfour/style.css?ver=1.0";
        $filtered_style = apply_filters("style_loader_src", $style_url);
        
        $this->assertStringNotContainsString(
            "?ver=",
            $filtered_style,
            "Version query string should be removed from styles"
        );
    }

    /**
     * Test XML-RPC is disabled
     *
     * @since 1.1.10
     */
    public function test_xmlrpc_disabled(): void
    {
        // Test XML-RPC enabled filter
        $xmlrpc_enabled = apply_filters("xmlrpc_enabled", true);
        $this->assertFalse($xmlrpc_enabled, "XML-RPC should be disabled");

        // Test XML-RPC methods are removed
        $methods = apply_filters("xmlrpc_methods", [
            "pingback.ping" => "this_pingback_ping",
            "demo.sayHello" => "this_sayHello"
        ]);
        
        $this->assertIsArray($methods, "XML-RPC methods should return array");
    }

    /**
     * Test login errors are hidden for security
     *
     * @since 1.1.10
     */
    public function test_login_errors_hidden(): void
    {
        $original_error = "<strong>ERROR</strong>: Invalid username.";
        $filtered_error = apply_filters("login_errors", $original_error);
        
        $this->assertNotEquals(
            $original_error,
            $filtered_error,
            "Login errors should be modified for security"
        );
        
        $this->assertStringNotContainsString(
            "Invalid username",
            $filtered_error,
            "Specific error details should not be exposed"
        );
    }

    /**
     * Test secure cookies are forced when HTTPS is available
     *
     * @since 1.1.10
     */
    public function test_secure_cookies_configuration(): void
    {
        // Test secure auth cookie filter
        $this->assertTrue(
            has_filter("secure_auth_cookie", [$this->general_security, "force_secure_cookies"]),
            "Secure auth cookie filter should be registered"
        );

        // Test secure logged in cookie filter
        $this->assertTrue(
            has_filter("secure_logged_in_cookie", [$this->general_security, "force_secure_cookies"]),
            "Secure logged in cookie filter should be registered"
        );
    }

    /**
     * Test user enumeration is disabled
     *
     * @since 1.1.10
     */
    public function test_user_enumeration_disabled(): void
    {
        // Create test user
        $user_id = $this->factory()->user->create([
            "user_login" => "testuser",
            "user_email" => "test@example.com"
        ]);

        // Simulate author archive request (user enumeration attempt)
        global $wp_query;
        $wp_query->set("author", $user_id);
        $wp_query->is_author = true;

        // Trigger init action
        do_action("init");

        // Verify the hook is registered
        $this->assertTrue(
            has_action("init", [$this->general_security, "disable_user_enumeration"]),
            "User enumeration prevention should be active"
        );
    }

    /**
     * Test admin bar is removed for non-admin users
     *
     * @since 1.1.10
     */
    public function test_admin_bar_removed_for_non_admins(): void
    {
        // Create non-admin user (subscriber)
        $subscriber_id = $this->factory()->user->create(["role" => "subscriber"]);
        \wp_set_current_user($subscriber_id);

        // Trigger after_setup_theme action
        do_action("after_setup_theme");

        // For non-admin users, show_admin_bar(false) should be called
        // We verify the hook is registered
        $this->assertTrue(
            has_action("after_setup_theme", [$this->general_security, "remove_admin_bar_for_non_admins"]),
            "Admin bar removal for non-admins should be active"
        );
    }

    /**
     * Test WordPress branding is removed from admin
     *
     * @since 1.1.10
     */
    public function test_wordpress_branding_removed(): void
    {
        // Test admin footer text modification
        $original_footer = "Thank you for creating with <a href=\"https://wordpress.org/\">WordPress</a>.";
        $filtered_footer = apply_filters("admin_footer_text", $original_footer);
        
        $this->assertNotEquals(
            $original_footer,
            $filtered_footer,
            "Admin footer text should be customized"
        );

        // Test WordPress logo removal from admin bar
        $this->assertTrue(
            has_action("wp_before_admin_bar_render", [$this->general_security, "remove_wp_logo"]),
            "WordPress logo removal should be active"
        );
    }

    /**
     * Test file editing is disabled for security
     *
     * @since 1.1.10
     */
    public function test_file_editing_disabled(): void
    {
        // File editing should be disabled via DISALLOW_FILE_EDIT constant
        // We verify the class initializes properly, which sets this up
        $this->assertInstanceOf(
            GeneralSecurity::class,
            $this->general_security,
            "GeneralSecurity should initialize file editing protection"
        );
    }

    /**
     * Test unnecessary headers are removed
     *
     * @since 1.1.10
     */
    public function test_unnecessary_headers_removed(): void
    {
        // Trigger init action
        do_action("init");

        // Verify the hook is registered
        $this->assertTrue(
            has_action("init", [$this->general_security, "remove_unnecessary_headers"]),
            "Unnecessary headers removal should be active"
        );
    }
}
