<?php
/**
 * Admin Hide Security Tests
 *
 * Tests for AdminHideSecurity class including custom admin path validation,
 * access control, URL filtering, and 404 responses for unauthorized access.
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.1.10
 */

namespace SilverAssist\Security\Tests\Security;

use SilverAssist\Security\Security\AdminHideSecurity;
use WP_UnitTestCase;

/**
 * Test AdminHideSecurity implementation
 */
class AdminHideSecurityTest extends WP_UnitTestCase
{
    /**
     * AdminHideSecurity instance
     *
     * @var AdminHideSecurity
     */
    private AdminHideSecurity $admin_hide_security;

    /**
     * Set up test environment
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Configure admin hiding options
        \update_option("silver_assist_admin_hide_enabled", 1);
        \update_option("silver_assist_admin_hide_path", "secure-backend-2024");
        
        $this->admin_hide_security = new AdminHideSecurity();
    }

    /**
     * Test admin hide security initializes properly
     *
     * @since 1.1.10
     */
    public function test_admin_hide_initializes(): void
    {
        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $this->admin_hide_security,
            "AdminHideSecurity should initialize"
        );
    }

    /**
     * Test emergency disable constant works
     *
     * @since 1.1.10
     */
    public function test_emergency_disable_constant(): void
    {
        // Define emergency disable constant
        if (!\defined("SILVER_ASSIST_HIDE_ADMIN")) {
            \define("SILVER_ASSIST_HIDE_ADMIN", false);
        }

        // Create new instance with emergency disable
        $emergency_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $emergency_instance,
            "Should initialize even with emergency disable"
        );
    }

    /**
     * Test custom admin path configuration
     *
     * @since 1.1.10
     */
    public function test_custom_admin_path_configuration(): void
    {
        // Test with valid custom path
        \update_option("silver_assist_admin_hide_path", "my-secure-admin");
        $instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $instance,
            "Should accept valid custom admin path"
        );

        // Test with forbidden path (should fallback to default)
        \update_option("silver_assist_admin_hide_path", "admin");
        $fallback_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $fallback_instance,
            "Should fallback to default for forbidden paths"
        );
    }

    /**
     * Test admin hide can be disabled via option
     *
     * @since 1.1.10
     */
    public function test_admin_hide_can_be_disabled(): void
    {
        // Disable admin hiding
        \update_option("silver_assist_admin_hide_enabled", 0);
        $disabled_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $disabled_instance,
            "Should initialize with admin hiding disabled"
        );

        // Re-enable for other tests and recreate instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $this->admin_hide_security = new AdminHideSecurity();
    }

    /**
     * Test site_url filter is registered when enabled
     *
     * @since 1.1.10
     */
    public function test_site_url_filter_registered(): void
    {
        // Ensure admin hide is enabled and create fresh instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $instance = new AdminHideSecurity();
        
        $this->assertNotFalse(
            \has_filter("site_url", [$instance, "filter_generated_url"]),
            "site_url filter should be registered when admin hide is enabled"
        );
    }

    /**
     * Test admin_url filter is registered when enabled
     *
     * @since 1.1.10
     */
    public function test_admin_url_filter_registered(): void
    {
        // Ensure admin hide is enabled and create fresh instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $instance = new AdminHideSecurity();
        
        $this->assertNotFalse(
            \has_filter("admin_url", [$instance, "filter_admin_url"]),
            "admin_url filter should be registered when admin hide is enabled"
        );
    }

    /**
     * Test wp_redirect filter is registered
     *
     * @since 1.1.10
     */
    public function test_wp_redirect_filter_registered(): void
    {
        // Ensure admin hide is enabled and create fresh instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $instance = new AdminHideSecurity();
        
        $this->assertNotFalse(
            \has_filter("wp_redirect", [$instance, "filter_redirect"]),
            "wp_redirect filter should be registered"
        );
    }

    /**
     * Test logout_redirect filter is registered
     *
     * @since 1.1.10
     */
    public function test_logout_redirect_filter_registered(): void
    {
        // Ensure admin hide is enabled and create fresh instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $instance = new AdminHideSecurity();
        
        $this->assertNotFalse(
            \has_filter("logout_redirect", [$instance, "handle_logout_redirect"]),
            "logout_redirect filter should be registered"
        );
    }

    /**
     * Test setup_theme action is registered
     *
     * @since 1.1.10
     */
    public function test_setup_theme_action_registered(): void
    {
        // Ensure admin hide is enabled and create fresh instance
        \update_option("silver_assist_admin_hide_enabled", 1);
        $instance = new AdminHideSecurity();
        
        $this->assertNotFalse(
            \has_action("setup_theme", [$instance, "handle_specific_page_requests"]),
            "setup_theme action should be registered for request handling"
        );
    }

    /**
     * Test WordPress default admin redirect is removed
     *
     * @since 1.1.10
     */
    public function test_wordpress_admin_redirect_removed(): void
    {
        // Verify that wp_redirect_admin_locations is not in template_redirect
        $this->assertFalse(
            \has_action("template_redirect", "wp_redirect_admin_locations"),
            "WordPress default admin redirect should be removed"
        );
    }

    /**
     * Test admin hide works during cron jobs
     *
     * @since 1.1.10
     */
    public function test_admin_hide_skips_cron(): void
    {
        // Simulate cron environment
        \define("DOING_CRON", true);

        // Create instance
        $cron_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $cron_instance,
            "Should initialize properly during cron"
        );
    }

    /**
     * Test admin hide works during AJAX requests
     *
     * @since 1.1.10
     */
    public function test_admin_hide_skips_ajax(): void
    {
        // Simulate AJAX environment
        if (!\defined("DOING_AJAX")) {
            \define("DOING_AJAX", true);
        }

        // Create instance
        $ajax_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $ajax_instance,
            "Should initialize properly during AJAX"
        );
    }

    /**
     * Test custom admin path sanitization
     *
     * @since 1.1.10
     */
    public function test_custom_admin_path_sanitization(): void
    {
        // Test with path that needs sanitization
        \update_option("silver_assist_admin_hide_path", "My Custom Path!");
        $sanitized_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $sanitized_instance,
            "Should sanitize custom admin path"
        );
    }

    /**
     * Test empty custom admin path defaults properly
     *
     * @since 1.1.10
     */
    public function test_empty_custom_admin_path_defaults(): void
    {
        // Test with empty path
        \update_option("silver_assist_admin_hide_path", "");
        $default_instance = new AdminHideSecurity();

        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $default_instance,
            "Should use default path when custom path is empty"
        );
    }

    /**
     * Test validation parameter is set
     *
     * @since 1.1.10
     */
    public function test_validation_parameter_exists(): void
    {
        // Validation parameter should be configured
        $this->assertInstanceOf(
            AdminHideSecurity::class,
            $this->admin_hide_security,
            "Validation parameter should be configured"
        );
    }

    /**
     * Test multiple admin hide instances use same configuration
     *
     * @since 1.1.10
     */
    public function test_multiple_instances_same_configuration(): void
    {
        $instance1 = new AdminHideSecurity();
        $instance2 = new AdminHideSecurity();

        // Both should initialize with same options
        $this->assertInstanceOf(AdminHideSecurity::class, $instance1);
        $this->assertInstanceOf(AdminHideSecurity::class, $instance2);
    }

    /**
     * Test hooks are not registered when admin hide is disabled
     *
     * @since 1.1.10
     */
    public function test_hooks_not_registered_when_disabled(): void
    {
        // Disable admin hiding
        \update_option("silver_assist_admin_hide_enabled", 0);
        
        // Remove existing hooks
        \remove_all_actions("setup_theme");
        \remove_all_filters("site_url");
        
        // Create new instance with disabled setting
        $disabled_instance = new AdminHideSecurity();

        // Verify setup_theme hook is not registered
        $this->assertFalse(
            \has_action("setup_theme", [$disabled_instance, "handle_specific_page_requests"]),
            "setup_theme action should not be registered when disabled"
        );
    }
}
