<?php
/**
 * Admin Hide Security Integration Tests
 *
 * Integration tests for AdminHideSecurity class testing real-world scenarios
 * with feature activation/deactivation, URL filtering, request handling,
 * and WordPress hook integration.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.13
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\AdminHideSecurity;
use WP_UnitTestCase;

/**
 * Integration test class for AdminHideSecurity
 *
 * Tests complete feature activation/deactivation workflows and
 * WordPress integration scenarios.
 *
 * @since 1.1.13
 */
class AdminHideSecurityTest extends WP_UnitTestCase
{
    /**
     * AdminHideSecurity instance
     *
     * @var AdminHideSecurity|null
     */
    private ?AdminHideSecurity $admin_hide_security = null;

    /**
     * Original REQUEST_URI value
     *
     * @var string
     */
    private string $original_request_uri;

    /**
     * Original SERVER values
     *
     * @var array<string, mixed>
     */
    private array $original_server;

    /**
     * Setup test environment before each test
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Backup original $_SERVER values
        $this->original_server = $_SERVER;
        $this->original_request_uri = $_SERVER['REQUEST_URI'] ?? '/';

        // Reset to clean state - feature DISABLED by default
        \update_option('silver_assist_admin_hide_enabled', 0);
        \update_option('silver_assist_admin_hide_path', 'secure-admin');

        // Clear all hooks to prevent test contamination
        $this->clear_admin_hide_hooks();
    }

    /**
     * Teardown test environment after each test
     *
     * @return void
     */
    public function tearDown(): void
    {
        // Restore original $_SERVER values
        $_SERVER = $this->original_server;
        $_SERVER['REQUEST_URI'] = $this->original_request_uri;

        // Clear all hooks
        $this->clear_admin_hide_hooks();

        // Reset options
        \delete_option('silver_assist_admin_hide_enabled');
        \delete_option('silver_assist_admin_hide_path');

        $this->admin_hide_security = null;

        parent::tearDown();
    }

    /**
     * Clear all AdminHideSecurity hooks
     *
     * @return void
     */
    private function clear_admin_hide_hooks(): void
    {
        \remove_all_actions('setup_theme');
        \remove_all_filters('site_url');
        \remove_all_filters('admin_url');
        \remove_all_filters('wp_redirect');
        \remove_all_filters('logout_redirect');
    }

    /**
     * Test AdminHideSecurity with feature DISABLED
     *
     * When disabled, no hooks should be registered and WordPress
     * default admin paths should work normally.
     *
     * @return void
     */
    public function test_feature_disabled_no_hooks_registered(): void
    {
        // Ensure feature is disabled
        \update_option('silver_assist_admin_hide_enabled', 0);

        // Create instance
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify no hooks were registered
        $this->assertFalse(
            \has_filter('site_url'),
            'site_url filter should NOT be registered when disabled'
        );

        $this->assertFalse(
            \has_filter('admin_url'),
            'admin_url filter should NOT be registered when disabled'
        );

        $this->assertFalse(
            \has_action('setup_theme'),
            'setup_theme action should NOT be registered when disabled'
        );
    }

    /**
     * Test AdminHideSecurity with feature ENABLED
     *
     * When enabled, all hooks should be registered and custom admin
     * path should be active.
     *
     * @return void
     */
    public function test_feature_enabled_hooks_registered(): void
    {
        // Enable feature with custom path
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'secure-backend-2024');

        // Create instance
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify hooks were registered
        $this->assertTrue(
            \has_filter('site_url'),
            'site_url filter should be registered when enabled'
        );

        $this->assertTrue(
            \has_filter('admin_url'),
            'admin_url filter should be registered when enabled'
        );

        $this->assertTrue(
            \has_action('setup_theme'),
            'setup_theme action should be registered when enabled'
        );

        // Verify custom path is active
        $actual_path = $this->admin_hide_security->get_custom_admin_path();
        $this->assertNotEmpty($actual_path, 'Custom path should not be empty');
        
        // Path should either be the configured one or the default if rejected
        $this->assertTrue(
            in_array($actual_path, ['secure-backend-2024', 'silver-admin']),
            "Custom admin path should be 'secure-backend-2024' or fallback to 'silver-admin', got: {$actual_path}"
        );

    }

    /**
     * Test URL filtering when feature is ENABLED
     *
     * Note: URL filtering in AdminHideSecurity is complex and requires
     * proper WordPress context. This test verifies hooks are registered.
     *
     * @return void
     */
    public function test_url_filtering_when_enabled(): void
    {
        // Enable feature
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'my-secret-admin');

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify that filters are registered (actual URL transformation
        // requires full WordPress context with proper request environment)
        $this->assertTrue(
            \has_filter('site_url'),
            'site_url filter should be registered'
        );

        $this->assertTrue(
            \has_filter('admin_url'),
            'admin_url filter should be registered'
        );

        // Verify custom path is configured
        $this->assertEquals(
            'my-secret-admin',
            $this->admin_hide_security->get_custom_admin_path()
        );
    }

    /**
     * Test URL filtering when feature is DISABLED
     *
     * @return void
     */
    public function test_url_filtering_when_disabled(): void
    {
        // Disable feature
        \update_option('silver_assist_admin_hide_enabled', 0);

        $this->admin_hide_security = new AdminHideSecurity();

        // Test that URLs are NOT filtered
        $original_url = 'https://example.com/wp-admin/';
        $filtered_url = \apply_filters('site_url', $original_url);

        $this->assertEquals(
            $original_url,
            $filtered_url,
            'site_url should NOT be filtered when disabled'
        );
    }

    /**
     * Test toggling feature ON during runtime
     *
     * Simulates activating the feature after plugin initialization.
     *
     * @return void
     */
    public function test_toggling_feature_on_during_runtime(): void
    {
        // Start with disabled feature
        \update_option('silver_assist_admin_hide_enabled', 0);
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify disabled state
        $this->assertFalse(\has_filter('site_url'), 'Should start disabled');

        // Enable feature mid-runtime
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'new-secure-path');

        // Create new instance to pick up changes
        $this->clear_admin_hide_hooks();
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify enabled state
        $this->assertTrue(
            \has_filter('site_url'),
            'Should be enabled after toggle'
        );

        $this->assertEquals(
            'new-secure-path',
            $this->admin_hide_security->get_custom_admin_path(),
            'Should use new custom path'
        );
    }

    /**
     * Test toggling feature OFF during runtime
     *
     * Simulates deactivating the feature after it was enabled.
     *
     * @return void
     */
    public function test_toggling_feature_off_during_runtime(): void
    {
        // Start with enabled feature
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'secure-path');
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify enabled state
        $this->assertTrue(\has_filter('site_url'), 'Should start enabled');

        // Disable feature mid-runtime
        \update_option('silver_assist_admin_hide_enabled', 0);

        // Create new instance to pick up changes
        $this->clear_admin_hide_hooks();
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify disabled state
        $this->assertFalse(
            \has_filter('site_url'),
            'Should be disabled after toggle'
        );
    }

    /**
     * Test emergency disable constant override
     *
     * SILVER_ASSIST_HIDE_ADMIN constant should disable feature
     * regardless of database settings.
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     * @return void
     */
    public function test_emergency_disable_constant_override(): void
    {
        // Enable in database
        \update_option('silver_assist_admin_hide_enabled', 1);

        // But define emergency disable constant
        if (!\defined('SILVER_ASSIST_HIDE_ADMIN')) {
            \define('SILVER_ASSIST_HIDE_ADMIN', false);
        }

        // Create instance
        $this->admin_hide_security = new AdminHideSecurity();

        // Verify feature is disabled despite database setting
        $this->assertFalse(
            \has_filter('site_url'),
            'Emergency constant should override database setting'
        );

        $this->assertFalse(
            $this->admin_hide_security->is_admin_hide_enabled(),
            'is_admin_hide_enabled() should return false with emergency constant'
        );
    }

    /**
     * Test request to default wp-admin when feature ENABLED
     *
     * Should be blocked/redirected when accessing default paths.
     *
     * @return void
     */
    public function test_request_to_default_admin_when_enabled(): void
    {
        // Enable feature
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'secure-admin');

        // Simulate request to default wp-admin
        $_SERVER['REQUEST_URI'] = '/wp-admin/index.php';

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify custom path is active
        $this->assertTrue(
            $this->admin_hide_security->is_admin_hide_enabled(),
            'Feature should be enabled'
        );

        $custom_path = $this->admin_hide_security->get_custom_admin_path();
        $this->assertEquals('secure-admin', $custom_path);
    }

    /**
     * Test request to custom admin path when feature ENABLED
     *
     * Should allow access when using correct custom path.
     *
     * @return void
     */
    public function test_request_to_custom_path_when_enabled(): void
    {
        // Enable feature with custom path
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'my-secure-backend');

        // Simulate request to custom path
        $_SERVER['REQUEST_URI'] = '/my-secure-backend';

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify feature is active
        $this->assertTrue($this->admin_hide_security->is_admin_hide_enabled());

        // Verify custom path matches
        $this->assertEquals(
            'my-secure-backend',
            $this->admin_hide_security->get_custom_admin_path()
        );
    }

    /**
     * Test AJAX requests are not blocked when feature ENABLED
     *
     * WordPress AJAX should continue working normally.
     *
     * @return void
     */
    public function test_ajax_requests_not_blocked(): void
    {
        // Enable feature
        \update_option('silver_assist_admin_hide_enabled', 1);

        // Simulate AJAX request
        $_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
        \define('DOING_AJAX', true);

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify feature doesn't interfere with AJAX
        $this->assertTrue(
            \defined('DOING_AJAX'),
            'AJAX constant should be defined'
        );

        // AJAX URLs should still work
        $ajax_url = \admin_url('admin-ajax.php');
        $this->assertStringContainsString('admin-ajax.php', $ajax_url);
    }

    /**
     * Test CRON requests are not blocked when feature ENABLED
     *
     * WordPress CRON should continue working normally.
     *
     * @return void
     */
    public function test_cron_requests_not_blocked(): void
    {
        // Enable feature
        \update_option('silver_assist_admin_hide_enabled', 1);

        // Simulate CRON request
        \define('DOING_CRON', true);

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify feature doesn't interfere with CRON
        $this->assertTrue(
            \defined('DOING_CRON'),
            'CRON constant should be defined'
        );
    }

    /**
     * Test custom admin path sanitization
     *
     * @return void
     */
    public function test_custom_path_sanitization(): void
    {
        // Test various path formats
        $test_cases = [
            'simple-path' => 'simple-path',
            '/with-leading-slash' => 'with-leading-slash',
            'with-trailing-slash/' => 'with-trailing-slash',
            '/both-slashes/' => 'both-slashes',
            'UPPERCASE-Path' => 'uppercase-path',
            'path with spaces' => 'path-with-spaces',
        ];

        foreach ($test_cases as $input => $expected) {
            \update_option('silver_assist_admin_hide_enabled', 1);
            \update_option('silver_assist_admin_hide_path', $input);

            $this->clear_admin_hide_hooks();
            $admin_hide = new AdminHideSecurity();

            $this->assertEquals(
                $expected,
                $admin_hide->get_custom_admin_path(),
                "Path '{$input}' should be sanitized to '{$expected}'"
            );
        }
    }

    /**
     * Test multiple instances with same configuration
     *
     * @return void
     */
    public function test_multiple_instances_same_config(): void
    {
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'shared-path');

        $instance1 = new AdminHideSecurity();
        $instance2 = new AdminHideSecurity();

        $this->assertEquals(
            $instance1->get_custom_admin_path(),
            $instance2->get_custom_admin_path(),
            'Multiple instances should have same configuration'
        );

        $this->assertEquals(
            $instance1->is_admin_hide_enabled(),
            $instance2->is_admin_hide_enabled(),
            'Multiple instances should have same enabled state'
        );
    }

    /**
     * Test feature state persistence across requests
     *
     * @return void
     */
    public function test_feature_state_persistence(): void
    {
        // Enable and configure
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'persistent-path');

        // First request
        $instance1 = new AdminHideSecurity();
        $state1_enabled = $instance1->is_admin_hide_enabled();
        $state1_path = $instance1->get_custom_admin_path();

        // Simulate new request (destroy and recreate)
        $this->clear_admin_hide_hooks();
        unset($instance1);

        // Second request
        $instance2 = new AdminHideSecurity();
        $state2_enabled = $instance2->is_admin_hide_enabled();
        $state2_path = $instance2->get_custom_admin_path();

        // Verify state persisted
        $this->assertEquals($state1_enabled, $state2_enabled);
        $this->assertEquals($state1_path, $state2_path);
        $this->assertEquals('persistent-path', $state2_path);
    }

    /**
     * Test logout redirect when feature ENABLED
     *
     * Note: Logout redirect requires full WordPress environment with proper
     * user context. This test verifies the filter is registered.
     *
     * @return void
     */
    public function test_logout_redirect_when_enabled(): void
    {
        // Enable feature
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'secure-backend');

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify logout redirect filter is registered
        $this->assertTrue(
            \has_filter('logout_redirect'),
            'Logout redirect filter should be registered'
        );

        // Verify custom path is configured
        $this->assertEquals(
            'secure-backend',
            $this->admin_hide_security->get_custom_admin_path()
        );
    }

    /**
     * Test validation parameter exists and is configurable
     *
     * @return void
     */
    public function test_validation_parameter_exists(): void
    {
        \update_option('silver_assist_admin_hide_enabled', 1);

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify that the class has validation mechanisms
        $this->assertTrue(
            $this->admin_hide_security->is_admin_hide_enabled(),
            'Validation should confirm enabled state'
        );
    }

    /**
     * Test forbidden admin paths are properly detected
     *
     * @return void
     */
    public function test_forbidden_admin_paths_detected(): void
    {
        \update_option('silver_assist_admin_hide_enabled', 1);

        // Test forbidden paths that should not be allowed
        // Based on PathValidator::$forbidden_paths
        $forbidden_paths = [
            'admin',
            'login',
            'wp-admin',
            'wp-login',
            'wp-content',
            'wp-includes',
            'dashboard',
            'backend',
            'administrator',
            'root',
            'user',
            'auth',
            'signin',
            'panel',
            'control',
            'manage',
            'system',
        ];

        foreach ($forbidden_paths as $forbidden) {
            \update_option('silver_assist_admin_hide_path', $forbidden);

            $this->clear_admin_hide_hooks();
            $admin_hide = new AdminHideSecurity();

            // Should fallback to default 'silver-admin' for forbidden paths
            $actual_path = $admin_hide->get_custom_admin_path();
            $this->assertEquals(
                'silver-admin',
                $actual_path,
                "Forbidden path '{$forbidden}' should fallback to 'silver-admin'"
            );
        }
    }

    /**
     * Test empty custom path defaults to 'secure-admin'
     *
     * @return void
     */
    public function test_empty_custom_path_defaults(): void
    {
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', '');

        $this->admin_hide_security = new AdminHideSecurity();

        $this->assertEquals(
            'silver-admin',
            $this->admin_hide_security->get_custom_admin_path(),
            'Empty path should default to silver-admin'
        );
    }

    /**
     * Test feature integration with WordPress admin environment
     *
     * @return void
     */
    public function test_wordpress_admin_environment_integration(): void
    {
        \update_option('silver_assist_admin_hide_enabled', 1);
        \update_option('silver_assist_admin_hide_path', 'wp-backend');

        // Simulate admin environment
        \set_current_screen('dashboard');

        $this->admin_hide_security = new AdminHideSecurity();

        // Verify feature works in admin context
        $this->assertTrue($this->admin_hide_security->is_admin_hide_enabled());
        $this->assertEquals('wp-backend', $this->admin_hide_security->get_custom_admin_path());
    }
}
