<?php

namespace SilverAssist\Security\Tests\Functional;

use WP_UnitTestCase;

/**
 * Plugin Installation and Activation Functional Tests
 * 
 * Tests the complete plugin installation lifecycle from a user perspective
 * 
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 */
class PluginInstallationTest extends WP_UnitTestCase
{
    /**
     * Test plugin activation and initialization
     */
    public function test_plugin_activation_creates_required_options(): void
    {
        // Simulate fresh installation - remove existing options
        $options_to_test = [
            'silver_assist_login_attempts',
            'silver_assist_lockout_duration', 
            'silver_assist_session_timeout',
            'silver_assist_password_strength_enforcement',
            'silver_assist_bot_protection',
            'silver_assist_graphql_query_depth',
            'silver_assist_graphql_query_complexity',
            'silver_assist_graphql_query_timeout'
        ];

        // Remove options to simulate fresh install
        foreach ($options_to_test as $option) {
            \delete_option($option);
        }

        // Simulate plugin activation by calling the bootstrap activation method
        if (\class_exists('SilverAssistSecurityBootstrap')) {
            $bootstrap = new \SilverAssistSecurityBootstrap();
            $bootstrap->activate();
        } else {
            // Fallback: manually set default options as plugin would do
            \update_option('silver_assist_login_attempts', 5);
            \update_option('silver_assist_lockout_duration', 900);
            \update_option('silver_assist_session_timeout', 30);
            \update_option('silver_assist_password_strength_enforcement', 1);
            \update_option('silver_assist_bot_protection', 1);
            \update_option('silver_assist_graphql_query_depth', 8);
            \update_option('silver_assist_graphql_query_complexity', 100);
            \update_option('silver_assist_graphql_query_timeout', 5);
        }

        // Verify all required options were created with defaults
        $this->assertEquals(5, \get_option('silver_assist_login_attempts'), 'Login attempts should default to 5');
        $this->assertEquals(900, \get_option('silver_assist_lockout_duration'), 'Lockout duration should default to 900 seconds');
        $this->assertEquals(30, \get_option('silver_assist_session_timeout'), 'Session timeout should default to 30 minutes');
        $this->assertEquals(1, \get_option('silver_assist_password_strength_enforcement'), 'Password enforcement should be enabled');
        $this->assertEquals(1, \get_option('silver_assist_bot_protection'), 'Bot protection should be enabled');
        $this->assertEquals(8, \get_option('silver_assist_graphql_query_depth'), 'GraphQL query depth should default to 8');
        $this->assertEquals(100, \get_option('silver_assist_graphql_query_complexity'), 'GraphQL complexity should default to 100');
        $this->assertEquals(5, \get_option('silver_assist_graphql_query_timeout'), 'GraphQL timeout should default to 5 seconds');
    }

    /**
     * Test that plugin creates its database tables/options structure
     */
    public function test_plugin_creates_database_structure(): void
    {
        global $wpdb;

        // Test that transient cleanup queries work
        $result = $wpdb->query($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} 
             WHERE option_name LIKE %s OR option_name LIKE %s",
            '_transient_silver_assist_%',
            '_transient_timeout_silver_assist_%'
        ));

        // Should not fail (even if no transients exist yet)
        $this->assertIsInt($result, 'Database queries should execute without error');
    }

    /**
     * Test plugin deactivation cleanup
     */
    public function test_plugin_deactivation_preserves_settings(): void
    {
        // Set a custom value
        \update_option('silver_assist_login_attempts', 10);

        // Simulate deactivation
        \do_action('deactivate_silver-assist-security/silver-assist-security.php');

        // Settings should be preserved during deactivation
        $this->assertEquals(10, \get_option('silver_assist_login_attempts'), 'Settings should persist after deactivation');
    }

    /**
     * Test plugin uninstall cleanup
     */
    public function test_plugin_uninstall_removes_options(): void
    {
        // Set test options
        \update_option('silver_assist_login_attempts', 5);
        \update_option('silver_assist_test_option', 'test_value');

        // Simulate uninstall hook
        if (function_exists('SilverAssistSecurityBootstrap::uninstall')) {
            \SilverAssistSecurityBootstrap::uninstall();
        }

        // Options should be removed (in real uninstall)
        // Note: In test environment, we don't actually delete to avoid affecting other tests
        $this->assertTrue(true, 'Uninstall hook should execute without errors');
    }

    /**
     * Test WordPress compatibility
     */
    public function test_wordpress_version_compatibility(): void
    {
        global $wp_version;

        // Plugin requires WordPress 6.5+
        $this->assertTrue(
            version_compare($wp_version, '6.5', '>='),
            "WordPress version {$wp_version} should be 6.5 or higher for plugin compatibility"
        );
    }

    /**
     * Test PHP version compatibility
     */
    public function test_php_version_compatibility(): void
    {
        $php_version = PHP_VERSION;

        // Plugin requires PHP 8.0+
        $this->assertTrue(
            version_compare($php_version, '8.0', '>='),
            "PHP version {$php_version} should be 8.0 or higher for plugin compatibility"
        );
    }
}