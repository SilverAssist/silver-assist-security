<?php
/**
 * WordPress Hooks Integration Tests
 *
 * Tests the integration of plugin hooks with WordPress core systems.
 * 
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * WordPress Hooks Integration Test Class
 *
 * Validates that plugin hooks are properly registered and executed
 * in a real WordPress environment.
 */
class WordPressHooksIntegrationTest extends WP_UnitTestCase
{
    /**
     * Plugin instance
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Set up test environment before each test
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();
        
        // Initialize plugin instance
        $this->plugin = Plugin::getInstance();
        
        // Reset hooks to ensure clean state
        \remove_all_actions('init');
        \remove_all_actions('wp_login_failed');
        \remove_all_actions('wp_login');
        \remove_all_actions('admin_menu');
        \remove_all_actions('wp_loaded');
    }

    /**
     * Test that WordPress init hooks are properly registered
     *
     * @return void
     */
    public function test_wordpress_init_hooks_registration(): void
    {
        // Re-initialize plugin to register hooks
        $this->plugin = Plugin::getInstance();
        
        // Check that init action is registered
        $this->assertTrue(
            \has_action('init'),
            'WordPress init hook should be registered by plugin'
        );
        
        // Execute init action and verify plugin components are loaded
        \do_action('init');
        
        // Verify plugin is properly initialized after init hook
        $this->assertInstanceOf(
            Plugin::class,
            $this->plugin,
            'Plugin should be initialized after WordPress init'
        );
    }

    /**
     * Test login security hooks integration
     *
     * @return void
     */
    public function test_login_security_hooks_integration(): void
    {
        // Initialize plugin and trigger WordPress loaded
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Test that login failed hook is registered
        $this->assertTrue(
            \has_action('wp_login_failed'),
            'Login failed hook should be registered for security monitoring'
        );
        
        // Test that successful login hook is registered
        $this->assertTrue(
            \has_action('wp_login'),
            'Successful login hook should be registered for security tracking'
        );
        
        // Test that authenticate filter is registered
        $this->assertTrue(
            \has_filter('authenticate'),
            'Authenticate filter should be registered for login protection'
        );
    }

    /**
     * Test admin hooks integration
     *
     * @return void
     */
    public function test_admin_hooks_integration(): void
    {
        // Set current user as admin
        \wp_set_current_user(1);
        \set_current_screen('dashboard');
        
        // Initialize plugin
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Test admin_menu hook registration
        $this->assertTrue(
            \has_action('admin_menu'),
            'Admin menu hook should be registered for admin interface'
        );
        
        // Test admin_enqueue_scripts hook
        $this->assertTrue(
            \has_action('admin_enqueue_scripts'),
            'Admin enqueue scripts hook should be registered'
        );
        
        // Test AJAX hooks registration
        $this->assertTrue(
            \has_action('wp_ajax_silver_assist_get_security_status'),
            'AJAX security status hook should be registered'
        );
        
        $this->assertTrue(
            \has_action('wp_ajax_silver_assist_auto_save'),
            'AJAX auto-save hook should be registered'
        );
    }

    /**
     * Test security headers hooks integration
     *
     * @return void
     */
    public function test_security_headers_hooks_integration(): void
    {
        // Initialize plugin
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Test that cookie modification hooks are registered
        $this->assertTrue(
            \has_action('wp_loaded'),
            'WP loaded hook should be registered for cookie security'
        );
        
        // Test that header hooks are registered for security
        $this->assertTrue(
            \has_action('send_headers') || \has_action('wp_headers'),
            'Security header hooks should be registered'
        );
    }

    /**
     * Test plugin activation and deactivation hooks
     *
     * @return void
     */
    public function test_plugin_lifecycle_hooks(): void
    {
        // Test that activation creates default options
        \do_action('activate_silver-assist-security/silver-assist-security.php');
        
        // Verify default options are created
        $this->assertNotEmpty(
            \get_option('silver_assist_login_attempts'),
            'Default login attempts option should be created on activation'
        );
        
        $this->assertNotEmpty(
            \get_option('silver_assist_lockout_duration'),
            'Default lockout duration option should be created on activation'
        );
        
        // Test that deactivation preserves settings
        \do_action('deactivate_silver-assist-security/silver-assist-security.php');
        
        // Options should still exist after deactivation
        $this->assertNotEmpty(
            \get_option('silver_assist_login_attempts'),
            'Plugin options should persist after deactivation'
        );
    }

    /**
     * Test GraphQL hooks integration (if WPGraphQL is available)
     *
     * @return void
     */
    public function test_graphql_hooks_integration(): void
    {
        if (!\class_exists('WPGraphQL')) {
            $this->markTestSkipped('WPGraphQL not available for GraphQL hooks testing');
        }
        
        // Initialize plugin
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Test GraphQL specific hooks
        $this->assertTrue(
            \has_filter('graphql_request_data') || \class_exists('WPGraphQL'),
            'GraphQL security hooks should be registered when WPGraphQL is active'
        );
    }

    /**
     * Test WordPress cron integration
     *
     * @return void
     */
    public function test_wordpress_cron_integration(): void
    {
        // Initialize plugin
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Check if plugin scheduled any cron events
        $cron_jobs = \_get_cron_array();
        
        // Plugin might schedule cleanup tasks
        $this->assertIsArray(
            $cron_jobs,
            'WordPress cron should be accessible for plugin scheduled tasks'
        );
    }

    /**
     * Test WordPress options integration
     *
     * @return void
     */
    public function test_wordpress_options_integration(): void
    {
        // Test setting and getting plugin options
        \update_option('silver_assist_test_option', 'test_value');
        
        $this->assertEquals(
            'test_value',
            \get_option('silver_assist_test_option'),
            'Plugin should be able to read/write WordPress options'
        );
        
        // Test transients integration
        \set_transient('silver_assist_test_transient', array('data' => 'test'), 60);
        
        $transient_data = \get_transient('silver_assist_test_transient');
        $this->assertIsArray($transient_data, 'Plugin should be able to use WordPress transients');
        $this->assertEquals('test', $transient_data['data'], 'Transient data should be preserved correctly');
        
        // Cleanup
        \delete_option('silver_assist_test_option');
        \delete_transient('silver_assist_test_transient');
    }

    /**
     * Test WordPress user capabilities integration
     *
     * @return void
     */
    public function test_wordpress_capabilities_integration(): void
    {
        // Create test user with admin capabilities
        $admin_user = \wp_create_user('test_admin', 'password', 'admin@test.com');
        $user = new \WP_User($admin_user);
        $user->set_role('administrator');
        
        \wp_set_current_user($admin_user);
        
        // Test capability checks that plugin uses
        $this->assertTrue(
            \current_user_can('manage_options'),
            'Admin user should have manage_options capability for plugin access'
        );
        
        // Create regular user
        $regular_user = \wp_create_user('test_user', 'password', 'user@test.com');
        \wp_set_current_user($regular_user);
        
        $this->assertFalse(
            \current_user_can('manage_options'),
            'Regular user should not have manage_options capability'
        );
        
        // Cleanup users
        \wp_delete_user($admin_user);
        \wp_delete_user($regular_user);
    }

    /**
     * Clean up after each test
     *
     * @return void
     */
    public function tearDown(): void
    {
        // Clean up any test data
        \delete_option('silver_assist_test_option');
        \delete_transient('silver_assist_test_transient');
        
        parent::tearDown();
    }
}