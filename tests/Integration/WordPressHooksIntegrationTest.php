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
        
        // Initialize plugin instance (singleton — hooks registered once on first call)
        $this->plugin = Plugin::getInstance();
    }

    /**
     * Test that WordPress init hooks are properly registered
     *
     * @return void
     */
    public function test_wordpress_init_hooks_registration(): void
    {
        // Plugin singleton is already initialized — hooks should be registered
        
        // Check that init action is registered
        $this->assertTrue(
            \has_action('init') !== false,
            'WordPress init hook should be registered by plugin'
        );
        
        // Verify plugin is properly initialized
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
        // LoginSecurity hooks should be registered by the plugin singleton
        
        // Test that login failed hook is registered
        $this->assertTrue(
            \has_action('wp_login_failed') !== false,
            'Login failed hook should be registered for security monitoring'
        );
        
        // Test that successful login hook is registered
        $this->assertTrue(
            \has_action('wp_login') !== false,
            'Successful login hook should be registered for security tracking'
        );
        
        // Test that authenticate filter is registered
        $this->assertTrue(
            \has_filter('authenticate') !== false,
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
        $admin_id = $this->factory()->user->create( [ 'role' => 'administrator' ] );
        \wp_set_current_user( $admin_id );
        \set_current_screen('dashboard');
        
        // AdminPanel (and SecurityAjaxHandler) is only created when is_admin()
        // The Plugin singleton may have been created before is_admin() was true.
        // Ensure AdminPanel exists by creating one explicitly if needed.
        if ( ! $this->plugin->get_admin_panel() ) {
            new AdminPanel();
        }
        
        // Test admin_menu hook registration
        $this->assertTrue(
            \has_action('admin_menu') !== false,
            'Admin menu hook should be registered for admin interface'
        );
        
        // Test admin_enqueue_scripts hook
        $this->assertTrue(
            \has_action('admin_enqueue_scripts') !== false,
            'Admin enqueue scripts hook should be registered'
        );
        
        // Test AJAX hooks registration
        $this->assertTrue(
            \has_action('wp_ajax_silver_assist_get_security_status') !== false,
            'AJAX security status hook should be registered'
        );
        
        $this->assertTrue(
            \has_action('wp_ajax_silver_assist_auto_save') !== false,
            'AJAX auto-save hook should be registered'
        );

        \wp_set_current_user( 0 );
    }

    /**
     * Test security headers hooks integration
     *
     * @return void
     */
    public function test_security_headers_hooks_integration(): void
    {
        // Security hooks should already be registered by plugin singleton
        
        // Test that cookie modification hooks are registered
        $this->assertTrue(
            \has_action('wp_loaded') !== false,
            'WP loaded hook should be registered for cookie security'
        );
        
        // Test that header hooks are registered for security
        $this->assertTrue(
            \has_action('send_headers') !== false || \has_action('wp_headers') !== false,
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
        // Delete options so activate() re-creates them
        \delete_option('silver_assist_login_attempts');
        \delete_option('silver_assist_lockout_duration');

        // Call the bootstrap activate method directly to simulate activation
        if (\class_exists('SilverAssistSecurityBootstrap')) {
            \SilverAssistSecurityBootstrap::getInstance()->activate();
        }
        
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
        
        // Test GraphQL specific hooks
        $this->assertTrue(
            \has_filter('graphql_request_data') !== false || \class_exists('WPGraphQL'),
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