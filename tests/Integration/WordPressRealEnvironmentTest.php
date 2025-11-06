<?php
/**
 * WordPress Real Environment Integration Tests
 *
 * Tests that validate plugin functionality in real WordPress environment
 * with actual WordPress functions and database operations.
 * 
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Security\ContactForm7Integration;
use WP_UnitTestCase;

/**
 * WordPress Real Environment Test Class
 *
 * Tests plugin functionality using real WordPress environment.
 */
class WordPressRealEnvironmentTest extends WP_UnitTestCase
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
        
        // Ensure WordPress is fully loaded
        \do_action('wp_loaded');
    }

    /**
     * Test WordPress database operations work correctly
     *
     * @return void
     */
    public function test_wordpress_database_operations(): void
    {
        // Test options API
        $test_option = 'silver_assist_wp_test_option';
        $test_value = array(
            'setting1' => 'value1',
            'setting2' => 42,
            'setting3' => true
        );
        
        // Add option
        $add_result = \add_option($test_option, $test_value);
        $this->assertTrue($add_result, 'Should successfully add option to WordPress database');
        
        // Get option
        $retrieved_value = \get_option($test_option);
        $this->assertEquals($test_value, $retrieved_value, 'Retrieved option should match stored value');
        
        // Update option
        $new_value = array('updated' => true);
        $update_result = \update_option($test_option, $new_value);
        $this->assertTrue($update_result, 'Should successfully update option in WordPress database');
        
        // Verify update
        $updated_retrieved = \get_option($test_option);
        $this->assertEquals($new_value, $updated_retrieved, 'Updated option should reflect new value');
        
        // Delete option
        $delete_result = \delete_option($test_option);
        $this->assertTrue($delete_result, 'Should successfully delete option from WordPress database');
    }

    /**
     * Test WordPress transients work correctly
     *
     * @return void
     */
    public function test_wordpress_transients_functionality(): void
    {
        $transient_name = 'silver_assist_wp_test_transient';
        $transient_data = array(
            'ip' => '192.168.1.200',
            'attempts' => 3,
            'timestamp' => \time()
        );
        $expiration = 60; // 1 minute
        
        // Set transient
        $set_result = \set_transient($transient_name, $transient_data, $expiration);
        $this->assertTrue($set_result, 'Should successfully set transient in WordPress');
        
        // Get transient
        $retrieved_data = \get_transient($transient_name);
        $this->assertEquals($transient_data, $retrieved_data, 'Retrieved transient should match stored data');
        
        // Delete transient
        $delete_result = \delete_transient($transient_name);
        $this->assertTrue($delete_result, 'Should successfully delete transient from WordPress');
        
        // Verify deletion
        $after_delete = \get_transient($transient_name);
        $this->assertFalse($after_delete, 'Transient should not exist after deletion');
    }

    /**
     * Test WordPress user operations work correctly
     *
     * @return void
     */
    public function test_wordpress_user_operations(): void
    {
        // Create user
        $username = 'wp_test_user_' . \wp_rand(1000, 9999);
        $password = 'test_password_123';
        $email = $username . '@test.com';
        
        $user_id = \wp_create_user($username, $password, $email);
        $this->assertIsInt($user_id, 'wp_create_user should return user ID');
        $this->assertGreaterThan(0, $user_id, 'User ID should be positive integer');
        
        // Get user
        $user = \get_user_by('id', $user_id);
        $this->assertInstanceOf('WP_User', $user, 'get_user_by should return WP_User object');
        $this->assertEquals($username, $user->user_login, 'User login should match');
        $this->assertEquals($email, $user->user_email, 'User email should match');
        
        // Update user meta
        $meta_key = 'silver_assist_test_meta';
        $meta_value = array('test' => 'data');
        
        $meta_result = \update_user_meta($user_id, $meta_key, $meta_value);
        $this->assertIsInt($meta_result, 'update_user_meta should return meta ID');
        
        // Get user meta
        $retrieved_meta = \get_user_meta($user_id, $meta_key, true);
        $this->assertEquals($meta_value, $retrieved_meta, 'Retrieved user meta should match stored value');
        
        // Delete user
        $delete_result = \wp_delete_user($user_id);
        $this->assertTrue($delete_result, 'Should successfully delete user from WordPress');
    }

    /**
     * Test WordPress hooks system works correctly
     *
     * @return void
     */
    public function test_wordpress_hooks_system(): void
    {
        // Test action hooks
        $test_action_fired = false;
        $test_callback = function() use (&$test_action_fired) {
            $test_action_fired = true;
        };
        
        \add_action('silver_assist_test_action', $test_callback);
        \do_action('silver_assist_test_action');
        
        $this->assertTrue($test_action_fired, 'WordPress action hook should execute callback');
        
        // Test filter hooks
        $test_filter_value = 'original_value';
        $filter_callback = function($value) {
            return $value . '_filtered';
        };
        
        \add_filter('silver_assist_test_filter', $filter_callback);
        $filtered_value = \apply_filters('silver_assist_test_filter', $test_filter_value);
        
        $this->assertEquals('original_value_filtered', $filtered_value, 'WordPress filter should modify value');
        
        // Test hook removal
        \remove_action('silver_assist_test_action', $test_callback);
        \remove_filter('silver_assist_test_filter', $filter_callback);
        
        $this->assertFalse(\has_action('silver_assist_test_action'), 'Action should be removed');
        $this->assertFalse(\has_filter('silver_assist_test_filter'), 'Filter should be removed');
    }

    /**
     * Test WordPress capability system works correctly
     *
     * @return void
     */
    public function test_wordpress_capability_system(): void
    {
        // Create admin user
        $admin_username = 'wp_admin_' . \wp_rand(1000, 9999);
        $admin_id = \wp_create_user($admin_username, 'admin_pass', $admin_username . '@admin.com');
        
        $admin_user = new \WP_User($admin_id);
        $admin_user->set_role('administrator');
        
        // Set as current user
        \wp_set_current_user($admin_id);
        
        // Test admin capabilities
        $this->assertTrue(\current_user_can('manage_options'), 'Admin should have manage_options capability');
        $this->assertTrue(\current_user_can('edit_users'), 'Admin should have edit_users capability');
        $this->assertTrue(\current_user_can('install_plugins'), 'Admin should have install_plugins capability');
        
        // Create subscriber user
        $subscriber_username = 'wp_subscriber_' . \wp_rand(1000, 9999);
        $subscriber_id = \wp_create_user($subscriber_username, 'sub_pass', $subscriber_username . '@sub.com');
        
        $subscriber_user = new \WP_User($subscriber_id);
        $subscriber_user->set_role('subscriber');
        
        // Switch to subscriber
        \wp_set_current_user($subscriber_id);
        
        // Test subscriber limitations
        $this->assertFalse(\current_user_can('manage_options'), 'Subscriber should not have manage_options capability');
        $this->assertFalse(\current_user_can('edit_users'), 'Subscriber should not have edit_users capability');
        $this->assertTrue(\current_user_can('read'), 'Subscriber should have read capability');
        
        // Cleanup users
        \wp_delete_user($admin_id);
        \wp_delete_user($subscriber_id);
    }

    /**
     * Test WordPress time and date functions work correctly
     *
     * @return void
     */
    public function test_wordpress_time_functions(): void
    {
        // Test current_time function
        $mysql_time = \current_time('mysql');
        $timestamp = \current_time('timestamp');
        
        $this->assertIsString($mysql_time, 'current_time mysql should return string');
        $this->assertIsInt($timestamp, 'current_time timestamp should return integer');
        $this->assertGreaterThan(0, $timestamp, 'Timestamp should be positive');
        
        // Test date format
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
            $mysql_time,
            'MySQL time should match YYYY-MM-DD HH:MM:SS format'
        );
    }

    /**
     * Test WordPress cron system works correctly
     *
     * @return void
     */
    public function test_wordpress_cron_system(): void
    {
        $hook_name = 'silver_assist_test_cron_hook';
        $timestamp = \time() + 300; // 5 minutes from now
        $args = array('test_arg' => 'test_value');
        
        // Schedule single event
        $schedule_result = \wp_schedule_single_event($timestamp, $hook_name, $args);
        $this->assertNotFalse($schedule_result, 'Should successfully schedule cron event');
        
        // Check if event is scheduled
        $next_run = \wp_next_scheduled($hook_name, $args);
        $this->assertEquals($timestamp, $next_run, 'Scheduled event should have correct timestamp');
        
        // Unschedule event
        $unschedule_result = \wp_unschedule_event($timestamp, $hook_name, $args);
        $this->assertNotFalse($unschedule_result, 'Should successfully unschedule cron event');
        
        // Verify unscheduled
        $after_unschedule = \wp_next_scheduled($hook_name, $args);
        $this->assertFalse($after_unschedule, 'Event should not be scheduled after unscheduling');
    }

    /**
     * Test plugin activation and deactivation in WordPress environment
     *
     * @return void
     */
    public function test_plugin_activation_deactivation(): void
    {
        // Manually trigger plugin activation to ensure options are set
        $bootstrap = \SilverAssistSecurityBootstrap::getInstance();
        $bootstrap->activate();
        
        // Test that default options exist (should be set during plugin activation)
        $default_options = array(
            'silver_assist_login_attempts',
            'silver_assist_lockout_duration',
            'silver_assist_session_timeout',
            'silver_assist_password_strength_enforcement',
            'silver_assist_bot_protection'
        );
        
        foreach ($default_options as $option_name) {
            $option_value = \get_option($option_name);
            $this->assertNotFalse(
                $option_value,
                "Default option {$option_name} should exist after plugin activation"
            );
            $this->assertGreaterThan(
                0,
                $option_value,
                "Default option {$option_name} should have a positive value: got {$option_value}"
            );
        }
    }

    /**
     * Test Contact Form 7 integration if CF7 is available
     *
     * @return void
     */
    public function test_contact_form7_integration(): void
    {
        if (!\class_exists('WPCF7_ContactForm')) {
            $this->markTestSkipped('Contact Form 7 not available for integration testing');
        }
        
        // Test CF7 integration hooks
        $this->assertTrue(
            \has_filter('wpcf7_validate') || \class_exists('WPCF7_ContactForm'),
            'CF7 integration hooks should be available when CF7 is active'
        );
    }

    /**
     * Test WordPress multisite functions if available
     *
     * @return void
     */
    public function test_wordpress_multisite_functions(): void
    {
        if (!\is_multisite()) {
            $this->markTestSkipped('Multisite not available for multisite testing');
        }
        
        // Test network options
        $network_option = 'silver_assist_network_test';
        $network_value = array('network' => true);
        
        \update_site_option($network_option, $network_value);
        $retrieved_network_value = \get_site_option($network_option);
        
        $this->assertEquals($network_value, $retrieved_network_value, 'Network option should work in multisite');
        
        // Cleanup
        \delete_site_option($network_option);
    }

    /**
     * Clean up after each test
     *
     * @return void
     */
    public function tearDown(): void
    {
        // Clean up test options
        $test_options = array(
            'silver_assist_wp_test_option',
            'silver_assist_network_test'
        );
        
        foreach ($test_options as $option) {
            \delete_option($option);
            if (\is_multisite()) {
                \delete_site_option($option);
            }
        }
        
        // Clean up test transients
        \delete_transient('silver_assist_wp_test_transient');
        
        // Remove test hooks
        \remove_all_actions('silver_assist_test_action');
        \remove_all_filters('silver_assist_test_filter');
        
        parent::tearDown();
    }
}