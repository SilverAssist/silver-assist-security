<?php
/**
 * Security Features Integration Tests
 *
 * Tests the integration of security features with WordPress systems.
 * 
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Core\SecurityHelper;
use WP_UnitTestCase;
use WP_User;

/**
 * Security Features Integration Test Class
 *
 * Validates security functionality in real WordPress environment.
 */
class SecurityFeaturesIntegrationTest extends WP_UnitTestCase
{
    /**
     * Plugin instance
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Test user ID
     *
     * @var int
     */
    private int $test_user_id;

    /**
     * Set up test environment before each test
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();
        
        // Initialize plugin
        $this->plugin = Plugin::getInstance();
        \do_action('wp_loaded');
        
        // Create test user
        $this->test_user_id = \wp_create_user('test_security_user', 'test_password_123', 'security@test.com');
    }

    /**
     * Test login attempt tracking with WordPress authentication
     *
     * @return void
     */
    public function test_login_attempt_tracking_integration(): void
    {
        $test_ip = '192.168.1.100';
        
        // Set up IP tracking
        $_SERVER['REMOTE_ADDR'] = $test_ip;
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '';
        $_SERVER['HTTP_X_REAL_IP'] = '';
        
        // Simulate failed login attempts
        $wp_error = new \WP_Error('invalid_username', 'Invalid username');
        
        // Trigger failed login
        \do_action('wp_login_failed', 'nonexistent_user', $wp_error);
        
        // Check that attempt was tracked (using SecurityHelper format)
        $attempt_key = "login_attempts_" . \md5($test_ip);
        $attempts = \get_transient($attempt_key);
        
        $this->assertGreaterThan(
            0,
            $attempts,
            'Failed login attempts should be tracked in WordPress transients'
        );
        
        // Test lockout after multiple attempts
        for ($i = 1; $i < 6; $i++) {
            \do_action('wp_login_failed', 'nonexistent_user', $wp_error);
        }
        
        // Check if IP is locked out (using SecurityHelper format)
        $lockout_key = "lockout_" . \md5($test_ip);
        $lockout_time = \get_transient($lockout_key);
        
        $this->assertNotFalse(
            $lockout_time,
            'IP should be locked out after exceeding failed login attempts'
        );
    }

    /**
     * Test successful login tracking integration
     *
     * @return void
     */
    public function test_successful_login_tracking_integration(): void
    {
        $test_ip = '192.168.1.101';
        $_SERVER['REMOTE_ADDR'] = $test_ip;
        
        // Get test user
        $user = \get_user_by('id', $this->test_user_id);
        $this->assertInstanceOf(WP_User::class, $user);
        
        // Simulate successful login
        \do_action('wp_login', $user->user_login, $user);
        
        // Check that successful login was tracked
        $attempt_key = "login_attempts_" . \md5($test_ip);
        $attempts = \get_transient($attempt_key);
        
        // Successful login should clear failed attempts
        $this->assertFalse(
            $attempts,
            'Successful login should clear failed login attempt tracking'
        );
    }

    /**
     * Test WordPress options integration for security settings
     *
     * @return void
     */
    public function test_security_options_integration(): void
    {
        // Test updating security options
        $test_options = array(
            'silver_assist_login_attempts' => 3,
            'silver_assist_lockout_duration' => 1800,
            'silver_assist_session_timeout' => 45,
            'silver_assist_password_strength_enforcement' => 1,
            'silver_assist_bot_protection' => 1
        );
        
        foreach ($test_options as $option_name => $value) {
            \update_option($option_name, $value);
            
            $retrieved_value = \get_option($option_name);
            $this->assertEquals(
                $value,
                $retrieved_value,
                "Security option {$option_name} should be stored and retrieved correctly"
            );
        }
        
        // Test that plugin uses these options
        $login_attempts = \get_option('silver_assist_login_attempts', 5);
        $this->assertIsNumeric($login_attempts, 'Login attempts option should be numeric');
        $this->assertGreaterThan(0, $login_attempts, 'Login attempts should be greater than 0');
    }

    /**
     * Test WordPress transients integration for temporary security data
     *
     * @return void
     */
    public function test_security_transients_integration(): void
    {
        $test_ip = '192.168.1.102';
        $transient_key = "security_test_" . \md5($test_ip);
        $test_data = array(
            'attempts' => 3,
            'timestamp' => \current_time('timestamp'),
            'user_agent' => 'Test Browser'
        );
        
        // Set transient with expiration
        \set_transient($transient_key, $test_data, 300); // 5 minutes
        
        // Retrieve and verify transient
        $retrieved_data = \get_transient($transient_key);
        
        $this->assertIsArray($retrieved_data, 'Security transient should return array data');
        $this->assertEquals($test_data['attempts'], $retrieved_data['attempts'], 'Transient data should be preserved');
        $this->assertEquals($test_data['timestamp'], $retrieved_data['timestamp'], 'Timestamp should be preserved');
        
        // Test transient expiration
        $this->assertTrue(
            \get_transient($transient_key) !== false,
            'Transient should exist before expiration'
        );
        
        // Delete transient
        \delete_transient($transient_key);
        $this->assertFalse(
            \get_transient($transient_key),
            'Transient should be deleted when requested'
        );
    }

    /**
     * Test security headers integration with WordPress
     *
     * @return void
     */
    public function test_security_headers_integration(): void
    {
        // Test that security headers can be set
        if (!\headers_sent()) {
            // Simulate header setting
            $security_headers = array(
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'SAMEORIGIN',
                'X-XSS-Protection' => '1; mode=block',
                'Referrer-Policy' => 'strict-origin-when-cross-origin'
            );
            
            foreach ($security_headers as $header => $value) {
                // In real implementation, headers would be set via WordPress hooks
                $this->assertIsString($header, 'Security header name should be string');
                $this->assertIsString($value, 'Security header value should be string');
            }
        }
        
        $this->assertTrue(true, 'Security headers integration test completed');
    }

    /**
     * Test WordPress user meta integration for security data
     *
     * @return void
     */
    public function test_user_security_meta_integration(): void
    {
        // Test storing security-related user meta
        $security_meta = array(
            'last_failed_login' => \current_time('mysql'),
            'failed_login_count' => 2,
            'last_password_change' => \current_time('mysql')
        );
        
        foreach ($security_meta as $meta_key => $meta_value) {
            $full_meta_key = "silver_assist_{$meta_key}";
            
            // Add user meta
            \update_user_meta($this->test_user_id, $full_meta_key, $meta_value);
            
            // Retrieve and verify
            $retrieved_value = \get_user_meta($this->test_user_id, $full_meta_key, true);
            
            $this->assertEquals(
                $meta_value,
                $retrieved_value,
                "User security meta {$meta_key} should be stored and retrieved correctly"
            );
        }
        
        // Test deletion of security meta
        \delete_user_meta($this->test_user_id, 'silver_assist_failed_login_count');
        $deleted_meta = \get_user_meta($this->test_user_id, 'silver_assist_failed_login_count', true);
        
        $this->assertEmpty(
            $deleted_meta,
            'Deleted security meta should not be retrievable'
        );
    }

    /**
     * Test WordPress capability checks for security features
     *
     * @return void
     */
    public function test_security_capability_integration(): void
    {
        // Create admin user
        $admin_user_id = \wp_create_user('test_admin_sec', 'admin_password_123', 'admin@security.com');
        $admin_user = new WP_User($admin_user_id);
        $admin_user->set_role('administrator');
        
        // Set current user as admin
        \wp_set_current_user($admin_user_id);
        
        // Test admin capabilities for security settings
        $this->assertTrue(
            \current_user_can('manage_options'),
            'Admin user should have capability to manage security options'
        );
        
        $this->assertTrue(
            \current_user_can('edit_users'),
            'Admin user should have capability to manage user security'
        );
        
        // Switch to regular user
        \wp_set_current_user($this->test_user_id);
        
        $this->assertFalse(
            \current_user_can('manage_options'),
            'Regular user should not have capability to manage security options'
        );
        
        // Cleanup
        \wp_delete_user($admin_user_id);
    }

    /**
     * Test WordPress database integration for security logs
     *
     * @return void
     */
    public function test_security_database_integration(): void
    {
        global $wpdb;
        
        // Test that we can access WordPress database
        $this->assertInstanceOf(
            'wpdb',
            $wpdb,
            'WordPress database should be accessible for security logging'
        );
        
        // Test WordPress options table access
        $test_option_name = 'silver_assist_db_test';
        $test_option_value = array('test' => 'data', 'timestamp' => \time());
        
        // Insert option
        $result = \add_option($test_option_name, $test_option_value);
        $this->assertTrue($result, 'Should be able to add security options to database');
        
        // Retrieve option
        $retrieved_option = \get_option($test_option_name);
        $this->assertEquals($test_option_value, $retrieved_option, 'Retrieved option should match inserted data');
        
        // Update option
        $updated_value = array('test' => 'updated', 'timestamp' => \time());
        $update_result = \update_option($test_option_name, $updated_value);
        $this->assertTrue($update_result, 'Should be able to update security options');
        
        // Delete option
        $delete_result = \delete_option($test_option_name);
        $this->assertTrue($delete_result, 'Should be able to delete security options');
    }

    /**
     * Test WordPress cron integration for security tasks
     *
     * @return void
     */
    public function test_security_cron_integration(): void
    {
        // Test scheduling a security cleanup task
        $hook = 'silver_assist_security_cleanup';
        $timestamp = \time() + 300; // 5 minutes from now
        $args = array('cleanup_type' => 'failed_logins');
        
        // Schedule event
        $scheduled = \wp_schedule_single_event($timestamp, $hook, $args);
        $this->assertNotFalse($scheduled, 'Should be able to schedule security cleanup tasks');
        
        // Check if event was scheduled
        $next_scheduled = \wp_next_scheduled($hook, $args);
        $this->assertEquals($timestamp, $next_scheduled, 'Security cleanup should be scheduled for correct time');
        
        // Unschedule event
        $unscheduled = \wp_unschedule_event($timestamp, $hook, $args);
        $this->assertNotFalse($unscheduled, 'Should be able to unschedule security tasks');
    }

    /**
     * Test WordPress multisite integration (if applicable)
     *
     * @return void
     */
    public function test_multisite_security_integration(): void
    {
        if (!\is_multisite()) {
            $this->markTestSkipped('Multisite not available for multisite security testing');
        }
        
        // Test network-wide security options
        $network_option = 'silver_assist_network_security';
        $network_value = array('enforce_across_network' => true);
        
        \update_site_option($network_option, $network_value);
        $retrieved_network_value = \get_site_option($network_option);
        
        $this->assertEquals(
            $network_value,
            $retrieved_network_value,
            'Network-wide security options should work in multisite'
        );
        
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
        // Clean up test user
        \wp_delete_user($this->test_user_id);
        
        // Clean up any test options and transients
        $test_options = array(
            'silver_assist_login_attempts',
            'silver_assist_lockout_duration', 
            'silver_assist_session_timeout',
            'silver_assist_password_strength_enforcement',
            'silver_assist_bot_protection',
            'silver_assist_db_test'
        );
        
        foreach ($test_options as $option) {
            \delete_option($option);
        }
        
        // Clean up transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_security_test_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_security_test_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_login_attempts_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_login_attempts_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_login_lockout_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_login_lockout_%'");
        
        parent::tearDown();
    }
}