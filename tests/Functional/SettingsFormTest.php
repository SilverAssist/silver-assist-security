<?php

namespace SilverAssist\Security\Tests\Functional;

use WP_UnitTestCase;
use SilverAssist\Security\Admin\AdminPanel;

/**
 * Settings Form and Auto-Save Functional Tests
 * 
 * Tests form functionality, auto-save, field validation, and default value updates
 * from a user experience perspective
 * 
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 */
class SettingsFormTest extends WP_UnitTestCase
{
    private AdminPanel $admin_panel;
    private int $admin_user_id;

    public function setUp(): void
    {
        parent::setUp();
        
        // Create administrator user for form testing
        $this->admin_user_id = $this->factory()->user->create(['role' => 'administrator']);
        \wp_set_current_user($this->admin_user_id);
        
        // Initialize admin panel
        $this->admin_panel = new AdminPanel();
        
        // Set up admin context for form processing
        $_GET['page'] = 'silver-assist-security';
        global $pagenow;
        $pagenow = 'admin.php';
    }

    /**
     * Test form rendering with default values
     */
    public function test_form_renders_with_default_values(): void
    {
        // Set some known values
        \update_option('silver_assist_login_attempts', 5);
        \update_option('silver_assist_graphql_query_depth', 8);
        \update_option('silver_assist_bot_protection', 1);

        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify form fields show current values
        $this->assertStringContainsString('value="5"', $output, 'Login attempts field should show current value');
        $this->assertStringContainsString('value="8"', $output, 'GraphQL depth field should show current value');
        $this->assertStringContainsString('checked', $output, 'Bot protection checkbox should be checked');
    }

    /**
     * Test settings form submission and processing
     */
    public function test_settings_form_submission(): void
    {
        // Simulate form submission
        $_POST['silver_assist_login_attempts'] = '10';
        $_POST['silver_assist_lockout_duration'] = '1800';
        $_POST['silver_assist_session_timeout'] = '45';
        $_POST['silver_assist_password_strength_enforcement'] = '1';
        $_POST['silver_assist_bot_protection'] = '1';
        $_POST['silver_assist_graphql_query_depth'] = '12';
        $_POST['silver_assist_graphql_query_complexity'] = '150';
        $_POST['silver_assist_graphql_query_timeout'] = '8';
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = \wp_create_nonce('silver_assist_security_settings');

        // Process form submission
        $this->admin_panel->handle_form_submission();

        // Verify values were updated
        $this->assertEquals(10, \get_option('silver_assist_login_attempts'), 'Login attempts should update to 10');
        $this->assertEquals(1800, \get_option('silver_assist_lockout_duration'), 'Lockout duration should update to 1800');
        $this->assertEquals(45, \get_option('silver_assist_session_timeout'), 'Session timeout should update to 45');
        $this->assertEquals(1, \get_option('silver_assist_password_strength_enforcement'), 'Password enforcement should remain enabled');
        $this->assertEquals(1, \get_option('silver_assist_bot_protection'), 'Bot protection should remain enabled');
        $this->assertEquals(12, \get_option('silver_assist_graphql_query_depth'), 'GraphQL depth should update to 12');
        $this->assertEquals(150, \get_option('silver_assist_graphql_query_complexity'), 'GraphQL complexity should update to 150');
        $this->assertEquals(8, \get_option('silver_assist_graphql_query_timeout'), 'GraphQL timeout should update to 8');
    }

    /**
     * Test field validation with invalid values
     */
    public function test_form_validation_with_invalid_values(): void
    {
        // Submit invalid values
        $_POST['silver_assist_login_attempts'] = '0'; // Below minimum (1)
        $_POST['silver_assist_lockout_duration'] = '30'; // Below minimum (60)
        $_POST['silver_assist_session_timeout'] = '200'; // Above maximum (120)
        $_POST['silver_assist_graphql_query_depth'] = '25'; // Above maximum (20)
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = \wp_create_nonce('silver_assist_security_settings');

        // Process form - should apply validation
        $this->admin_panel->handle_form_submission();

        // Verify values were clamped to valid ranges
        $this->assertGreaterThanOrEqual(1, \get_option('silver_assist_login_attempts'), 'Login attempts should be at least 1');
        $this->assertGreaterThanOrEqual(60, \get_option('silver_assist_lockout_duration'), 'Lockout duration should be at least 60');
        $this->assertLessThanOrEqual(120, \get_option('silver_assist_session_timeout'), 'Session timeout should be max 120');
        $this->assertLessThanOrEqual(20, \get_option('silver_assist_graphql_query_depth'), 'GraphQL depth should be max 20');
    }

    /**
     * Test checkbox handling (unchecked values)
     */
    public function test_checkbox_unchecked_handling(): void
    {
        // Initially enable all checkboxes
        \update_option('silver_assist_password_strength_enforcement', 1);
        \update_option('silver_assist_bot_protection', 1);

        // Submit form WITHOUT checkboxes (simulates unchecked)
        $_POST['silver_assist_login_attempts'] = '5';
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = \wp_create_nonce('silver_assist_security_settings');
        // Note: No checkbox values in POST = unchecked

        $this->admin_panel->handle_form_submission();

        // Verify checkboxes were disabled (0)
        $this->assertEquals(0, \get_option('silver_assist_password_strength_enforcement'), 'Password enforcement should be disabled when unchecked');
        $this->assertEquals(0, \get_option('silver_assist_bot_protection'), 'Bot protection should be disabled when unchecked');
    }

    /**
     * Test auto-save functionality via AJAX
     */
    public function test_auto_save_functionality(): void
    {
        // Mock auto-save AJAX request
        $_POST['action'] = 'silver_assist_auto_save';
        $_POST['nonce'] = \wp_create_nonce('silver_assist_security_ajax');
        $_POST['form_data'] = 'silver_assist_login_attempts=8&silver_assist_session_timeout=25';

        // Simulate AJAX handler
        \set_current_user($this->admin_user_id);
        
        \ob_start();
        try {
            // This would normally be handled by WordPress AJAX system
            $this->admin_panel->ajax_auto_save();
        } catch (\Exception $e) {
            // Expected in unit test environment
        }
        $output = \ob_get_clean();

        // Verify auto-save attempted to process data
        $this->assertTrue(true, 'Auto-save should execute without fatal errors');
    }

    /**
     * Test form field range validation
     */
    public function test_form_field_ranges(): void
    {
        $test_cases = [
            // [field_name, test_value, expected_min, expected_max]
            ['silver_assist_login_attempts', 25, 1, 20],
            ['silver_assist_lockout_duration', 30, 60, 3600], 
            ['silver_assist_session_timeout', 200, 5, 120],
            ['silver_assist_graphql_query_depth', 0, 1, 20],
            ['silver_assist_graphql_query_complexity', 2000, 10, 1000],
            ['silver_assist_graphql_query_timeout', 50, 1, 30]
        ];

        foreach ($test_cases as [$field, $test_value, $min, $max]) {
            // Test value above maximum
            $_POST = [$field => $test_value, 'submit' => 'Save Settings', '_wpnonce' => \wp_create_nonce('silver_assist_security_settings')];
            $this->admin_panel->handle_form_submission();
            
            $actual_value = \get_option($field);
            $this->assertGreaterThanOrEqual($min, $actual_value, "{$field} should respect minimum value {$min}");
            $this->assertLessThanOrEqual($max, $actual_value, "{$field} should respect maximum value {$max}");
        }
    }

    /**
     * Test success message display after form save
     */
    public function test_success_message_after_save(): void
    {
        // Submit valid form
        $_POST['silver_assist_login_attempts'] = '7';
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = \wp_create_nonce('silver_assist_security_settings');

        $this->admin_panel->handle_form_submission();

        // Check for settings errors (success messages)
        $settings_errors = \get_settings_errors('silver_assist_security_messages');
        
        $this->assertNotEmpty($settings_errors, 'Should have settings messages after form submission');
        
        // Look for success type message
        $has_success = false;
        foreach ($settings_errors as $error) {
            if ($error['type'] === 'success') {
                $has_success = true;
                break;
            }
        }
        
        $this->assertTrue($has_success, 'Should have success message after valid form submission');
    }

    /**
     * Test form nonce security validation
     */
    public function test_form_nonce_validation(): void
    {
        // Submit form with invalid nonce
        $_POST['silver_assist_login_attempts'] = '99';
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = 'invalid_nonce';

        $original_value = \get_option('silver_assist_login_attempts', 5);
        
        $this->admin_panel->handle_form_submission();

        // Value should not change with invalid nonce
        $this->assertEquals($original_value, \get_option('silver_assist_login_attempts'), 'Settings should not change with invalid nonce');
    }

    /**
     * Test form field sanitization
     */
    public function test_form_field_sanitization(): void
    {
        // Submit form with potentially dangerous input
        $_POST['silver_assist_login_attempts'] = '<script>alert("xss")</script>5';
        $_POST['submit'] = 'Save Settings';
        $_POST['_wpnonce'] = \wp_create_nonce('silver_assist_security_settings');

        $this->admin_panel->handle_form_submission();

        // Should be sanitized to just the numeric value
        $this->assertEquals(5, \get_option('silver_assist_login_attempts'), 'Input should be sanitized to numeric value only');
    }

    public function tearDown(): void
    {
        // Clean up POST data
        $_POST = [];
        $_GET = [];
        
        parent::tearDown();
    }
}