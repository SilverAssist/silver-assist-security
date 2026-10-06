<?php

namespace SilverAssist\Security\Tests\Functional;

use WP_UnitTestCase;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Admin\Settings\SettingsHandler;

/**
 * Settings Form and Save Functional Tests
 * 
 * Tests form functionality, settings save, field validation, and default value updates
 * from a user experience perspective
 * 
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 */
class SettingsFormTest extends WP_UnitTestCase
{
    private AdminPanel $admin_panel;
    private SettingsHandler $settings_handler;
    private int $admin_user_id;

    public function setUp(): void
    {
        parent::setUp();
        
        // Create administrator user for form testing
        $this->admin_user_id = $this->factory()->user->create(['role' => 'administrator']);
        \wp_set_current_user($this->admin_user_id);
        
        // Initialize admin panel and settings handler
        $this->admin_panel = new AdminPanel();
        $this->settings_handler = new SettingsHandler();
        
        // Set up admin context for form processing
        $_GET['page'] = 'silver-assist-security';
        global $pagenow;
        $pagenow = 'admin.php';
    }

    /**
     * Helper to simulate form submission via SettingsHandler
     * Sets the required POST trigger key and nonce
     *
     * @param array $fields Key-value pairs of form fields
     */
    private function submit_settings(array $fields): void
    {
        $_POST = array_merge($fields, [
            'save_silver_assist_security' => '1',
            '_wpnonce' => \wp_create_nonce('silver_assist_security_settings'),
        ]);
        $this->settings_handler->save_security_settings();
    }

    /**
     * Test form rendering with default values
     */
    public function test_form_renders_with_default_values(): void
    {
        // Set some known values
        \update_option('silver_assist_login_attempts', 5);
        \update_option('silver_assist_bot_protection', 1);

        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify form fields show current values
        $this->assertStringContainsString('value="5"', $output, 'Login attempts field should show current value');
        $this->assertStringContainsString('checked', $output, 'Bot protection toggle should be checked');
        $this->assertStringContainsString('silver_assist_login_attempts', $output, 'Login attempts field should be present');
        $this->assertStringContainsString('silver_assist_lockout_duration', $output, 'Lockout duration field should be present');
    }

    /**
     * Test settings form submission and processing via SettingsHandler
     */
    public function test_settings_form_submission(): void
    {
        $this->submit_settings([
            'silver_assist_login_attempts' => '10',
            'silver_assist_lockout_duration' => '1800',
            'silver_assist_session_timeout' => '45',
            'silver_assist_password_strength_enforcement' => '1',
            'silver_assist_bot_protection' => '1',
        ]);

        // Verify values were updated
        $this->assertEquals(10, \get_option('silver_assist_login_attempts'), 'Login attempts should update to 10');
        $this->assertEquals(1800, \get_option('silver_assist_lockout_duration'), 'Lockout duration should update to 1800');
        $this->assertEquals(45, \get_option('silver_assist_session_timeout'), 'Session timeout should update to 45');
        $this->assertEquals(1, \get_option('silver_assist_password_strength_enforcement'), 'Password enforcement should remain enabled');
        $this->assertEquals(1, \get_option('silver_assist_bot_protection'), 'Bot protection should remain enabled');
    }

    /**
     * Test field validation with invalid values
     */
    public function test_form_validation_with_invalid_values(): void
    {
        $this->submit_settings([
            'silver_assist_login_attempts' => '0',   // Below minimum (1)
            'silver_assist_lockout_duration' => '30', // Below minimum (60)
            'silver_assist_session_timeout' => '200', // Above maximum (120)
        ]);

        // Verify values were clamped to valid ranges
        $this->assertGreaterThanOrEqual(1, \get_option('silver_assist_login_attempts'), 'Login attempts should be at least 1');
        $this->assertGreaterThanOrEqual(60, \get_option('silver_assist_lockout_duration'), 'Lockout duration should be at least 60');
        $this->assertLessThanOrEqual(120, \get_option('silver_assist_session_timeout'), 'Session timeout should be max 120');
    }

    /**
     * Test checkbox/toggle handling (unchecked values)
     */
    public function test_checkbox_unchecked_handling(): void
    {
        // Initially enable all toggles
        \update_option('silver_assist_password_strength_enforcement', 1);
        \update_option('silver_assist_bot_protection', 1);

        // Submit form WITHOUT toggle fields (simulates unchecked)
        $this->submit_settings([
            'silver_assist_login_attempts' => '5',
            // Note: No toggle values in POST = unchecked/disabled
        ]);

        // Verify toggles were disabled (0)
        $this->assertEquals(0, \get_option('silver_assist_password_strength_enforcement'), 'Password enforcement should be disabled when unchecked');
        $this->assertEquals(0, \get_option('silver_assist_bot_protection'), 'Bot protection should be disabled when unchecked');
    }

    /**
     * Test auto-save AJAX action is registered
     */
    public function test_auto_save_action_registered(): void
    {
        // The auto_save action should be registered by SecurityAjaxHandler
        $this->assertNotFalse(
            \has_action('wp_ajax_silver_assist_auto_save'),
            'Auto-save AJAX action should be registered'
        );
    }

    /**
     * Test form field range validation on login security fields
     */
    public function test_form_field_ranges(): void
    {
        $test_cases = [
            // [field_name, test_value, expected_min, expected_max]
            ['silver_assist_login_attempts', 25, 1, 20],
            ['silver_assist_lockout_duration', 30, 60, 3600], 
            ['silver_assist_session_timeout', 200, 5, 120],
        ];

        foreach ($test_cases as [$field, $test_value, $min, $max]) {
            $this->submit_settings([$field => (string) $test_value]);
            
            $actual_value = \get_option($field);
            $this->assertGreaterThanOrEqual($min, $actual_value, "{$field} should respect minimum value {$min}");
            $this->assertLessThanOrEqual($max, $actual_value, "{$field} should respect maximum value {$max}");
        }
    }

    /**
     * Test success notice is added after form save
     */
    public function test_success_message_after_save(): void
    {
        $this->submit_settings([
            'silver_assist_login_attempts' => '7',
        ]);

        // SettingsHandler registers an admin_notices action on success
        $this->assertNotFalse(
            \has_action('admin_notices'),
            'Should have admin notice registered after form submission'
        );
    }

    /**
     * Test form nonce security validation
     */
    public function test_form_nonce_validation(): void
    {
        // Submit form with invalid nonce
        $_POST = [
            'save_silver_assist_security' => '1',
            'silver_assist_login_attempts' => '99',
            '_wpnonce' => 'invalid_nonce',
        ];

        // SettingsHandler calls wp_die() on invalid nonce, which throws WPDieException in tests
        $this->expectException(\WPDieException::class);
        $this->settings_handler->save_security_settings();
    }

    /**
     * Test form field sanitization
     */
    public function test_form_field_sanitization(): void
    {
        $this->submit_settings([
            'silver_assist_login_attempts' => '<script>alert("xss")</script>5',
        ]);

        // Should be sanitized to just the numeric value
        $value = \get_option('silver_assist_login_attempts');
        $this->assertIsInt($value, 'Input should be sanitized to integer');
        $this->assertGreaterThanOrEqual(1, $value, 'Sanitized value should be within valid range');
        $this->assertLessThanOrEqual(20, $value, 'Sanitized value should be within valid range');
    }

    public function tearDown(): void
    {
        // Clean up POST data
        $_POST = [];
        $_GET = [];
        
        parent::tearDown();
    }
}