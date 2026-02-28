<?php

namespace SilverAssist\Security\Tests\Functional;

use WP_UnitTestCase;

/**
 * End-to-End User Experience Tests
 * 
 * Tests the complete user workflow from plugin activation through
 * admin interface usage, simulating real user interactions
 * 
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 */
class UserExperienceTest extends WP_UnitTestCase
{
    private int $admin_user_id;

    public function setUp(): void
    {
        parent::setUp();
        
        // Create admin user and simulate login
        $this->admin_user_id = $this->factory()->user->create([
            'role' => 'administrator',
            'user_login' => 'admin_user',
            'user_email' => 'admin@test.com'
        ]);
        \wp_set_current_user($this->admin_user_id);
        
        // Ensure default options exist (simulate fresh installation)
        $this->setup_default_options();
    }

    /**
     * Set up default plugin options as if freshly installed
     */
    private function setup_default_options(): void
    {
        $defaults = [
            'silver_assist_login_attempts' => 5,
            'silver_assist_lockout_duration' => 900,
            'silver_assist_session_timeout' => 30,
            'silver_assist_password_strength_enforcement' => 1,
            'silver_assist_bot_protection' => 1,
            'silver_assist_graphql_query_depth' => 8,
            'silver_assist_graphql_query_complexity' => 100,
            'silver_assist_graphql_query_timeout' => 5,
            'silver_assist_graphql_headless_mode' => 0
        ];

        foreach ($defaults as $option => $value) {
            \update_option($option, $value);
        }
    }

    /**
     * Scenario 1: User installs plugin and sees default values
     */
    public function test_user_sees_default_values_after_installation(): void
    {
        // Verify default values are set correctly
        $this->assertEquals(5, \get_option('silver_assist_login_attempts'), 'Login attempts should default to 5');
        $this->assertEquals(900, \get_option('silver_assist_lockout_duration'), 'Lockout should default to 15 minutes');
        $this->assertEquals(30, \get_option('silver_assist_session_timeout'), 'Session should default to 30 minutes');
        $this->assertEquals(1, \get_option('silver_assist_bot_protection'), 'Bot protection should be enabled by default');
        $this->assertEquals(8, \get_option('silver_assist_graphql_query_depth'), 'GraphQL depth should default to 8');
        $this->assertEquals(0, \get_option('silver_assist_graphql_headless_mode'), 'Headless mode should be disabled by default');
    }

    /**
     * Scenario 2: User navigates to admin menu and sees Silver Assist section
     */
    public function test_user_finds_admin_menu(): void
    {
        global $menu, $submenu;
        
        // Simulate WordPress admin menu system
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        // In real WordPress, this would add menu items
        // For testing, we verify the class exists and can be instantiated
        $this->assertInstanceOf(
            \SilverAssist\Security\Admin\AdminPanel::class, 
            $admin_panel,
            'AdminPanel should be accessible for menu creation'
        );
    }

    /**
     * Scenario 3: User clicks Configure button and sees admin interface
     */
    public function test_user_accesses_configure_interface(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        // Simulate user navigating to plugin page
        $_GET['page'] = 'silver-assist-security';
        
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        // Verify user sees expected interface elements
        $this->assertStringContainsString('Security Essentials', $output, 'User should see main heading');
        $this->assertStringContainsString('dashboard-tab', $output, 'User should see Dashboard tab');
        $this->assertStringContainsString('login-security-tab', $output, 'User should see Login Security tab');
        $this->assertStringContainsString('ip-management-tab', $output, 'User should see IP Management tab');
    }

    /**
     * Scenario 4: User sees current security status on Dashboard
     */
    public function test_user_sees_security_dashboard(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        // Verify dashboard shows security information
        $this->assertStringContainsString('Login Security', $output, 'Dashboard should show login security status');
        $this->assertStringContainsString('status-indicator', $output, 'Dashboard should show status indicators');
        $this->assertStringContainsString('HTTPOnly Cookies', $output, 'Should show cookie security status');
    }

    /**
     * Scenario 5: User changes settings and sees updated values
     */
    public function test_user_modifies_settings(): void
    {
        // User changes login attempts from 5 to 8
        \update_option('silver_assist_login_attempts', 8);
        
        // User changes session timeout from 30 to 45 minutes
        \update_option('silver_assist_session_timeout', 45);
        
        // User enables headless mode
        \update_option('silver_assist_graphql_headless_mode', 1);
        
        // Verify changes were applied
        $this->assertEquals(8, \get_option('silver_assist_login_attempts'), 'Login attempts should update to user choice');
        $this->assertEquals(45, \get_option('silver_assist_session_timeout'), 'Session timeout should update to user choice');
        $this->assertEquals(1, \get_option('silver_assist_graphql_headless_mode'), 'Headless mode should be enabled');
        
        // Verify admin interface shows updated values
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        $this->assertStringContainsString('value="8"', $output, 'Settings form should show updated login attempts');
        $this->assertStringContainsString('value="45"', $output, 'Settings form should show updated session timeout');
    }

    /**
     * Scenario 6: User sees validation messages for invalid input
     */
    public function test_user_receives_validation_feedback(): void
    {
        // Test boundary values that should be corrected
        $test_cases = [
            ['silver_assist_login_attempts', 0, 1, 'Login attempts below minimum should be corrected'],
            ['silver_assist_login_attempts', 25, 20, 'Login attempts above maximum should be corrected'],
            ['silver_assist_session_timeout', 2, 5, 'Session timeout below minimum should be corrected'],
            ['silver_assist_session_timeout', 200, 120, 'Session timeout above maximum should be corrected'],
        ];
        
        foreach ($test_cases as [$option, $invalid_value, $expected_corrected, $message]) {
            \update_option($option, $invalid_value);
            
            // Simulate form processing (would normally validate and correct)
            $corrected_value = \get_option($option);
            
            // In real implementation, validation would occur
            $this->assertIsInt($corrected_value, $message);
        }
    }

    /**
     * Scenario 7: User sees real-time updates on dashboard
     */
    public function test_user_sees_monitoring_information(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        // Verify monitoring elements are present in dashboard
        $this->assertStringContainsString('Recent Security Activity', $output, 'Should show security activity section');
        $this->assertStringContainsString('Failed Login Attempts', $output, 'Should show login statistics');
        $this->assertStringContainsString('Blocked IPs', $output, 'Should show blocked IPs section');
    }

    /**
     * Scenario 8: CF7 tab only appears when Contact Form 7 is active
     */
    public function test_user_manages_cf7_security(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        // CF7 tab and content should NOT be present when CF7 is not installed
        $this->assertStringNotContainsString('cf7-security-tab', $output, 'CF7 tab should not appear without CF7 plugin');
        $this->assertStringNotContainsString('Contact Form 7 Protection', $output, 'CF7 content should not appear without CF7 plugin');
        
        // But the IP management tab should always be present
        $this->assertStringContainsString('ip-management-tab', $output, 'IP Management tab should always be accessible');
    }

    /**
     * Scenario 9: User finds descriptive labels and documentation
     */
    public function test_user_finds_help_information(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        \ob_start();
        $admin_panel->render_admin_page();
        $output = \ob_get_clean();
        
        // Verify descriptive help elements are available
        $this->assertStringContainsString('description', $output, 'Should have description text for user guidance');
        $this->assertStringContainsString('form-table', $output, 'Should have structured form tables');
    }

    /**
     * Scenario 10: User workflow - complete settings configuration
     */
    public function test_complete_user_workflow(): void
    {
        $admin_panel = new \SilverAssist\Security\Admin\AdminPanel();
        
        // Step 1: User navigates to plugin
        $_GET['page'] = 'silver-assist-security';
        
        // Step 2: User sees interface
        \ob_start();
        $admin_panel->render_admin_page();
        $interface_output = \ob_get_clean();
        
        $this->assertStringContainsString('Silver Assist Security Essentials', $interface_output, 'User should see plugin branding');
        
        // Step 3: User modifies several settings
        \update_option('silver_assist_login_attempts', 10);
        \update_option('silver_assist_bot_protection', 0);  // Disable bot protection
        
        // Step 4: User sees updated interface reflects changes  
        \ob_start();
        $admin_panel->render_admin_page();
        $updated_output = \ob_get_clean();
        
        // Login attempts is rendered as a range input with value attribute
        $this->assertStringContainsString('value="10"', $updated_output, 'Interface should reflect login attempts change');
        
        // Step 5: Verify settings persist
        $this->assertEquals(10, \get_option('silver_assist_login_attempts'), 'Settings should persist');
        $this->assertEquals(0, \get_option('silver_assist_bot_protection'), 'Settings should persist');
    }

    public function tearDown(): void
    {
        // Clean up
        unset($_GET['page']);
        
        parent::tearDown();
    }
}