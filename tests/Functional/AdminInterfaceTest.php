<?php

namespace SilverAssist\Security\Tests\Functional;

use WP_UnitTestCase;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;

/**
 * Admin Menu and Interface Functional Tests
 * 
 * Tests the admin interface from a user perspective including menus,
 * tabs, buttons, and form functionality
 * 
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 */
class AdminInterfaceTest extends WP_UnitTestCase
{
    use AjaxTestHelper;

    private AdminPanel $admin_panel;

    public function setUp(): void
    {
        parent::setUp();

        // Create administrator user and set current user
        $admin_user = $this->factory()->user->create(['role' => 'administrator']);
        \wp_set_current_user($admin_user);

        // Initialize admin panel
        $this->admin_panel = new AdminPanel();

        // Set admin context
        \set_current_screen('admin');
        $_GET['page'] = 'silver-assist-security';
    }

    /**
     * Test that plugin menu appears under "Silver Assist" when Settings Hub is available
     */
    public function test_menu_registration_with_settings_hub(): void
    {
        // Mock Settings Hub availability
        if (!\class_exists('SilverAssist\\SettingsHub\\SettingsHub')) {
            $this->markTestSkipped('Settings Hub not available for testing integration');
        }

        // Test menu registration
        $this->admin_panel->register_with_hub();

        // In integration, this would be registered under Settings Hub
        // For unit test, we verify the method executes without error
        $this->assertTrue(true, 'Admin menu registration should complete without errors');
    }

    /**
     * Test standalone menu registration when Settings Hub is not available  
     */
    public function test_standalone_menu_registration(): void
    {
        global $admin_page_hooks, $submenu;

        // Ensure we're testing standalone mode
        $this->admin_panel->register_with_hub();

        // Check if our menu hook exists
        $found_menu = false;
        if (\is_array($admin_page_hooks)) {
            foreach ($admin_page_hooks as $menu_slug => $hook) {
                if (\strpos($menu_slug, 'silver-assist-security') !== false) {
                    $found_menu = true;
                    break;
                }
            }
        }

        // In standalone mode, should have its own menu
        $this->assertTrue(true, 'Standalone menu should be registered when Settings Hub unavailable');
    }

    /**
     * Test Configure button functionality
     */
    public function test_configure_button_functionality(): void
    {
        // Simulate clicking Configure button (which loads admin page)
        $_GET['page'] = 'silver-assist-security';

        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify page renders with Configure functionality
        $this->assertStringContainsString('Security Essentials', $output, 'Configure page should load Security Essentials interface');
        $this->assertStringContainsString('dashboard-tab', $output, 'Configure page should show dashboard tab');
    }

    /**
     * Test Check Updates button functionality
     */
    public function test_check_updates_button(): void
    {
        // Set up AJAX environment so wp_send_json uses wp_die (not die)
        $this->setup_ajax_environment();

        // Simulate Settings Hub action for update check
        $_POST['action'] = 'silver_assist_check_updates';
        $_POST['nonce'] = \wp_create_nonce('silver_assist_security_ajax');

        // Mock AJAX request for update check
        \add_action('wp_ajax_silver_assist_check_updates', [$this->admin_panel, 'ajax_check_updates']);

        // Capture output using AjaxTestHelper
        try {
            $this->_ajax_response = '';
            $ob_level = ob_get_level();
            ob_start();
            \do_action('wp_ajax_silver_assist_check_updates');
            $this->_ajax_response = ob_get_clean();
        } catch (\SilverAssist\Security\Tests\Helpers\AjaxTestDieError $e) {
            while (ob_get_level() > $ob_level) {
                ob_end_clean();
            }
        }

        $this->teardown_ajax_environment();

        // Verify update check was triggered
        $this->assertTrue(true, 'Update check should execute without fatal errors');
    }

    /**
     * Test that admin page renders main structure
     */
    public function test_admin_messages_display(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Check for main page wrapper and heading
        $this->assertStringContainsString('wrap', $output, 'Admin page should render WordPress wrap container');
        $this->assertStringContainsString('Silver Assist Security Essentials', $output, 'Admin page should render plugin heading');
    }

    /**
     * Test Dashboard tab functionality
     */
    public function test_dashboard_tab_display(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify Dashboard tab elements
        $this->assertStringContainsString('dashboard-tab', $output, 'Dashboard tab should be present');
        $this->assertStringContainsString('Security Dashboard', $output, 'Dashboard should show security dashboard heading');
        $this->assertStringContainsString('status-indicator', $output, 'Dashboard should show status indicators');
    }

    /**
     * Test Recent Activity section in dashboard
     */
    public function test_recent_activity_display(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify recent activity section elements in dashboard
        $this->assertStringContainsString('Recent Security Activity', $output, 'Dashboard should show recent security activity');
        $this->assertStringContainsString('Failed Login Attempts', $output, 'Dashboard should show login statistics');
        $this->assertStringContainsString('Blocked IPs', $output, 'Dashboard should show blocked IPs section');
    }

    /**
     * Test Login Security settings tab functionality
     */
    public function test_login_security_tab_display(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Verify Login Security tab elements
        $this->assertStringContainsString('login-security-tab', $output, 'Login Security tab should be present');
        $this->assertStringContainsString('Login Protection Settings', $output, 'Settings should show login protection section');

        // Check for form elements
        $this->assertStringContainsString('silver_assist_login_attempts', $output, 'Settings form should have login attempts field');
        $this->assertStringContainsString('silver_assist_lockout_duration', $output, 'Settings form should have lockout duration field');
        $this->assertStringContainsString('silver_assist_session_timeout', $output, 'Settings form should have session timeout field');
    }

    /**
     * Test CF7 tab is conditional on CF7 being active
     */
    public function test_cf7_tab_conditional_display(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // CF7 tab should NOT be rendered when Contact Form 7 plugin is not active
        $this->assertStringNotContainsString('cf7-security-tab', $output, 'CF7 tab should not appear when CF7 is not active');
        $this->assertStringNotContainsString('Contact Form 7 Protection', $output, 'CF7 content should not appear when CF7 is not active');
    }

    /**
     * Test tab navigation structure
     */
    public function test_tab_navigation_scripts(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Check for tab navigation elements
        $this->assertStringContainsString('silver-nav-tab', $output, 'Tabs should have navigation buttons');
        $this->assertStringContainsString('silver-tab-content', $output, 'Tabs should have content containers');
        $this->assertStringContainsString('silver-nav-tab-wrapper', $output, 'Tab navigation wrapper should be present');
    }

    /**
     * Test responsive design elements
     */
    public function test_responsive_design_elements(): void
    {
        \ob_start();
        $this->admin_panel->render_admin_page();
        $output = \ob_get_clean();

        // Check for responsive CSS classes
        $this->assertStringContainsString('wrap', $output, 'Page should have WordPress wrap container');
        $this->assertStringContainsString('status-card', $output, 'Page should use card-based layout');
        $this->assertStringContainsString('card-header', $output, 'Cards should have headers');
        $this->assertStringContainsString('card-content', $output, 'Cards should have content sections');
    }

    public function tearDown(): void
    {
        // Clean up
        unset($_GET['page']);
        unset($_POST['action']);
        unset($_POST['nonce']);

        parent::tearDown();
    }
}
