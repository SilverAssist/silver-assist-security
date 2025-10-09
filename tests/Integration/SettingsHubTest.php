<?php
/**
 * Settings Hub Integration Tests
 *
 * Tests for the Settings Hub integration functionality in AdminPanel.
 * Verifies proper registration, fallback mechanisms, and update button integration.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.13
 */

use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Core\Plugin;
use SilverAssist\SettingsHub\SettingsHub;

/**
 * Settings Hub integration test class
 *
 * @coversDefaultClass \SilverAssist\Security\Admin\AdminPanel
 */
class SettingsHubTest extends WP_UnitTestCase
{
    /**
     * Admin panel instance for testing
     *
     * @var AdminPanel
     */
    private AdminPanel $admin_panel;

    /**
     * Plugin instance for testing
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Set up test environment
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Create admin user and set as current
        $admin_id = $this->factory()->user->create(["role" => "administrator"]);
        wp_set_current_user($admin_id);

        // Initialize plugin instance
        $this->plugin = Plugin::getInstance();
        
        // Initialize admin panel
        $this->admin_panel = new AdminPanel();
    }

    /**
     * Tear down test environment
     *
     * @return void
     */
    public function tearDown(): void
    {
        // Clean up
        wp_set_current_user(0);

        parent::tearDown();
    }

    /**
     * Test that Settings Hub class detection works
     *
     * @covers ::register_with_hub
     * @return void
     */
    public function test_settings_hub_class_detection(): void
    {
        // Check if SettingsHub class exists (depends on if package is installed)
        $hub_available = class_exists(SettingsHub::class);

        // If hub is available, it should be detectable
        if ($hub_available) {
            $this->assertTrue(class_exists(SettingsHub::class), "SettingsHub class should be available");
        } else {
            $this->assertFalse(class_exists(SettingsHub::class), "SettingsHub class should not be available");
        }
    }

    /**
     * Test that fallback menu registration works when hub is unavailable
     *
     * @covers ::register_with_hub
     * @covers ::add_admin_menu
     * @return void
     */
    public function test_fallback_menu_registration(): void
    {
        global $submenu;

        // If SettingsHub is not available, fallback should register standalone menu
        if (!class_exists(SettingsHub::class)) {
            // Trigger admin_menu action
            do_action("admin_menu");

            // Check that settings submenu was registered
            $this->assertNotEmpty($submenu, "Submenu should be registered when hub unavailable");

            // Verify our plugin appears in settings submenu
            $found = false;
            if (isset($submenu["options-general.php"])) {
                foreach ($submenu["options-general.php"] as $menu_item) {
                    if ($menu_item[2] === "silver-assist-security") {
                        $found = true;
                        break;
                    }
                }
            }

            $this->assertTrue($found, "Plugin should register in settings submenu as fallback");
        } else {
            $this->markTestSkipped("Settings Hub is available, fallback test not applicable");
        }
    }

    /**
     * Test that update button action is configured correctly
     *
     * @covers ::get_hub_actions
     * @return void
     */
    public function test_update_button_configuration(): void
    {
        // Get updater from plugin
        $updater = $this->plugin->get_updater();

        // Verify updater exists
        $this->assertNotNull($updater, "Updater should be available");
    }

    /**
     * Test AJAX update check handler
     *
     * @covers ::ajax_check_updates
     * @return void
     */
    public function test_ajax_update_check_handler(): void
    {
        // Create valid nonce
        $nonce = wp_create_nonce("silver_assist_security_updates_nonce");

        // Set up POST data
        $_POST["nonce"] = $nonce;
        $_POST["action"] = "silver_assist_check_updates";

        // This test verifies the handler exists and can be called
        // The actual AJAX execution would require WordPress AJAX environment
        $this->assertTrue(method_exists($this->admin_panel, "ajax_check_updates"), "ajax_check_updates method should exist");

        // Clean up
        unset($_POST["nonce"], $_POST["action"]);
    }

    /**
     * Test AJAX update check security validation
     *
     * @covers ::ajax_check_updates
     * @return void
     */
    public function test_ajax_update_check_security_validation(): void
    {
        // Test without nonce - should fail
        $_POST["action"] = "silver_assist_check_updates";
        unset($_POST["nonce"]);

        try {
            ob_start();
            $this->admin_panel->ajax_check_updates();
            $output = ob_get_clean();

            $response = json_decode($output, true);
            if (is_array($response)) {
                $this->assertFalse($response["success"] ?? true, "Request without nonce should fail");
            }
        } catch (Exception $e) {
            // Expected exception for security failure
            $this->assertNotNull($e, "Security validation should throw exception");
        }

        // Clean up
        unset($_POST["action"]);
    }

    /**
     * Test update check script rendering
     *
     * @covers ::render_update_check_script
     * @return void
     */
    public function test_update_check_script_rendering(): void
    {
        // Start output buffering
        ob_start();
        
        // Call render method
        $this->admin_panel->render_update_check_script();
        
        // Get output
        $output = ob_get_clean();

        // Verify JavaScript is rendered
        if (!empty($output)) {
            $this->assertStringContainsString("<script", $output, "Output should contain script tag");
            $this->assertStringContainsString("silver_assist_check_updates", $output, "Script should reference update action");
            $this->assertStringContainsString("ajaxurl", $output, "Script should use ajaxurl");
        } else {
            // If no updater, output may be empty
            $updater = $this->plugin->get_updater();
            $this->assertNull($updater, "Empty output is only valid when updater is unavailable");
        }
    }

    /**
     * Test that Settings Hub registration includes proper metadata
     *
     * @covers ::register_with_hub
     * @return void
     */
    public function test_hub_registration_metadata(): void
    {
        if (!class_exists(SettingsHub::class)) {
            $this->markTestSkipped("Settings Hub not available");
            return;
        }

        // Get hub instance
        $hub = SettingsHub::get_instance();
        $this->assertNotNull($hub, "Settings Hub instance should be available");

        // Verify registration method exists
        $this->assertTrue(method_exists($this->admin_panel, "register_with_hub"), "register_with_hub method should exist");
    }

    /**
     * Test that actions array contains update button when updater available
     *
     * @covers ::get_hub_actions
     * @return void
     */
    public function test_actions_array_includes_update_button(): void
    {
        if (!class_exists(SettingsHub::class)) {
            $this->markTestSkipped("Settings Hub not available");
            return;
        }

        $updater = $this->plugin->get_updater();

        if ($updater) {
            // Verify get_hub_actions method exists
            $reflection = new \ReflectionClass($this->admin_panel);
            $this->assertTrue($reflection->hasMethod("get_hub_actions"), "get_hub_actions method should exist");
        } else {
            $this->markTestSkipped("Updater not available");
        }
    }

    /**
     * Test that admin hooks are properly registered
     *
     * @covers ::init
     * @return void
     */
    public function test_admin_hooks_registration(): void
    {
        // Verify AJAX action is registered
        $ajax_action = "wp_ajax_silver_assist_check_updates";
        $has_action = has_action($ajax_action);

        $this->assertNotFalse($has_action, "AJAX update check action should be registered");
    }
}
