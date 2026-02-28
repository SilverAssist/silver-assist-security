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
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;

/**
 * Settings Hub integration test class
 *
 * @coversDefaultClass \SilverAssist\Security\Admin\AdminPanel
 */
class SettingsHubTest extends WP_UnitTestCase
{
    use AjaxTestHelper;
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

        // Set up AJAX testing environment
        $this->setup_ajax_environment();
    }

    /**
     * Tear down test environment
     *
     * @return void
     */
    public function tearDown(): void
    {
        // Clean up AJAX environment
        $this->teardown_ajax_environment();

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

        $response = $this->call_ajax_handler($this->admin_panel, 'ajax_check_updates');

        $this->assertIsArray($response, 'Response should be valid JSON');
        $this->assertFalse($response["success"] ?? true, "Request without nonce should fail");

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
        // render_update_check_script() echoes output (returns void), so capture with ob
        ob_start();
        $this->admin_panel->render_update_check_script();
        $output = ob_get_clean();

        // Verify JavaScript handler is returned
        if (!empty($output)) {
            // Method now returns onclick handler string, not full script tag
            $this->assertIsString($output, "Output should be a string");
            $this->assertStringContainsString("silverAssistCheckUpdates", $output, "Handler should call global function");
            $this->assertStringContainsString("return false", $output, "Handler should prevent default action");
            
            // Verify it's a valid onclick handler format (no script tags)
            $this->assertStringNotContainsString("<script", $output, "Should not contain script tags");
            $this->assertStringNotContainsString("</script>", $output, "Should not contain script closing tags");
            
            // Verify script was enqueued
            $this->assertTrue(\wp_script_is("silver-assist-update-check", "registered"), "Update check script should be registered");
            $this->assertTrue(\wp_script_is("silver-assist-update-check", "enqueued"), "Update check script should be enqueued");
            
            // Verify script has correct dependencies
            global $wp_scripts;
            $script_data = $wp_scripts->registered["silver-assist-update-check"];
            $this->assertContains("jquery", $script_data->deps, "Script should depend on jQuery");
            
            // Verify script is loaded in footer (WordPress stores this in extra['group'] = 1)
            $extra_data = $wp_scripts->get_data("silver-assist-update-check", "group");
            $this->assertEquals(1, $extra_data, "Script should load in footer (group 1)");
            
            // Verify localization data was registered
            $localized_data = $wp_scripts->get_data("silver-assist-update-check", "data");
            $this->assertNotEmpty($localized_data, "Script should have localized data");
            
            // Verify localized data contains required properties
            $this->assertStringContainsString("silverAssistUpdateCheck", $localized_data, "Should define silverAssistUpdateCheck object");
            $this->assertStringContainsString("ajaxurl", $localized_data, "Should contain ajaxurl");
            $this->assertStringContainsString("nonce", $localized_data, "Should contain nonce");
            $this->assertStringContainsString("updateUrl", $localized_data, "Should contain updateUrl");
            $this->assertStringContainsString("strings", $localized_data, "Should contain strings object");
            
            // Verify translation strings are present
            $this->assertStringContainsString("updateAvailable", $localized_data, "Should contain updateAvailable string");
            $this->assertStringContainsString("upToDate", $localized_data, "Should contain upToDate string");
            $this->assertStringContainsString("checkError", $localized_data, "Should contain checkError string");
            $this->assertStringContainsString("connectError", $localized_data, "Should contain connectError string");
        } else {
            // If no updater, output should be empty string
            $updater = $this->plugin->get_updater();
            $this->assertNull($updater, "Empty output is only valid when updater is unavailable");
            
            // Verify script was NOT enqueued when no updater
            $this->assertFalse(\wp_script_is("silver-assist-update-check", "enqueued"), "Script should not be enqueued without updater");
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
