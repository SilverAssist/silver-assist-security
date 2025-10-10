<?php
/**
 * Admin Access Integration Tests
 *
 * Tests for admin page access permissions and capability verification.
 * These tests simulate real WordPress admin page access scenarios to ensure
 * proper permission handling and prevent unauthorized access.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.14
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\AdminPanel;
use WP_UnitTestCase;

/**
 * Test class for admin page access permissions
 *
 * @since 1.1.14
 */
class AdminAccessTest extends WP_UnitTestCase
{
    /**
     * AdminPanel instance
     *
     * @var AdminPanel
     */
    private AdminPanel $admin_panel;

    /**
     * Administrator user ID
     *
     * @var int
     */
    private int $admin_user_id;

    /**
     * Subscriber user ID (no admin privileges)
     *
     * @var int
     */
    private int $subscriber_user_id;

    /**
     * Setup test environment before each test
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Create admin user with manage_options capability
        $this->admin_user_id = $this->factory()->user->create([
            "role" => "administrator"
        ]);

        // Create subscriber user without manage_options capability
        $this->subscriber_user_id = $this->factory()->user->create([
            "role" => "subscriber"
        ]);

        // Initialize AdminPanel
        $this->admin_panel = new AdminPanel();
    }

    /**
     * Teardown test environment after each test
     *
     * @return void
     */
    public function tearDown(): void
    {
        parent::tearDown();
    }

    /**
     * Test that administrator can access admin page
     *
     * @return void
     */
    public function test_administrator_can_access_admin_page(): void
    {
        // Set current user to administrator
        \wp_set_current_user($this->admin_user_id);

        // Verify user has manage_options capability
        $this->assertTrue(\current_user_can("manage_options"));

        // Capture output from render_admin_page
        ob_start();
        try {
            $this->admin_panel->render_admin_page();
            $output = ob_get_clean();

            // Assert that page rendered successfully
            $this->assertNotEmpty($output);
            $this->assertStringContainsString("Silver Assist Security Essentials", $output);
            $this->assertStringContainsString("Security Status Dashboard", $output);
        } catch (\Exception $e) {
            ob_end_clean();
            $this->fail("Administrator should be able to access admin page: " . $e->getMessage());
        }
    }

    /**
     * Test that subscriber cannot access admin page
     *
     * @return void
     */
    public function test_subscriber_cannot_access_admin_page(): void
    {
        // Set current user to subscriber
        \wp_set_current_user($this->subscriber_user_id);

        // Verify user does NOT have manage_options capability
        $this->assertFalse(\current_user_can("manage_options"));

        // Expect wp_die() to be called with permission denied message
        $this->expectException(\WPDieException::class);

        // Attempt to render admin page - should throw WPDieException
        $this->admin_panel->render_admin_page();
    }

    /**
     * Test that unauthenticated users cannot access admin page
     *
     * @return void
     */
    public function test_unauthenticated_user_cannot_access_admin_page(): void
    {
        // Set current user to 0 (not logged in)
        \wp_set_current_user(0);

        // Verify user does NOT have manage_options capability
        $this->assertFalse(\current_user_can("manage_options"));

        // Expect wp_die() to be called
        $this->expectException(\WPDieException::class);

        // Attempt to render admin page - should throw WPDieException
        $this->admin_panel->render_admin_page();
    }

    /**
     * Test that editor role cannot access admin page
     *
     * Editors have many capabilities but not manage_options
     *
     * @return void
     */
    public function test_editor_cannot_access_admin_page(): void
    {
        // Create editor user
        $editor_user_id = $this->factory()->user->create([
            "role" => "editor"
        ]);

        // Set current user to editor
        \wp_set_current_user($editor_user_id);

        // Verify editor does NOT have manage_options capability
        $this->assertFalse(\current_user_can("manage_options"));

        // Expect wp_die() to be called
        $this->expectException(\WPDieException::class);

        // Attempt to render admin page - should throw WPDieException
        $this->admin_panel->render_admin_page();
    }

    /**
     * Test that custom role with manage_options can access admin page
     *
     * @return void
     */
    public function test_custom_role_with_capability_can_access(): void
    {
        // Create custom role with manage_options capability
        \add_role("security_manager", "Security Manager", [
            "read" => true,
            "manage_options" => true
        ]);

        // Create user with custom role
        $custom_user_id = $this->factory()->user->create([
            "role" => "security_manager"
        ]);

        // Set current user
        \wp_set_current_user($custom_user_id);

        // Verify user has manage_options capability
        $this->assertTrue(\current_user_can("manage_options"));

        // Capture output from render_admin_page
        ob_start();
        try {
            $this->admin_panel->render_admin_page();
            $output = ob_get_clean();

            // Assert that page rendered successfully
            $this->assertNotEmpty($output);
            $this->assertStringContainsString("Silver Assist Security Essentials", $output);
        } catch (\Exception $e) {
            ob_end_clean();
            $this->fail("User with manage_options should access page: " . $e->getMessage());
        }

        // Cleanup custom role
        \remove_role("security_manager");
    }

    /**
     * Test that capability check occurs before any data loading
     *
     * @return void
     */
    public function test_capability_check_occurs_first(): void
    {
        // Set current user to subscriber (no permissions)
        \wp_set_current_user($this->subscriber_user_id);

        // Monitor if any database queries happen before wp_die
        $query_count_before = $GLOBALS["wpdb"]->num_queries;

        try {
            $this->admin_panel->render_admin_page();
            $this->fail("Should have thrown WPDieException before executing");
        } catch (\WPDieException $e) {
            $query_count_after = $GLOBALS["wpdb"]->num_queries;

            // Capability check should happen BEFORE any data loading
            // Allow for minimal queries (WordPress core checks), but not data loading
            $queries_executed = $query_count_after - $query_count_before;
            $this->assertLessThan(5, $queries_executed, "Should check capabilities before loading data");
        }
    }

    /**
     * Test AJAX handlers also check capabilities
     *
     * @return void
     */
    public function test_ajax_handlers_check_capabilities(): void
    {
        // Set current user to subscriber
        \wp_set_current_user($this->subscriber_user_id);

        // Set up AJAX request
        $_POST["nonce"] = \wp_create_nonce("silver_assist_security_ajax");
        $_POST["action"] = "silver_assist_get_security_status";

        // Call AJAX handler directly
        ob_start();
        $this->admin_panel->ajax_get_security_status();
        $output = ob_get_clean();

        // Parse JSON response
        $response = json_decode($output, true);

        // Should return error due to permissions
        $this->assertFalse($response["success"]);
        $this->assertArrayHasKey("data", $response);
    }

    /**
     * Test that menu registration requires correct capabilities
     *
     * @return void
     */
    public function test_menu_registration_uses_correct_capability(): void
    {
        global $menu, $submenu;

        // Set current user to administrator
        \wp_set_current_user($this->admin_user_id);

        // Trigger admin_menu hook to register menus
        do_action("admin_menu");

        // Check if Settings Hub menu exists
        $found_hub_menu = false;
        if (class_exists("SilverAssist\\SettingsHub\\SettingsHub")) {
            // Settings Hub creates "silver-assist" parent menu
            foreach ($menu as $menu_item) {
                if ($menu_item[2] === "silver-assist") {
                    $found_hub_menu = true;
                    // Verify capability requirement
                    $this->assertEquals("manage_options", $menu_item[1]);
                    break;
                }
            }
        }

        // Check for standalone menu if hub not found
        if (!$found_hub_menu) {
            // Should find "settings_page_silver-assist-security" submenu under Settings
            $found_settings_menu = false;
            if (isset($submenu["options-general.php"])) {
                foreach ($submenu["options-general.php"] as $submenu_item) {
                    if ($submenu_item[2] === "silver-assist-security") {
                        $found_settings_menu = true;
                        // Verify capability requirement
                        $this->assertEquals("manage_options", $submenu_item[1]);
                        break;
                    }
                }
            }

            $this->assertTrue($found_settings_menu || $found_hub_menu, "Menu should be registered with proper capability");
        }
    }
}
