<?php
/**
 * Admin Panel Integration Tests
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Integration;

use PHPUnit\Framework\TestCase;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\TestHelper;

/**
 * Test AdminPanel integration
 */
class AdminPanelTest extends TestCase
{
    /**
     * AdminPanel instance
     *
     * @var AdminPanel
     */
    private AdminPanel $admin_panel;

    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Mock admin environment
        global $pagenow;
        $pagenow = "admin.php";

        // Set admin user
        $admin_id = TestHelper::create_test_user(["role" => "administrator"]);
        wp_set_current_user($admin_id);

        // Initialize AdminPanel
        $this->admin_panel = new AdminPanel();
    }

    /**
     * Clean up after tests
     */
    protected function tearDown(): void
    {
        wp_set_current_user(0);
        parent::tearDown();
    }

    /**
     * Test admin panel initialization
     */
    public function test_admin_panel_initialization(): void
    {
        $this->assertInstanceOf(AdminPanel::class, $this->admin_panel);
    }

    /**
     * Test AJAX auto-save functionality
     */
    public function test_ajax_auto_save(): void
    {
        // Mock AJAX request with current available settings
        $_POST = [
            "action" => "silver_assist_auto_save",
            "nonce" => wp_create_nonce("silver_assist_security_ajax"),
            "silver_assist_login_attempts" => "10",
            "silver_assist_lockout_duration" => "1800",
            "silver_assist_session_timeout" => "60",
            "silver_assist_password_strength_enforcement" => "1",
            "silver_assist_bot_protection" => "1",
            "silver_assist_graphql_query_depth" => "10",
            "silver_assist_graphql_query_complexity" => "200",
            "silver_assist_graphql_query_timeout" => "10"
        ];

        // Capture output
        ob_start();

        try {
            $this->admin_panel->ajax_auto_save();
        } catch (\Exception $e) {
            // May exit with wp_send_json_success
        }

        $output = ob_get_clean();

        // Verify settings were saved
        $this->assertEquals("10", get_option("silver_assist_login_attempts"));
        $this->assertEquals("1800", get_option("silver_assist_lockout_duration"));
        $this->assertEquals("60", get_option("silver_assist_session_timeout"));
    }

    /**
     * Test security status AJAX endpoint
     */
    public function test_ajax_security_status(): void
    {
        // Mock AJAX request
        $_POST = [
            "action" => "silver_assist_get_security_status",
            "nonce" => wp_create_nonce("silver_assist_security_ajax")
        ];

        // Capture output
        ob_start();

        try {
            $this->admin_panel->ajax_get_security_status();
        } catch (\Exception $e) {
            // May exit with wp_send_json_success
        }

        $output = ob_get_clean();

        // Should contain JSON response
        $this->assertJson($output, "Security status should return valid JSON");

        $data = json_decode($output, true);
        $this->assertArrayHasKey("success", $data, "Response should have success key");
    }

    /**
     * Test admin menu registration
     */
    public function test_admin_menu_registration(): void
    {
        global $menu, $submenu;

        // Trigger admin_menu action
        do_action('admin_menu');

        // Check if our menu was added
        $found_menu = false;
        if (isset($submenu["options-general.php"])) {
            foreach ($submenu["options-general.php"] as $item) {
                if (in_array("silver-assist-security", $item)) {
                    $found_menu = true;
                    break;
                }
            }
        }

        $this->assertTrue($found_menu, "Admin menu should be registered under Settings");
    }

    /**
     * Test settings registration
     */
    public function test_settings_registration(): void
    {
        global $wp_settings_fields;

        // Trigger admin_init action
        do_action("admin_init");

        // Check if settings are registered
        $this->assertArrayHasKey("silver_assist_login_attempts", $wp_settings_fields, "Login attempts setting should be registered");
        $this->assertArrayHasKey("silver_assist_custom_admin_url", $wp_settings_fields, "Custom admin URL setting should be registered");
    }

    /**
     * Test admin scripts enqueuing
     */
    public function test_admin_scripts_enqueuing(): void
    {
        global $wp_scripts, $wp_styles;

        // Mock admin page
        $_GET["page"] = "silver-assist-security";

        // Trigger script enqueuing
        do_action("admin_enqueue_scripts", "settings_page_silver-assist-security");

        // Check if scripts are enqueued
        $this->assertTrue(wp_script_is("silver-assist-security-admin", "enqueued"), "Admin script should be enqueued");
        $this->assertTrue(wp_style_is("silver-assist-security-admin", "enqueued"), "Admin style should be enqueued");
    }

    /**
     * Test form validation
     */
    public function test_form_validation(): void
    {
        // Test with invalid data
        $_POST = [
            "silver_assist_login_attempts" => "0", // Invalid: too low
            "silver_assist_lockout_duration" => "30", // Invalid: too low
            "silver_assist_session_timeout" => "200", // Invalid: too high
        ];

        ob_start();

        try {
            $this->admin_panel->save_security_settings();
        } catch (\Exception $e) {
            // May redirect on validation error
        }

        ob_get_clean();

        // Values should not be saved if validation fails
        $this->assertNotEquals("0", get_option("silver_assist_login_attempts"));
    }

    /**
     * Test AdminPanel integration with GraphQLConfigManager
     * 
     * @since 1.1.0
     */
    public function test_admin_panel_graphql_config_integration(): void
    {
        // Skip if WPGraphQL not available
        if (!class_exists("WPGraphQL")) {
            $this->markTestSkipped("WPGraphQL not available");
            return;
        }

        // Test that AdminPanel can access GraphQLConfigManager
        $config_manager = GraphQLConfigManager::getInstance();
        $this->assertInstanceOf(GraphQLConfigManager::class, $config_manager);

        // Test that configuration methods work
        $config = $config_manager->get_all_configurations();
        $this->assertIsArray($config, "GraphQLConfigManager should provide configuration array");

        // Test that AdminPanel doesn't break with centralized GraphQL configuration
        ob_start();
        try {
            $this->admin_panel->ajax_get_security_status();
        } catch (\Exception $e) {
            // May exit with wp_send_json_success
        }
        $output = ob_get_clean();

        // Should not cause fatal errors or exceptions related to GraphQL configuration
        $this->assertNotNull($output, "AdminPanel should work with centralized GraphQL configuration");
    }

    /**
     * Test that GraphQL settings are handled through GraphQLConfigManager
     * 
     * @since 1.1.0
     */
    public function test_graphql_settings_centralization(): void
    {
        // Skip if WPGraphQL not available
        if (!class_exists("WPGraphQL")) {
            $this->markTestSkipped("WPGraphQL not available");
            return;
        }

        $config_manager = GraphQLConfigManager::getInstance();

        // Test that we can get consistent GraphQL configuration
        $depth1 = $config_manager->get_query_depth();
        $depth2 = $config_manager->get_query_depth();

        $this->assertEquals($depth1, $depth2, "GraphQL configuration should be consistent");
        $this->assertIsInt($depth1, "Query depth should be integer");
        $this->assertGreaterThan(0, $depth1, "Query depth should be positive");

        // Test that AdminPanel doesn't duplicate GraphQL configuration logic
        $reflection = new \ReflectionClass($this->admin_panel);
        $methods = $reflection->getMethods(\ReflectionMethod::IS_PUBLIC | \ReflectionMethod::IS_PROTECTED | \ReflectionMethod::IS_PRIVATE);

        $graphql_methods = array_filter($methods, function ($method) {
            return strpos(strtolower($method->getName()), "graphql") !== false;
        });

        // AdminPanel should have minimal GraphQL-specific methods since configuration is centralized
        $this->assertLessThan(5, count($graphql_methods), "AdminPanel should have minimal GraphQL methods due to centralization");
    }
}
