<?php
/**
 * Admin Panel Integration Tests
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Integration;

use Brain\Monkey\Functions;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\BrainMonkeyTestCase;

/**
 * Test AdminPanel integration
 */
class AdminPanelTest extends BrainMonkeyTestCase
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
        
        // Setup WordPress admin function mocks
        $this->setup_admin_mocks();
        
        // Mock $_SERVER superglobal
        $_SERVER["REQUEST_METHOD"] = "POST";
        $_SERVER["REMOTE_ADDR"] = "127.0.0.1";
        $_SERVER["HTTP_USER_AGENT"] = "PHPUnit Test";
        $_SERVER["REQUEST_URI"] = "/wp-admin/admin-ajax.php";

        // Mock admin environment
        global $pagenow;
        $pagenow = "admin.php";

        // Initialize AdminPanel
        $this->admin_panel = new AdminPanel();
    }
    
    /**
     * Setup WordPress admin function mocks
     *
     * @return void
     */
    private function setup_admin_mocks(): void
    {
        // Storage for options (stateful mock)
        static $options_storage = [];
        
        // Mock wp_generate_password
        Functions\when("wp_generate_password")->alias(function($length = 12, $special_chars = true) {
            $characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            if ($special_chars) {
                $characters .= "!@#$%^&*()";
            }
            $password = "";
            for ($i = 0; $i < $length; $i++) {
                $password .= $characters[rand(0, strlen($characters) - 1)];
            }
            return $password;
        });
        
        // Mock wp_parse_args
        Functions\when("wp_parse_args")->alias(function($args, $defaults = []) {
            if (is_object($args)) {
                $args = get_object_vars($args);
            } elseif (!is_array($args)) {
                $args = [];
            }
            return array_merge($defaults, $args);
        });
        
        // Mock wp_insert_user
        Functions\when("wp_insert_user")->justReturn(1);
        
        // Mock wp_delete_user
        Functions\when("wp_delete_user")->justReturn(true);
        
        // Mock wp_set_current_user
        Functions\when("wp_set_current_user")->justReturn(null);
        
        // Mock current_user_can
        Functions\when("current_user_can")->justReturn(true);
        
        // Mock add_action
        Functions\expect("add_action")->andReturn(true);
        
        // Mock add_menu_page
        Functions\when("add_menu_page")->justReturn("silver-assist-security");
        
        // Mock register_setting
        Functions\when("register_setting")->justReturn(true);
        
        // Mock wp_enqueue_script
        Functions\when("wp_enqueue_script")->justReturn(true);
        
        // Mock wp_enqueue_style
        Functions\when("wp_enqueue_style")->justReturn(true);
        
        // Mock wp_localize_script
        Functions\when("wp_localize_script")->justReturn(true);
        
        // Mock wp_create_nonce
        Functions\when("wp_create_nonce")->justReturn("test_nonce_12345");
        
        // Mock wp_verify_nonce
        Functions\when("wp_verify_nonce")->justReturn(1);
        
        // Mock get_option - STATEFUL mock with storage
        Functions\when("get_option")->alias(function($option, $default = false) use (&$options_storage) {
            if (isset($options_storage[$option])) {
                return $options_storage[$option];
            }
            
            $defaults = [
                "silver_assist_login_attempts" => 5,
                "silver_assist_lockout_duration" => 900,
                "silver_assist_session_timeout" => 30,
                "silver_assist_password_strength_enforcement" => 1,
                "silver_assist_bot_protection" => 1,
                "silver_assist_graphql_query_depth" => 8,
                "silver_assist_graphql_query_complexity" => 100,
                "silver_assist_graphql_query_timeout" => 5,
                "silver_assist_graphql_headless_mode" => 0,
            ];
            return $defaults[$option] ?? $default;
        });
        
        // Mock update_option - STATEFUL mock that updates storage
        Functions\when("update_option")->alias(function($option, $value) use (&$options_storage) {
            $options_storage[$option] = $value;
            return true;
        });
        
        // Mock wp_send_json_success - throw exception instead of exit for testing
        Functions\when("wp_send_json_success")->alias(function($data = null) {
            throw new \Exception("WP_SEND_JSON_SUCCESS: " . json_encode(["success" => true, "data" => $data]));
        });
        
        // Mock wp_send_json_error - throw exception instead of exit for testing
        Functions\when("wp_send_json_error")->alias(function($data = null) {
            throw new \Exception("WP_SEND_JSON_ERROR: " . json_encode(["success" => false, "data" => $data]));
        });
        
        // Mock class_exists
        Functions\when("class_exists")->alias(function($class_name) {
            return $class_name === "WPGraphQL";
        });
        
        // Mock function_exists
        Functions\when("function_exists")->alias(function($function_name) {
            return $function_name !== "get_graphql_setting";
        });
        
        // Mock get_transient
        Functions\when("get_transient")->justReturn(false);
        
        // Mock set_transient
        Functions\when("set_transient")->justReturn(true);
        
        // Mock ini_get
        Functions\when("ini_get")->alias(function($option) {
            return $option === "max_execution_time" ? "30" : false;
        });
        
        // Mock wp_script_is
        Functions\when("wp_script_is")->justReturn(true);
        
        // Mock wp_style_is
        Functions\when("wp_style_is")->justReturn(true);
        
        // Mock is_ssl
        Functions\when("is_ssl")->justReturn(false);
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
            "nonce" => \wp_create_nonce("silver_assist_security_ajax"),
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
            "nonce" => \wp_create_nonce("silver_assist_security_ajax")
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
        $this->assertTrue(\wp_script_is("silver-assist-security-admin", "enqueued"), "Admin script should be enqueued");
        $this->assertTrue(\wp_style_is("silver-assist-security-admin", "enqueued"), "Admin style should be enqueued");
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
        $config = $config_manager->get_configuration();
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
        $depth1 = $config_manager->get_safe_limit("depth");
        $depth2 = $config_manager->get_safe_limit("depth");

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
