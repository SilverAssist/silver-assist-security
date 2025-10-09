<?php
/**
 * WordPress Integration Tests for AdminPanel
 *
 * Tests AdminPanel functionality with real WordPress environment
 *
 * @package SilverAssist\Security\Tests\WordPress
 * @since 1.1.10
 */

namespace SilverAssist\Security\Tests\WordPress;

use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use WP_UnitTestCase;

/**
 * AdminPanel WordPress Integration Tests
 * 
 * Uses WP_UnitTestCase to test AdminPanel with real WordPress environment
 */
class AdminPanelTest extends WP_UnitTestCase
{
    /**
     * AdminPanel instance
     *
     * @var AdminPanel
     */
    private AdminPanel $admin_panel;

    /**
     * Set up test environment with WordPress
     */
    public function set_up(): void
    {
        parent::set_up();
        
        // Initialize AdminPanel with real WordPress environment
        $this->admin_panel = new AdminPanel();
    }

    /**
     * Clean up after tests
     */
    public function tear_down(): void
    {
        parent::tear_down();
    }

    /**
     * Test admin panel initialization
     */
    public function test_admin_panel_initialization(): void
    {
        $this->assertInstanceOf(AdminPanel::class, $this->admin_panel);
    }

    /**
     * Test GraphQLConfigManager integration
     */
    public function test_graphql_config_manager_integration(): void
    {
        $config_manager = GraphQLConfigManager::getInstance();
        
        $this->assertInstanceOf(GraphQLConfigManager::class, $config_manager);
        
        // Test configuration methods with real WordPress
        $this->assertIsInt($config_manager->get_safe_limit("depth"));
        $this->assertIsInt($config_manager->get_safe_limit("complexity"));
        $this->assertIsInt($config_manager->get_safe_limit("timeout"));
        
        $config = $config_manager->get_configuration();
        $this->assertIsArray($config);
        $this->assertArrayHasKey("query_depth_limit", $config);
        $this->assertArrayHasKey("query_complexity_limit", $config);
    }

    /**
     * Test WordPress options integration
     */
    public function test_wordpress_options_integration(): void
    {
        // Test setting and getting options
        $test_value = 10;
        update_option("silver_assist_login_attempts", $test_value);
        
        $retrieved = get_option("silver_assist_login_attempts");
        $this->assertEquals($test_value, $retrieved);
        
        // Test default value
        $default_value = get_option("silver_assist_lockout_duration", 900);
        $this->assertIsInt($default_value);
    }

    /**
     * Test admin menu registration
     */
    public function test_admin_menu_registration(): void
    {
        global $menu, $submenu;
        
        // Set current user as administrator
        $user_id = $this->factory()->user->create(["role" => "administrator"]);
        wp_set_current_user($user_id);
        
        // Trigger admin_menu action
        do_action("admin_menu");
        
        // Verify menu was registered
        $this->assertNotEmpty($submenu);
    }

    /**
     * Test settings registration
     */
    public function test_settings_registration(): void
    {
        global $wp_registered_settings;
        
        // Trigger admin_init action
        do_action("admin_init");
        
        // Verify settings are registered
        $this->assertArrayHasKey("silver_assist_login_attempts", $wp_registered_settings);
    }

    /**
     * Test nonce creation and verification
     */
    public function test_nonce_functionality(): void
    {
        $action = "silver_assist_security_ajax";
        $nonce = wp_create_nonce($action);
        
        $this->assertNotEmpty($nonce);
        $this->assertIsString($nonce);
        
        // Verify nonce
        $result = wp_verify_nonce($nonce, $action);
        $this->assertEquals(1, $result);
        
        // Test invalid nonce
        $invalid_result = wp_verify_nonce("invalid_nonce", $action);
        $this->assertFalse($invalid_result);
    }

    /**
     * Test transient functionality
     */
    public function test_transient_functionality(): void
    {
        $key = "silver_assist_test_transient";
        $value = ["test" => "data", "number" => 123];
        
        // Set transient
        $set_result = set_transient($key, $value, 60);
        $this->assertTrue($set_result);
        
        // Get transient
        $retrieved = get_transient($key);
        $this->assertEquals($value, $retrieved);
        
        // Delete transient
        $delete_result = delete_transient($key);
        $this->assertTrue($delete_result);
        
        // Verify deletion
        $after_delete = get_transient($key);
        $this->assertFalse($after_delete);
    }

    /**
     * Test user capability checks
     */
    public function test_user_capability_checks(): void
    {
        // Create test users
        $admin_id = $this->factory()->user->create(["role" => "administrator"]);
        $subscriber_id = $this->factory()->user->create(["role" => "subscriber"]);
        
        // Test administrator capabilities
        wp_set_current_user($admin_id);
        $this->assertTrue(current_user_can("manage_options"));
        $this->assertTrue(current_user_can("activate_plugins"));
        
        // Test subscriber capabilities
        wp_set_current_user($subscriber_id);
        $this->assertFalse(current_user_can("manage_options"));
        $this->assertFalse(current_user_can("activate_plugins"));
    }
}
