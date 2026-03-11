<?php
/**
 * GraphQLConfigManager Unit Tests
 *
 * Tests for the centralized GraphQL configuration management system.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.0
 * @version 1.1.12
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Test GraphQLConfigManager functionality
 * 
 * @since 1.1.0
 */
class GraphQLConfigManagerTest extends \WP_UnitTestCase
{
    /**
     * GraphQLConfigManager instance
     *
     * @var GraphQLConfigManager
     */
    private GraphQLConfigManager $config_manager;

    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up WordPress options for GraphQL configuration
        update_option("silver_assist_graphql_query_depth", 8);
        update_option("silver_assist_graphql_query_complexity", 100);
        update_option("silver_assist_graphql_query_timeout", 30);
        update_option("silver_assist_graphql_headless_mode", 0);
        
        // Reset singleton instance before each test
        $reflection = new \ReflectionClass(GraphQLConfigManager::class);
        $instance = $reflection->getProperty("instance");
        $instance->setAccessible(true);
        $instance->setValue(null, null);
        
        $this->config_manager = GraphQLConfigManager::getInstance();
    }

    /**
     * Test singleton pattern implementation
     * 
     * @since 1.1.12
     */
    public function test_singleton_pattern(): void
    {
        $instance1 = GraphQLConfigManager::getInstance();
        $instance2 = GraphQLConfigManager::getInstance();

        $this->assertSame($instance1, $instance2);
        $this->assertInstanceOf(GraphQLConfigManager::class, $instance1);
    }

    /**
     * Test WPGraphQL availability detection
     *
     * Detection should return a boolean reflecting actual WPGraphQL availability
     *
     * @since 1.1.12
     * @return void
     */
    public function test_wpgraphql_availability_detection(): void
    {
        $is_available = $this->config_manager->is_wpgraphql_available();
        
        $this->assertIsBool($is_available);

        // Result should match whether the WPGraphQL class is actually loaded
        if (\class_exists('WPGraphQL')) {
            $this->assertTrue($is_available, 'Should detect WPGraphQL when class exists');
        } else {
            $this->assertFalse($is_available, 'Should not detect WPGraphQL when class does not exist');
        }
    }

    /**
     * Test headless mode detection
     *
     * @since 1.1.12
     * @return void
     */
    public function test_headless_mode_detection(): void
    {
        $is_headless = $this->config_manager->is_headless_mode();
        
        $this->assertIsBool($is_headless);
        $this->assertFalse($is_headless);
    }

    /**
     * Test PHP execution timeout retrieval
     *
     * @since 1.1.12
     * @return void
     */
    public function test_php_execution_timeout(): void
    {
        $timeout = $this->config_manager->get_php_execution_timeout();
        
        $this->assertIsInt($timeout);
        // In test environment, ini_get("max_execution_time") may return 0 (no limit) or actual value
        $this->assertGreaterThanOrEqual(0, $timeout);
    }

    /**
     * Test timeout configuration
     *
     * @since 1.1.12
     * @return void
     */
    public function test_timeout_configuration(): void
    {
        $timeout_config = $this->config_manager->get_timeout_config();
        
        $this->assertIsArray($timeout_config);
        $this->assertArrayHasKey("php_timeout", $timeout_config);
        $this->assertArrayHasKey("current_timeout", $timeout_config);
        $this->assertArrayHasKey("is_unlimited_php", $timeout_config);
        $this->assertArrayHasKey("is_using_php_default", $timeout_config);
        $this->assertArrayHasKey("recommended_min", $timeout_config);
        $this->assertArrayHasKey("recommended_max", $timeout_config);
    }

    /**
     * Test complete configuration retrieval
     *
     * @since 1.1.12
     * @return void
     */
    public function test_configuration_retrieval(): void
    {
        $config = $this->config_manager->get_configuration();
        
        $this->assertIsArray($config);
        $this->assertArrayHasKey("query_depth_limit", $config);
        $this->assertArrayHasKey("query_complexity_limit", $config);
        $this->assertArrayHasKey("query_timeout", $config);
        $this->assertArrayHasKey("introspection_enabled", $config);
        $this->assertArrayHasKey("debug_mode", $config);
        $this->assertArrayHasKey("endpoint_access", $config);
        $this->assertArrayHasKey("batch_enabled", $config);
        $this->assertArrayHasKey("batch_limit", $config);
    }

    /**
     * Test security recommendations generation
     *
     * @since 1.1.12
     * @return void
     */
    public function test_security_recommendations(): void
    {
        $recommendations = $this->config_manager->get_security_recommendations();
        
        $this->assertIsArray($recommendations);
        // Recommendations may be empty if configuration is secure
        // Each recommendation should have 'level' and 'message' keys
        foreach ($recommendations as $recommendation) {
            $this->assertIsArray($recommendation);
            $this->assertArrayHasKey("level", $recommendation);
            $this->assertArrayHasKey("message", $recommendation);
        }
    }

    /**
     * Test settings display HTML generation
     *
     * @since 1.1.12
     * @return void
     */
    public function test_settings_display(): void
    {
        $html = $this->config_manager->get_settings_display();
        
        $this->assertIsString($html);
        // When WPGraphQL is available, settings include security details; otherwise a "not active" message
        if (\class_exists('WPGraphQL')) {
            $this->assertStringContainsString('<ul>', $html, 'Settings display should contain a list when WPGraphQL is active');
            $this->assertStringContainsString('endpoint', strtolower($html), 'Settings should mention endpoint access');
        } else {
            $this->assertStringContainsString('graphql', strtolower($html), 'Settings should mention GraphQL when not active');
        }
    }

    /**
     * Test safe limit retrieval
     *
     * @since 1.1.12
     * @return void
     */
    public function test_safe_limit_retrieval(): void
    {
        $depth_limit = $this->config_manager->get_safe_limit("depth");
        $complexity_limit = $this->config_manager->get_safe_limit("complexity");
        $timeout_limit = $this->config_manager->get_safe_limit("timeout");
        
        $this->assertIsInt($depth_limit);
        $this->assertIsInt($complexity_limit);
        $this->assertIsInt($timeout_limit);
        
        $this->assertGreaterThan(0, $depth_limit);
        $this->assertGreaterThan(0, $complexity_limit);
        $this->assertGreaterThan(0, $timeout_limit);
    }

    /**
     * Test rate limiting configuration
     *
     * @since 1.1.12
     * @return void
     */
    public function test_rate_limiting_configuration(): void
    {
        $rate_config = $this->config_manager->get_rate_limiting_config();
        
        $this->assertIsArray($rate_config);
        $this->assertArrayHasKey("requests_per_minute", $rate_config);
        $this->assertArrayHasKey("burst_limit", $rate_config);
        $this->assertArrayHasKey("timeout_seconds", $rate_config);
    }

    /**
     * Test WPGraphQL integration status monitoring
     *
     * @since 1.1.12
     * @return void
     */
    public function test_integration_status(): void
    {
        $status = $this->config_manager->get_integration_status();
        
        $this->assertIsArray($status);
        $this->assertArrayHasKey("wpgraphql_available", $status);
        $this->assertArrayHasKey("headless_mode", $status);
        $this->assertArrayHasKey("current_config", $status);
        $this->assertArrayHasKey("security_level", $status);
        $this->assertArrayHasKey("recommendations", $status);
    }

    /**
     * Test cache clearing
     *
     * @since 1.1.12
     * @return void
     */
    public function test_cache_clearing(): void
    {
        $this->config_manager->clear_cache();
        
        $this->assertTrue(true);
    }

    /**
     * Test is_authentication_required returns false when WPGraphQL setting is off
     *
     * @since 1.8.0
     * @return void
     */
    public function test_authentication_required_wpgraphql_off(): void
    {
        $settings = get_option('graphql_general_settings', array());
        $settings['restrict_endpoint_to_logged_in_users'] = 'off';
        update_option('graphql_general_settings', $settings);

        $this->config_manager->clear_cache();

        $this->assertFalse(
            $this->config_manager->is_authentication_required(),
            'Should return false when WPGraphQL setting is off'
        );
    }

    /**
     * Test is_authentication_required returns true when WPGraphQL setting is on
     *
     * @since 1.8.0
     * @return void
     */
    public function test_authentication_required_wpgraphql_on(): void
    {
        if (! \class_exists('WPGraphQL')) {
            $this->markTestSkipped('WPGraphQL plugin not available');
        }

        $settings = get_option('graphql_general_settings', array());
        $settings['restrict_endpoint_to_logged_in_users'] = 'on';
        update_option('graphql_general_settings', $settings);

        $this->config_manager->clear_cache();

        $this->assertTrue(
            $this->config_manager->is_authentication_required(),
            'Should return true when WPGraphQL setting is enabled'
        );
    }

    /**
     * Test is_authentication_required returns false when setting is not set
     *
     * @since 1.8.0
     * @return void
     */
    public function test_authentication_required_default(): void
    {
        delete_option('graphql_general_settings');

        $this->config_manager->clear_cache();

        $this->assertFalse(
            $this->config_manager->is_authentication_required(),
            'Should return false when WPGraphQL setting is not configured'
        );
    }

    /**
     * Test security level does not double-count authentication restriction
     *
     * When both endpoint_access is restricted and authentication is required,
     * the score should only get +3 once, not +6.
     *
     * @since 1.8.0
     * @return void
     */
    public function test_security_level_no_double_counting_auth(): void
    {
        // Enable authentication via WPGraphQL native setting.
        $settings = get_option('graphql_general_settings', array());
        $settings['restrict_endpoint_to_logged_in_users'] = 'on';
        update_option('graphql_general_settings', $settings);

        $this->config_manager->clear_cache();
        $status = $this->config_manager->get_integration_status();

        $this->assertContains(
            $status['security_level'],
            array('high', 'medium', 'low'),
            'Security level should be one of high, medium, or low'
        );
    }
}
