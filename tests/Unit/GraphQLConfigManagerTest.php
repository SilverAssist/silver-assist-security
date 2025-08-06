<?php
/**
 * GraphQLConfigManager Unit Tests
 *
 * Tests for the centralized GraphQL configuration management system.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.0
 */

namespace SilverAssist\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\TestHelper;

/**
 * Test GraphQLConfigManager functionality
 * 
 * @since 1.1.0
 */
class GraphQLConfigManagerTest extends TestCase
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
        
        // Reset singleton for clean testing
        $reflection = new \ReflectionClass(GraphQLConfigManager::class);
        $instance = $reflection->getProperty("instance");
        $instance->setAccessible(true);
        $instance->setValue(null, null);
        
        $this->config_manager = GraphQLConfigManager::getInstance();
    }

    /**
     * Clean up after tests
     */
    protected function tearDown(): void
    {
        // Reset any WordPress options that might have been set during testing
        delete_option("silver_assist_graphql_query_depth");
        delete_option("silver_assist_graphql_query_complexity");
        delete_option("silver_assist_graphql_query_timeout");
        
        // Clear any transients
        delete_transient("graphql_config_query_depth");
        delete_transient("graphql_config_query_complexity");
        delete_transient("graphql_config_query_timeout");
        delete_transient("graphql_config_rate_limit");
        delete_transient("graphql_config_wpgraphql_active");
        delete_transient("graphql_config_headless_mode");
        
        parent::tearDown();
    }

    /**
     * Test singleton pattern implementation
     * 
     * @since 1.1.0
     */
    public function test_singleton_pattern(): void
    {
        $instance1 = GraphQLConfigManager::getInstance();
        $instance2 = GraphQLConfigManager::getInstance();
        
        $this->assertSame($instance1, $instance2, "GraphQLConfigManager should implement singleton pattern");
        $this->assertInstanceOf(GraphQLConfigManager::class, $instance1);
    }

    /**
     * Test query depth configuration
     * 
     * @since 1.1.0
     */
    public function test_query_depth_configuration(): void
    {
        // Test default value
        $depth = $this->config_manager->get_query_depth();
        $this->assertIsInt($depth, "Query depth should be integer");
        $this->assertGreaterThan(0, $depth, "Query depth should be positive");
        $this->assertLessThanOrEqual(50, $depth, "Query depth should be reasonable");
        
        // Test with custom WordPress option
        update_option("silver_assist_graphql_query_depth", 15);
        
        // Reset singleton to pick up new option
        $reflection = new \ReflectionClass(GraphQLConfigManager::class);
        $instance = $reflection->getProperty("instance");
        $instance->setAccessible(true);
        $instance->setValue(null, null);
        
        $new_manager = GraphQLConfigManager::getInstance();
        $custom_depth = $new_manager->get_query_depth();
        $this->assertEquals(15, $custom_depth, "Should use custom WordPress option value");
    }

    /**
     * Test query complexity configuration
     * 
     * @since 1.1.0
     */
    public function test_query_complexity_configuration(): void
    {
        $complexity = $this->config_manager->get_query_complexity();
        $this->assertIsInt($complexity, "Query complexity should be integer");
        $this->assertGreaterThan(0, $complexity, "Query complexity should be positive");
    }

    /**
     * Test query timeout configuration
     * 
     * @since 1.1.0
     */
    public function test_query_timeout_configuration(): void
    {
        $timeout = $this->config_manager->get_query_timeout();
        $this->assertIsInt($timeout, "Query timeout should be integer");
        $this->assertGreaterThan(0, $timeout, "Query timeout should be positive");
        $this->assertLessThanOrEqual(30, $timeout, "Query timeout should be reasonable");
    }

    /**
     * Test intelligent rate limiting
     * 
     * @since 1.1.0
     */
    public function test_rate_limiting(): void
    {
        $rate_limit = $this->config_manager->get_rate_limit();
        $this->assertIsInt($rate_limit, "Rate limit should be integer");
        $this->assertGreaterThan(0, $rate_limit, "Rate limit should be positive");
        
        // Rate limit should be reasonable (between 10 and 200 requests per minute)
        $this->assertGreaterThanOrEqual(10, $rate_limit, "Rate limit should allow reasonable usage");
        $this->assertLessThanOrEqual(200, $rate_limit, "Rate limit should prevent abuse");
    }

    /**
     * Test WPGraphQL detection
     * 
     * @since 1.1.0
     */
    public function test_wpgraphql_detection(): void
    {
        $is_active = $this->config_manager->is_wpgraphql_active();
        $this->assertIsBool($is_active, "WPGraphQL detection should return boolean");
        
        // The actual value depends on test environment, but should be consistent
        $is_active_second_call = $this->config_manager->is_wpgraphql_active();
        $this->assertEquals($is_active, $is_active_second_call, "WPGraphQL detection should be consistent");
    }

    /**
     * Test headless mode detection
     * 
     * @since 1.1.0
     */
    public function test_headless_mode_detection(): void
    {
        $is_headless = $this->config_manager->is_headless_mode();
        $this->assertIsBool($is_headless, "Headless mode detection should return boolean");
    }

    /**
     * Test security level evaluation
     * 
     * @since 1.1.0
     */
    public function test_security_level_evaluation(): void
    {
        $security_level = $this->config_manager->evaluate_security_level();
        $this->assertIsString($security_level, "Security level should be string");
        
        $valid_levels = ["low", "medium", "high", "maximum"];
        $this->assertContains($security_level, $valid_levels, "Security level should be valid");
    }

    /**
     * Test complete configuration retrieval
     * 
     * @since 1.1.0
     */
    public function test_all_configurations(): void
    {
        $config = $this->config_manager->get_all_configurations();
        $this->assertIsArray($config, "All configurations should return array");
        
        // Check required keys exist
        $required_keys = [
            "query_depth_limit",
            "query_complexity_limit", 
            "query_timeout",
            "rate_limit",
            "is_wpgraphql_active",
            "is_headless_mode",
            "security_level"
        ];
        
        foreach ($required_keys as $key) {
            $this->assertArrayHasKey($key, $config, "Configuration should include {$key}");
        }
        
        // Verify data types
        $this->assertIsInt($config["query_depth_limit"], "Query depth should be integer");
        $this->assertIsInt($config["query_complexity_limit"], "Query complexity should be integer");
        $this->assertIsInt($config["query_timeout"], "Query timeout should be integer");
        $this->assertIsInt($config["rate_limit"], "Rate limit should be integer");
        $this->assertIsBool($config["is_wpgraphql_active"], "WPGraphQL status should be boolean");
        $this->assertIsBool($config["is_headless_mode"], "Headless mode should be boolean");
        $this->assertIsString($config["security_level"], "Security level should be string");
    }

    /**
     * Test configuration caching
     * 
     * @since 1.1.0
     */
    public function test_configuration_caching(): void
    {
        // First call should cache the configuration
        $depth1 = $this->config_manager->get_query_depth();
        
        // Second call should use cached value (same result)
        $depth2 = $this->config_manager->get_query_depth();
        
        $this->assertEquals($depth1, $depth2, "Cached configuration should be consistent");
        
        // Verify that transients are being used for caching
        $cached_depth = get_transient("graphql_config_query_depth");
        if ($cached_depth !== false) {
            $this->assertEquals($depth1, $cached_depth, "Transient cache should match configuration");
        }
    }

    /**
     * Test configuration HTML generation
     * 
     * @since 1.1.0
     */
    public function test_configuration_html(): void
    {
        $html = $this->config_manager->get_configuration_html();
        $this->assertIsString($html, "Configuration HTML should be string");
        $this->assertNotEmpty($html, "Configuration HTML should not be empty");
        
        // Should contain basic HTML structure
        $this->assertStringContainsString("<div", $html, "HTML should contain div elements");
        
        // Should contain configuration values
        $depth = $this->config_manager->get_query_depth();
        $this->assertStringContainsString((string)$depth, $html, "HTML should display query depth");
    }

    /**
     * Test error handling for missing WPGraphQL
     * 
     * @since 1.1.0
     */
    public function test_missing_wpgraphql_handling(): void
    {
        // This test assumes WPGraphQL might not be available in test environment
        // The configuration should still work with fallback values
        
        $config = $this->config_manager->get_all_configurations();
        $this->assertIsArray($config, "Configuration should work even without WPGraphQL");
        
        // All required values should still be present and valid
        $this->assertGreaterThan(0, $config["query_depth_limit"], "Should have fallback query depth");
        $this->assertGreaterThan(0, $config["query_complexity_limit"], "Should have fallback complexity");
        $this->assertGreaterThan(0, $config["query_timeout"], "Should have fallback timeout");
        $this->assertGreaterThan(0, $config["rate_limit"], "Should have fallback rate limit");
    }
}
