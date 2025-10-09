<?php
/**
 * Security-focused Tests
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Security;

use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use WP_UnitTestCase;

/**
 * Test security implementations
 */
class SecurityTest extends WP_UnitTestCase
{
    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Configure GraphQL options for testing
        update_option("silver_assist_graphql_query_depth", 8);
        update_option("silver_assist_graphql_query_complexity", 100);
        update_option("silver_assist_graphql_query_timeout", 5);
        update_option("silver_assist_graphql_headless_mode", 0);
    }
    
    /**
     * Test GraphQLConfigManager API methods
     * 
     * @since 1.1.0
     */
    public function test_graphql_config_manager_api(): void
    {
        $config_manager = GraphQLConfigManager::getInstance();

        // Test singleton pattern
        $config_manager2 = GraphQLConfigManager::getInstance();
        $this->assertSame($config_manager, $config_manager2, "GraphQLConfigManager should be singleton");

        // Test get_safe_limit method
        $depth_limit = $config_manager->get_safe_limit("depth");
        $this->assertIsInt($depth_limit, "Query depth should be integer");
        $this->assertGreaterThan(0, $depth_limit, "Query depth should be positive");
        $this->assertLessThanOrEqual(50, $depth_limit, "Query depth should be reasonable");
        
        $complexity_limit = $config_manager->get_safe_limit("complexity");
        $this->assertIsInt($complexity_limit, "Query complexity should be integer");
        $this->assertGreaterThan(0, $complexity_limit, "Query complexity should be positive");
        
        $timeout_limit = $config_manager->get_safe_limit("timeout");
        $this->assertIsInt($timeout_limit, "Query timeout should be integer");
        $this->assertGreaterThan(0, $timeout_limit, "Query timeout should be positive");
        
        // Test get_configuration method
        $config = $config_manager->get_configuration();
        $this->assertIsArray($config, "Configuration should be array");
        $this->assertArrayHasKey("query_depth_limit", $config);
        $this->assertArrayHasKey("query_complexity_limit", $config);
        $this->assertArrayHasKey("query_timeout", $config);
        
        // Test rate limiting configuration
        $rate_config = $config_manager->get_rate_limiting_config();
        $this->assertIsArray($rate_config, "Rate limiting config should be array");
        $this->assertArrayHasKey("requests_per_minute", $rate_config);
        $this->assertIsInt($rate_config["requests_per_minute"]);
        $this->assertGreaterThan(0, $rate_config["requests_per_minute"]);
        
        // Test WPGraphQL availability check
        $this->assertIsBool($config_manager->is_wpgraphql_available(), "WPGraphQL status should be boolean");
        
        // Test headless mode check
        $this->assertIsBool($config_manager->is_headless_mode(), "Headless mode should be boolean");
    }
}
