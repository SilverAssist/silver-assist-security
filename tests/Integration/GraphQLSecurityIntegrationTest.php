<?php
/**
 * Integration Tests for GraphQL Security Class
 *
 * Tests the complete GraphQL security system including query depth/complexity limits,
 * rate limiting, introspection control, and integration with WPGraphQL plugin.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.14
 */

namespace SilverAssist\Security\Tests\Integration;

use WP_UnitTestCase;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Class GraphQLSecurityIntegrationTest
 *
 * Integration tests for GraphQL security features with WordPress and WPGraphQL.
 *
 * @since 1.1.14
 */
class GraphQLSecurityIntegrationTest extends WP_UnitTestCase {

	/**
	 * GraphQL Security instance
	 *
	 * @var GraphQLSecurity|null
	 */
	private ?GraphQLSecurity $graphql_security = null;

	/**
	 * GraphQL Config Manager instance
	 *
	 * @var GraphQLConfigManager|null
	 */
	private ?GraphQLConfigManager $config_manager = null;

	/**
	 * Set up test environment
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		// Initialize config manager
		$this->config_manager = GraphQLConfigManager::getInstance();

		// Only initialize GraphQL security if WPGraphQL is available
		if ( \class_exists( 'WPGraphQL' ) ) {
			$this->graphql_security = new GraphQLSecurity();
		}
	}

	/**
	 * Clean up after each test
	 *
	 * @return void
	 */
	public function tearDown(): void {
		// Clean up transients
		\delete_transient( 'graphql_security_config' );
		\delete_transient( 'wpgraphql_config_cache' );

		parent::tearDown();
	}

	/**
	 * Test GraphQL security initialization with WPGraphQL plugin
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_graphql_security_initializes_with_wpgraphql(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL plugin not available' );
		}

		$security = new GraphQLSecurity();
		$this->assertInstanceOf( GraphQLSecurity::class, $security );
	}

	/**
	 * Test that GraphQL security registers WordPress hooks
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_graphql_security_registers_wordpress_hooks(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL plugin not available' );
		}

		$security = new GraphQLSecurity();

		// Check if hooks are registered
		$this->assertTrue( \has_action( 'init' ) !== false, 'init action should be registered' );
		$this->assertTrue( \has_filter( 'graphql_request_results' ) !== false, 'graphql_request_results filter should be registered' );
	}

	/**
	 * Test GraphQL configuration manager integration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_graphql_config_manager_integration(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$config         = $config_manager->get_configuration();

		$this->assertIsArray( $config, 'Configuration should be an array' );
		$this->assertArrayHasKey( 'query_depth_limit', $config );
		$this->assertArrayHasKey( 'query_complexity_limit', $config );
		$this->assertArrayHasKey( 'query_timeout', $config );
	}

	/**
	 * Test query depth limit configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_query_depth_limit_configuration(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$config         = $config_manager->get_configuration();
		$depth_limit    = $config['query_depth_limit'];

		$this->assertIsInt( $depth_limit, 'Query depth limit should be an integer' );
		$this->assertGreaterThan( 0, $depth_limit, 'Query depth limit should be greater than 0' );
		$this->assertLessThanOrEqual( 20, $depth_limit, 'Query depth limit should not exceed 20' );
	}

	/**
	 * Test query complexity limit configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_query_complexity_limit_configuration(): void {
		$config_manager   = GraphQLConfigManager::getInstance();
		$config           = $config_manager->get_configuration();
		$complexity_limit = $config['query_complexity_limit'];

		$this->assertIsInt( $complexity_limit, 'Query complexity limit should be an integer' );
		$this->assertGreaterThanOrEqual( 10, $complexity_limit, 'Query complexity limit should be at least 10' );
		$this->assertLessThanOrEqual( 1000, $complexity_limit, 'Query complexity limit should not exceed 1000' );
	}

	/**
	 * Test query timeout configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_query_timeout_configuration(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$config         = $config_manager->get_configuration();
		$timeout        = $config['query_timeout'];

		$this->assertIsInt( $timeout, 'Query timeout should be an integer' );
		$this->assertGreaterThan( 0, $timeout, 'Query timeout should be greater than 0' );
		$this->assertLessThanOrEqual( 30, $timeout, 'Query timeout should not exceed 30 seconds' );
	}

	/**
	 * Test WPGraphQL plugin detection
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_wpgraphql_plugin_detection(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$is_available   = $config_manager->is_wpgraphql_available();

		$this->assertIsBool( $is_available, 'WPGraphQL detection should return boolean' );

		if ( \class_exists( 'WPGraphQL' ) ) {
			$this->assertTrue( $is_available, 'Should detect WPGraphQL when class exists' );
		} else {
			$this->assertFalse( $is_available, 'Should not detect WPGraphQL when class does not exist' );
		}
	}

	/**
	 * Test headless mode detection
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_headless_mode_detection(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$is_headless    = $config_manager->is_headless_mode();

		$this->assertIsBool( $is_headless, 'Headless mode detection should return boolean' );
	}

	/**
	 * Test rate limiting configuration for standard mode
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_rate_limiting_standard_mode(): void {
		// Ensure headless mode is disabled
		\update_option( 'silver_assist_graphql_headless_mode', 0 );

		$config_manager     = GraphQLConfigManager::getInstance();
		$rate_limit_config  = $config_manager->get_rate_limiting_config();

		$this->assertIsArray( $rate_limit_config, 'Rate limit config should be an array' );
		$this->assertArrayHasKey( 'requests_per_minute', $rate_limit_config );
		$this->assertGreaterThan( 0, $rate_limit_config['requests_per_minute'], 'Rate limit should be greater than 0' );
	}

	/**
	 * Test rate limiting configuration for headless mode
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_rate_limiting_headless_mode(): void {
		// Enable headless mode
		\update_option( 'silver_assist_graphql_headless_mode', 1 );

		$config_manager     = GraphQLConfigManager::getInstance();
		$rate_limit_config  = $config_manager->get_rate_limiting_config();

		$this->assertIsArray( $rate_limit_config, 'Rate limit config should be an array' );
		$this->assertArrayHasKey( 'requests_per_minute', $rate_limit_config );
	}

	/**
	 * Test introspection blocking in production environment
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_introspection_disabled_in_production(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL plugin not available' );
		}

		// Enable introspection in WPGraphQL settings so the method doesn't early-return.
		$settings                                  = \get_option( 'graphql_general_settings', array() );
		$settings['public_introspection_enabled'] = 'on';
		\update_option( 'graphql_general_settings', $settings );

		// Clear singleton config cache so it picks up the new setting.
		GraphQLConfigManager::getInstance()->clear_cache();

		// If WP_ENVIRONMENT_TYPE is already defined as non-production, we can only verify
		// the method doesn't add the filter. Constants cannot be redefined in PHP.
		if ( defined( 'WP_ENVIRONMENT_TYPE' ) && WP_ENVIRONMENT_TYPE !== 'production' ) {
			$security = new GraphQLSecurity();
			$security->disable_introspection_in_production();
			$this->assertFalse(
				\has_filter( 'graphql_introspection_enabled' ) !== false,
				'Introspection filter should not be registered in non-production environment'
			);
		} else {
			// Define production environment if not already defined.
			if ( ! defined( 'WP_ENVIRONMENT_TYPE' ) ) {
				define( 'WP_ENVIRONMENT_TYPE', 'production' );
			}

			$security = new GraphQLSecurity();
			$security->disable_introspection_in_production();

			$this->assertTrue(
				\has_filter( 'graphql_introspection_enabled' ) !== false,
				'Introspection filter should be registered in production'
			);
		}

		// Cleanup.
		\delete_option( 'graphql_general_settings' );
	}

	/**
	 * Test security headers for GraphQL endpoint
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_graphql_security_headers(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL plugin not available' );
		}

		$security = new GraphQLSecurity();

		// Check if send_headers action is registered
		$this->assertTrue( \has_action( 'send_headers' ) !== false, 'send_headers action should be registered' );
	}

	/**
	 * Test safe limit calculation for aliases
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_safe_limit_for_aliases(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$alias_limit    = $config_manager->get_safe_limit( 'aliases' );

		$this->assertIsInt( $alias_limit, 'Alias limit should be an integer' );
		$this->assertGreaterThan( 0, $alias_limit, 'Alias limit should be greater than 0' );
	}

	/**
	 * Test safe limit calculation for directives
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_safe_limit_for_directives(): void {
		$config_manager   = GraphQLConfigManager::getInstance();
		$directive_limit  = $config_manager->get_safe_limit( 'directives' );

		$this->assertIsInt( $directive_limit, 'Directive limit should be an integer' );
		$this->assertGreaterThan( 0, $directive_limit, 'Directive limit should be greater than 0' );
	}

	/**
	 * Test safe limit calculation for field duplicates
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_safe_limit_for_field_duplicates(): void {
		$config_manager      = GraphQLConfigManager::getInstance();
		$field_dup_limit     = $config_manager->get_safe_limit( 'field_duplicates' );

		$this->assertIsInt( $field_dup_limit, 'Field duplicate limit should be an integer' );
		$this->assertGreaterThan( 0, $field_dup_limit, 'Field duplicate limit should be greater than 0' );
	}

	/**
	 * Test adaptive limits based on headless mode
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_adaptive_limits_headless_mode(): void {
		// Enable headless mode
		\update_option( 'silver_assist_graphql_headless_mode', 1 );

		$config_manager = GraphQLConfigManager::getInstance();
		$alias_limit    = $config_manager->get_safe_limit( 'aliases' );

		// Headless mode should have reasonable limits (20 is the actual value)
		$this->assertGreaterThanOrEqual( 15, $alias_limit, 'Headless mode should allow reasonable aliases' );
		$this->assertLessThanOrEqual( 25, $alias_limit, 'Headless mode limits should be controlled' );
	}

	/**
	 * Test adaptive limits based on standard mode
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_adaptive_limits_standard_mode(): void {
		// Disable headless mode
		\update_option( 'silver_assist_graphql_headless_mode', 0 );

		$config_manager = GraphQLConfigManager::getInstance();
		$alias_limit    = $config_manager->get_safe_limit( 'aliases' );

		// Standard mode should have conservative limits
		$this->assertLessThanOrEqual( 30, $alias_limit, 'Standard mode should have conservative alias limit' );
	}

	/**
	 * Test GraphQL security evaluation
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_security_evaluation(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$status         = $config_manager->get_integration_status();

		$this->assertIsArray( $status, 'Integration status should be an array' );
		$this->assertArrayHasKey( 'wpgraphql_available', $status );
		$this->assertArrayHasKey( 'headless_mode', $status );
		$this->assertArrayHasKey( 'current_config', $status );
		$this->assertArrayHasKey( 'security_level', $status );
		$this->assertArrayHasKey( 'recommendations', $status );
	}

	/**
	 * Test configuration caching
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_configuration_caching(): void {
		// Clear cache
		\delete_transient( 'graphql_security_config' );

		$config_manager = GraphQLConfigManager::getInstance();

		// First call should create cache
		$config1 = $config_manager->get_configuration();

		// Second call should use cache
		$config2 = $config_manager->get_configuration();

		$this->assertEquals( $config1, $config2, 'Cached configuration should match original' );
	}

	/**
	 * Test WPGraphQL native settings integration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_wpgraphql_native_settings_integration(): void {
		if ( ! \function_exists( 'get_graphql_setting' ) ) {
			$this->markTestSkipped( 'WPGraphQL settings function not available' );
		}

		$config_manager = GraphQLConfigManager::getInstance();
		$status         = $config_manager->get_integration_status();

		$this->assertIsArray( $status, 'Integration status should be an array' );
		$this->assertArrayHasKey( 'wpgraphql_available', $status, 'Status should include wpgraphql_available key' );
		$this->assertTrue( $status['wpgraphql_available'], 'WPGraphQL should be detected as available' );
	}

	/**
	 * Test GraphQL security with multiple instances
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_multiple_security_instances(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL plugin not available' );
		}

		$security1 = new GraphQLSecurity();
		$security2 = new GraphQLSecurity();

		$this->assertInstanceOf( GraphQLSecurity::class, $security1 );
		$this->assertInstanceOf( GraphQLSecurity::class, $security2 );
		$this->assertNotSame( $security1, $security2, 'Each GraphQLSecurity instance should be unique' );
	}

	/**
	 * Test configuration HTML generation for admin display
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_configuration_html_generation(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$html           = $config_manager->get_settings_display();

		$this->assertIsString( $html, 'Configuration HTML should be a string' );
		$this->assertNotEmpty( $html, 'Configuration HTML should not be empty' );
	}

	/**
	 * Test all configuration values are within valid ranges
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_all_configuration_values_valid(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$config         = $config_manager->get_configuration();

		$this->assertIsArray( $config, 'All configurations should be an array' );
		$this->assertNotEmpty( $config, 'Configurations should not be empty' );

		// Verify query depth
		if ( isset( $config['query_depth_limit'] ) ) {
			$this->assertGreaterThan( 0, $config['query_depth_limit'] );
			$this->assertLessThanOrEqual( 20, $config['query_depth_limit'] );
		}

		// Verify query complexity
		if ( isset( $config['query_complexity_limit'] ) ) {
			$this->assertGreaterThanOrEqual( 10, $config['query_complexity_limit'] );
			$this->assertLessThanOrEqual( 1000, $config['query_complexity_limit'] );
		}

		// Verify timeout
		if ( isset( $config['query_timeout'] ) ) {
			$this->assertGreaterThan( 0, $config['query_timeout'] );
			$this->assertLessThanOrEqual( 30, $config['query_timeout'] );
		}
	}

	/**
	 * Test GraphQL security initialization without WPGraphQL
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_graceful_handling_without_wpgraphql(): void {
		// This test verifies the plugin doesn't break when WPGraphQL is not active
		$config_manager = GraphQLConfigManager::getInstance();

		$this->assertInstanceOf( GraphQLConfigManager::class, $config_manager );

		// Should still provide default configuration
		$config = $config_manager->get_configuration();
		$this->assertIsArray( $config );
	}

	/**
	 * Test security recommendations generation
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_security_recommendations(): void {
		$config_manager = GraphQLConfigManager::getInstance();
		$html           = $config_manager->get_settings_display();

		// HTML output should always be a string
		$this->assertIsString( $html );
		$this->assertNotEmpty( $html, 'Settings display should not be empty' );

		// Should contain either WPGraphQL configuration or "not active" message
		$has_graphql_content = (
			stripos( $html, 'WPGraphQL' ) !== false ||
			stripos( $html, 'Endpoint' ) !== false ||
			stripos( $html, 'Query' ) !== false ||
			stripos( $html, 'not active' ) !== false
		);

		$this->assertTrue( $has_graphql_content, 'HTML should contain WPGraphQL-related content' );
	}
}
