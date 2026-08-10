<?php
/**
 * REST API Security Integration Tests
 *
 * Integration tests for RestAPISecurity class testing real-world scenarios
 * with feature activation/deactivation, REST endpoint handling.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.0
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Security\RestAPISecurity;
use WP_REST_Request;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Integration test class for RestAPISecurity
 *
 * Tests REST API security integration with WordPress and plugin initialization.
 *
 * @since 1.5.0
 */
class RestAPISecurityIntegrationTest extends WP_UnitTestCase {

	/**
	 * Plugin instance
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * REST API Security instance
	 *
	 * @var RestAPISecurity
	 */
	private RestAPISecurity $rest_api_security;

	/**
	 * Set up test environment before each test
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		// Get plugin instance
		$this->plugin = Plugin::getInstance();

		// Initialize REST API security
		$this->rest_api_security = new RestAPISecurity();
	}

	/**
	 * Test REST API security initializes through plugin
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_rest_api_security_initializes_through_plugin(): void {
		// Enable both features
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );

		// Trigger plugin initialization
		$this->plugin->init_security_components();

		// Verify REST API security was initialized
		$rest_api_security = $this->plugin->get_rest_api_security();
		$this->assertInstanceOf(
			RestAPISecurity::class,
			$rest_api_security,
			'REST API security should be initialized through plugin'
		);
	}

	/**
	 * Test batch endpoint restriction via WordPress REST API
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_batch_endpoint_blocked_unauthenticated(): void {
		// Enable batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );

		$rest_api_security = new RestAPISecurity();

		// Mock batch endpoint request
		$request = new WP_REST_Request( 'POST', '/batch/v1/requests' );

		// Ensure user is not logged in
		wp_set_current_user( 0 );

		// Apply filter
		$result = $rest_api_security->restrict_batch_endpoint(
			null,
			new WP_REST_Server(),
			$request
		);

		// Verify batch endpoint is blocked
		$this->assertInstanceOf(
			\WP_Error::class,
			$result,
			'Batch endpoint should be blocked for unauthenticated users'
		);
		$this->assertEquals(
			'rest_batch_disabled',
			$result->get_error_code(),
			'Error code should be rest_batch_disabled'
		);
		$this->assertEquals(
			403,
			$result->get_error_data()['status'],
			'HTTP status should be 403 Forbidden'
		);
	}

	/**
	 * Test WPGraphQL endpoints are not affected by REST API security
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_graphql_endpoints_not_affected(): void {
		// Enable all REST API security features
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );

		$rest_api_security = new RestAPISecurity();

		// Mock GraphQL request (should not be affected)
		$request = new WP_REST_Request( 'POST', '/graphql' );

		// Ensure user is not logged in
		wp_set_current_user( 0 );

		// Apply filters
		$result_batch = $rest_api_security->restrict_batch_endpoint(
			null,
			new WP_REST_Server(),
			$request
		);
		$result_rate = $rest_api_security->rate_limit_rest_api(
			null,
			new WP_REST_Server(),
			$request
		);

		// GraphQL should not be affected by batch endpoint restriction
		$this->assertNull( $result_batch );

		// GraphQL has its own rate limiting in GraphQLSecurity
		// REST API rate limiting should not interfere
		$this->assertNull( $result_rate );
	}

	/**
	 * Test configuration can be disabled via options
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_features_can_be_disabled_via_options(): void {
		// Disable both features
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 0 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 0 );

		// Plugin should not initialize REST API security if both are disabled
		$this->plugin->init_security_components();

		// Verify REST API security was not initialized (or is null)
		$rest_api_security = $this->plugin->get_rest_api_security();
		$this->assertNull(
			$rest_api_security,
			'REST API security should not be initialized when both features are disabled'
		);
	}

	/**
	 * Test only batch endpoint protection initializes when rate limiting is disabled
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_only_batch_protection_initializes(): void {
		// Enable only batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 0 );

		// Plugin should initialize REST API security
		$this->plugin->init_security_components();

		// Verify REST API security was initialized
		$rest_api_security = $this->plugin->get_rest_api_security();
		$this->assertInstanceOf(
			RestAPISecurity::class,
			$rest_api_security,
			'REST API security should initialize when batch endpoint protection is enabled'
		);
	}

	/**
	 * Test CloudFlare IP detection in rate limiting
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_cloudflare_ip_detection(): void {
		// Enable rate limiting
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );
		\update_option( 'silver_assist_rest_rate_limit_requests', 1 );
		\update_option( 'silver_assist_rest_rate_limit_window', 60 );

		$rest_api_security = new RestAPISecurity();

		// Mock CloudFlare header
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.1';

		// Ensure user is not logged in
		wp_set_current_user( 0 );

		// Create mock request
		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		// First request should succeed
		$response1 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertNull( $response1 );

		// Second request should be rate limited
		$response2 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertInstanceOf(
			\WP_Error::class,
			$response2,
			'Second request should be rate limited'
		);

		// Clean up
		\delete_transient( 'silver_assist_rest_limit_203.0.113.1' );
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
	}
}
