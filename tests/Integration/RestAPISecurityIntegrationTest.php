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

		// Ensure user is not logged in
		wp_set_current_user( 0 );

		// Get client IP that will be used for rate limiting
		$client_ip = ! empty( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '127.0.0.1';
		$client_ip_hash = \hash( 'sha256', $client_ip );

		// Clean any REST transients first
		\delete_transient( "silver_assist_rest_window_{$client_ip_hash}" );
		\delete_transient( "silver_assist_rest_limit_{$client_ip_hash}" );

		// Make a real GraphQL request via REST API
		// This should NOT increment the REST rate limit counter
		$request = \rest_ensure_request(
			new WP_REST_Request( 'POST', '/graphql' )
		);

		// Dispatch the request
		$response = \rest_do_request( $request );

		// Verify REST rate limit transient was NOT created for GraphQL
		$window_exists = \get_transient( "silver_assist_rest_window_{$client_ip_hash}" );
		$count_exists = \get_transient( "silver_assist_rest_limit_{$client_ip_hash}" );

		$this->assertFalse(
			$window_exists,
			'GraphQL request should not create REST rate limit window transient'
		);
		$this->assertFalse(
			$count_exists,
			'GraphQL request should not create REST rate limit counter transient'
		);
	}

	/**
	 * Test configuration can be disabled via options
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_features_can_be_disabled_via_options(): void {
		// Disable both features BEFORE re-initialization
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 0 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 0 );

		// Reset the plugin singleton to clear previously registered hooks
		$reflection = new \ReflectionClass( Plugin::class );
		$instance_property = $reflection->getProperty( 'instance' );
		$instance_property->setAccessible( true );
		$instance_property->setValue( null, null );

		// Clean all REST filters
		\remove_all_filters( 'rest_pre_dispatch' );

		// Get fresh plugin instance and initialize
		$plugin = Plugin::getInstance();
		$plugin->init_security_components();

		// Verify REST API security was not initialized
		$rest_api_security = $plugin->get_rest_api_security();
		$this->assertNull(
			$rest_api_security,
			'REST API security should not be initialized when both features are disabled'
		);

		// Verify the REST filters are not registered
		$this->assertFalse(
			\has_filter( 'rest_pre_dispatch', array( $rest_api_security, 'restrict_batch_endpoint' ) ),
			'Batch endpoint filter should not be registered when disabled'
		);
		$this->assertFalse(
			\has_filter( 'rest_pre_dispatch', array( $rest_api_security, 'rate_limit_rest_api' ) ),
			'Rate limiting filter should not be registered when disabled'
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

		// Simulate traffic through Cloudflare:
		// REMOTE_ADDR is a Cloudflare edge IP (from the official range 104.16.0.0/12)
		// HTTP_CF_CONNECTING_IP contains the real client IP
		$cloudflare_edge_ip = '104.16.1.1';      // Valid Cloudflare IP
		$client_ip = '203.0.113.5';               // Client's real public IP
		$_SERVER['REMOTE_ADDR'] = $cloudflare_edge_ip;
		$_SERVER['HTTP_CF_CONNECTING_IP'] = $client_ip;

		// Ensure user is not logged in
		wp_set_current_user( 0 );

		// Create mock request
		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		// Calculate expected transient key based on client IP (extracted from CF header)
		$client_ip_hash = \hash( 'sha256', $client_ip );
		$cf_window_key = "silver_assist_rest_window_{$client_ip_hash}";
		$cf_limit_key = "silver_assist_rest_limit_{$client_ip_hash}";

		// Also calculate key for edge IP (should NOT be used)
		$edge_ip_hash = \hash( 'sha256', $cloudflare_edge_ip );
		$edge_window_key = "silver_assist_rest_window_{$edge_ip_hash}";
		$edge_limit_key = "silver_assist_rest_limit_{$edge_ip_hash}";

		// Clean transients before test
		\delete_transient( $cf_window_key );
		\delete_transient( $cf_limit_key );
		\delete_transient( $edge_window_key );
		\delete_transient( $edge_limit_key );

		// First request should succeed
		$response1 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertNull( $response1, 'First request should not be rate limited' );

		// Verify the client IP transient was created (from CF header), not edge IP
		$this->assertNotFalse(
			\get_transient( $cf_window_key ),
			'Window transient should be created for client IP from CF header'
		);
		$this->assertFalse(
			\get_transient( $edge_window_key ),
			'Window transient should NOT be created for edge IP'
		);

		// Second request should be rate limited
		$response2 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertInstanceOf(
			\WP_Error::class,
			$response2,
			'Second request should be rate limited'
		);

		// Clean up
		\delete_transient( $cf_window_key );
		\delete_transient( $cf_limit_key );
		\delete_transient( $edge_window_key );
		\delete_transient( $edge_limit_key );
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['REMOTE_ADDR'] );
	}
}
