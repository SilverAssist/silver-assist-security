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
use SilverAssist\Security\Core\SecurityHelper;
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

		// Get client IP and generate keys using same method as implementation
		$client_ip = ! empty( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '127.0.0.1';
		$window_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_window', $client_ip );
		$count_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', $client_ip );

		// Clean any REST transients first
		\delete_transient( $window_key );
		\delete_transient( $count_key );

		// Make a request to /graphql via REST API
		// This should NOT increment the REST rate limit counter because
		// GraphQL requests use the separate graphql_request hook, not REST filters
		$request = \rest_ensure_request(
			new WP_REST_Request( 'POST', '/graphql' )
		);

		// Dispatch the request
		$response = \rest_do_request( $request );

		// Verify REST rate limit transient was NOT created for GraphQL
		$window_exists = \get_transient( $window_key );
		$count_exists = \get_transient( $count_key );

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
	 * Test trusted-proxy client IP extraction from X-Forwarded-For
	 *
	 * Simulates the target infrastructure (AWS CloudFront + ALB): REMOTE_ADDR is
	 * the ALB's private IP (declared as trusted via the filter) and the real
	 * client address travels at the leftmost position of `X-Forwarded-For`,
	 * followed by CloudFront edge and ALB hops.
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_trusted_proxy_client_ip_detection(): void {
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );
		\update_option( 'silver_assist_rest_rate_limit_requests', 1 );
		\update_option( 'silver_assist_rest_rate_limit_window', 60 );

		$alb_private_ip     = '10.0.1.42';    // ALB inside the VPC
		$cloudfront_edge_ip = '52.84.1.1';    // CloudFront edge (also treated as trusted proxy hop)
		$client_ip          = '203.0.113.5';  // Real client public IP

		$trusted_cidrs_filter = static fn (): array => array( '10.0.0.0/8', '52.84.0.0/15' );
		\add_filter( 'silver_assist_trusted_proxy_cidrs', $trusted_cidrs_filter );

		$rest_api_security = new RestAPISecurity();

		$_SERVER['REMOTE_ADDR']          = $alb_private_ip;
		$_SERVER['HTTP_X_FORWARDED_FOR'] = "{$client_ip}, {$cloudfront_edge_ip}, {$alb_private_ip}";

		\wp_set_current_user( 0 );

		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		$client_hash     = \hash( 'md5', $client_ip );
		$client_window   = "silver_assist_rest_window_{$client_hash}";
		$client_counter  = "silver_assist_rest_limit_{$client_hash}";
		$alb_hash        = \hash( 'md5', $alb_private_ip );
		$alb_window      = "silver_assist_rest_window_{$alb_hash}";
		$alb_counter     = "silver_assist_rest_limit_{$alb_hash}";

		\delete_transient( $client_window );
		\delete_transient( $client_counter );
		\delete_transient( $alb_window );
		\delete_transient( $alb_counter );

		$response1 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertNull( $response1, 'First request should not be rate limited' );

		$this->assertNotFalse(
			\get_transient( $client_window ),
			'Window transient should be created for the real client IP extracted from X-Forwarded-For'
		);
		$this->assertFalse(
			\get_transient( $alb_window ),
			'Window transient should NOT be created for the ALB proxy IP'
		);

		$response2 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertInstanceOf(
			\WP_Error::class,
			$response2,
			'Second request should be rate limited'
		);

		\delete_transient( $client_window );
		\delete_transient( $client_counter );
		\delete_transient( $alb_window );
		\delete_transient( $alb_counter );
		\remove_filter( 'silver_assist_trusted_proxy_cidrs', $trusted_cidrs_filter );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		unset( $_SERVER['REMOTE_ADDR'] );
	}
}
