<?php
/**
 * REST API Security Unit Tests
 *
 * Tests for RestAPISecurity class including batch endpoint restriction
 * and rate limiting functionality.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.5.0
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Security\RestAPISecurity;
use SilverAssist\Security\Core\DefaultConfig;
use WP_UnitTestCase;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Test RestAPISecurity class
 *
 * @since 1.5.0
 */
class RestAPISecurityTest extends WP_UnitTestCase {

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
	protected function setUp(): void {
		parent::setUp();
		$this->rest_api_security = new RestAPISecurity();
	}

	/**
	 * Test batch endpoint is restricted for unauthenticated users
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_batch_endpoint_restricted_for_unauthenticated(): void {
		// Enable batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );

		$rest_api_security = new RestAPISecurity();

		// Create a mock REST request to batch endpoint
		$request = new WP_REST_Request( 'POST', '/batch/v1/requests' );

		// Test with unauthenticated user
		wp_set_current_user( 0 );

		$result = $rest_api_security->restrict_batch_endpoint( null, new WP_REST_Server(), $request );

		// Should return an error
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertEquals( 'rest_batch_disabled', $result->get_error_code() );
		$this->assertEquals( 403, $result->get_error_data()['status'] );
	}

	/**
	 * Test batch endpoint is allowed for authenticated users
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_batch_endpoint_allowed_for_authenticated(): void {
		// Enable batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );

		$rest_api_security = new RestAPISecurity();

		// Create admin user and set as current
		$admin_user = $this->factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $admin_user );

		// Create a mock REST request to batch endpoint
		$request = new WP_REST_Request( 'POST', '/batch/v1/requests' );

		// Mock response
		$original_response = new \stdClass();

		$result = $rest_api_security->restrict_batch_endpoint( $original_response, new WP_REST_Server(), $request );

		// Should return the original response (not an error)
		$this->assertNotInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $original_response, $result );
	}

	/**
	 * Test non-batch endpoints are not restricted for unauthenticated users
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_non_batch_endpoints_allowed(): void {
		// Enable batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );

		$rest_api_security = new RestAPISecurity();

		// Create a mock REST request to non-batch endpoint
		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		// Test with unauthenticated user
		wp_set_current_user( 0 );

		// Mock response
		$original_response = new \stdClass();

		$result = $rest_api_security->restrict_batch_endpoint( $original_response, new WP_REST_Server(), $request );

		// Should return the original response (not an error)
		$this->assertNotInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $original_response, $result );
	}

	/**
	 * Test rate limiting is applied to unauthenticated requests
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_rate_limiting_applied_to_unauthenticated(): void {
		// Enable rate limiting with low limits for testing
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );
		\update_option( 'silver_assist_rest_rate_limit_requests', 2 );
		\update_option( 'silver_assist_rest_rate_limit_window', 60 );

		$rest_api_security = new RestAPISecurity();

		// Mock client IP
		$_SERVER['REMOTE_ADDR'] = '192.168.1.1';

		// Test with unauthenticated user
		wp_set_current_user( 0 );

		// Create mock requests
		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		// First request should succeed
		$response1 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertNull( $response1 );

		// Second request should succeed
		$response2 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertNull( $response2 );

		// Third request should be rate limited
		$response3 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$this->assertInstanceOf( \WP_Error::class, $response3 );
		$this->assertEquals( 'rest_rate_limit_exceeded', $response3->get_error_code() );
		$this->assertEquals( 429, $response3->get_error_data()['status'] );

		// Clean up transients
		\delete_transient( 'silver_assist_rest_limit_192.168.1.1' );
	}

	/**
	 * Test rate limiting is not applied to authenticated users
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_rate_limiting_not_applied_to_authenticated(): void {
		// Enable rate limiting
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );
		\update_option( 'silver_assist_rest_rate_limit_requests', 1 );
		\update_option( 'silver_assist_rest_rate_limit_window', 60 );

		$rest_api_security = new RestAPISecurity();

		// Create admin user and set as current
		$admin_user = $this->factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $admin_user );

		// Mock client IP
		$_SERVER['REMOTE_ADDR'] = '192.168.1.2';

		// Create mock request
		$request = new WP_REST_Request( 'GET', '/wp/v2/posts' );

		// Even with limit of 1, authenticated users should not be rate limited
		$response1 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$response2 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );
		$response3 = $rest_api_security->rate_limit_rest_api( null, new WP_REST_Server(), $request );

		// All should succeed
		$this->assertNull( $response1 );
		$this->assertNull( $response2 );
		$this->assertNull( $response3 );
	}

	/**
	 * Test default configuration values exist
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_default_configuration_values_exist(): void {
		$defaults = DefaultConfig::get_defaults();

		// Check REST API security configuration keys exist
		$this->assertArrayHasKey( 'silver_assist_rest_batch_endpoint_protection', $defaults );
		$this->assertArrayHasKey( 'silver_assist_rest_rate_limiting_enabled', $defaults );
		$this->assertArrayHasKey( 'silver_assist_rest_rate_limit_requests', $defaults );
		$this->assertArrayHasKey( 'silver_assist_rest_rate_limit_window', $defaults );

		// Verify values are reasonable
		$this->assertTrue( $defaults['silver_assist_rest_batch_endpoint_protection'] );
		$this->assertTrue( $defaults['silver_assist_rest_rate_limiting_enabled'] );
		$this->assertGreaterThan( 0, $defaults['silver_assist_rest_rate_limit_requests'] );
		$this->assertGreaterThan( 0, $defaults['silver_assist_rest_rate_limit_window'] );
	}

	/**
	 * Test batch endpoint protection can be disabled
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_batch_endpoint_protection_can_be_disabled(): void {
		// Disable batch endpoint protection
		\update_option( 'silver_assist_rest_batch_endpoint_protection', 0 );

		// RestAPISecurity should still initialize
		$rest_api_security = new RestAPISecurity();
		$this->assertInstanceOf( RestAPISecurity::class, $rest_api_security );
	}

	/**
	 * Test rate limiting can be disabled
	 *
	 * @since 1.5.0
	 * @return void
	 */
	public function test_rate_limiting_can_be_disabled(): void {
		// Disable rate limiting
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 0 );

		// RestAPISecurity should still initialize
		$rest_api_security = new RestAPISecurity();
		$this->assertInstanceOf( RestAPISecurity::class, $rest_api_security );
	}
}
