<?php
/**
 * GraphQL API Key AJAX Handler Tests
 *
 * Tests for AJAX-based API key generation and revocation.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.8.0
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Admin\Ajax\GraphQLApiKeyAjaxHandler;
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;
use WP_UnitTestCase;

/**
 * Test GraphQLApiKeyAjaxHandler functionality
 *
 * @since 1.8.0
 */
class GraphQLApiKeyAjaxHandlerTest extends WP_UnitTestCase {

	use AjaxTestHelper;

	/**
	 * GraphQLApiKeyAjaxHandler instance
	 *
	 * @var GraphQLApiKeyAjaxHandler
	 */
	private GraphQLApiKeyAjaxHandler $handler;

	/**
	 * Admin user ID
	 *
	 * @var int
	 */
	private int $admin_user_id;

	/**
	 * Subscriber user ID
	 *
	 * @var int
	 */
	private int $subscriber_user_id;

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->admin_user_id      = $this->factory()->user->create( array( 'role' => 'administrator' ) );
		$this->subscriber_user_id = $this->factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->handler = new GraphQLApiKeyAjaxHandler();

		$this->setup_ajax_environment();
		$_SERVER['REQUEST_METHOD']  = 'POST';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test)';
		$_SERVER['REMOTE_ADDR']     = '127.0.0.1';
	}

	/**
	 * Tear down test environment
	 */
	protected function tearDown(): void {
		$this->teardown_ajax_environment();
		\delete_option( 'silver_assist_graphql_api_key' );
		\delete_option( 'silver_assist_graphql_service_user_id' );
		$_POST = array();
		parent::tearDown();
	}

	/**
	 * Test AJAX actions are registered
	 */
	public function test_ajax_actions_registered(): void {
		$this->assertNotFalse(
			\has_action( 'wp_ajax_silver_assist_generate_graphql_api_key' ),
			'Generate API key AJAX action should be registered'
		);

		$this->assertNotFalse(
			\has_action( 'wp_ajax_silver_assist_revoke_graphql_api_key' ),
			'Revoke API key AJAX action should be registered'
		);
	}

	/**
	 * Test generate API key succeeds for admin user
	 */
	public function test_generate_api_key_success(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'generate_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertTrue( $response['success'], 'Response should indicate success' );
		$this->assertNotEmpty( $response['data']['api_key'], 'Response should contain API key' );
		$this->assertEquals( 64, strlen( $response['data']['api_key'] ), 'API key should be 64 hex characters' );
		$this->assertNotEmpty( $response['data']['message'], 'Response should contain a message' );

		// Verify hash was stored.
		$stored_hash = \get_option( 'silver_assist_graphql_api_key' );
		$this->assertNotEmpty( $stored_hash, 'API key hash should be stored in options' );
		$this->assertTrue(
			\wp_check_password( $response['data']['api_key'], $stored_hash ),
			'Stored hash should match the returned API key'
		);
	}

	/**
	 * Test generate API key fails without nonce
	 */
	public function test_generate_api_key_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );

		$response = $this->call_ajax_handler( $this->handler, 'generate_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertFalse( $response['success'], 'Response should indicate failure' );
	}

	/**
	 * Test generate API key fails for subscriber
	 */
	public function test_generate_api_key_fails_for_subscriber(): void {
		\wp_set_current_user( $this->subscriber_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'generate_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertFalse( $response['success'], 'Response should indicate failure' );
		$this->assertNotEmpty( $response['data']['error'], 'Response should contain an error message' );
	}

	/**
	 * Test generate API key fails for logged-out user
	 */
	public function test_generate_api_key_fails_for_logged_out_user(): void {
		\wp_set_current_user( 0 );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'generate_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertFalse( $response['success'], 'Response should indicate failure' );
	}

	/**
	 * Test regenerate replaces existing key
	 */
	public function test_regenerate_replaces_existing_key(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Generate first key.
		$response1 = $this->call_ajax_handler( $this->handler, 'generate_api_key' );
		$first_key = $response1['data']['api_key'];
		$first_hash = \get_option( 'silver_assist_graphql_api_key' );

		// Regenerate.
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$response2 = $this->call_ajax_handler( $this->handler, 'generate_api_key' );
		$second_key = $response2['data']['api_key'];

		$this->assertNotEquals( $first_key, $second_key, 'Regenerated key should be different' );

		// First key should no longer validate.
		$current_hash = \get_option( 'silver_assist_graphql_api_key' );
		$this->assertFalse(
			\wp_check_password( $first_key, $current_hash ),
			'Old key should no longer validate against stored hash'
		);
		$this->assertTrue(
			\wp_check_password( $second_key, $current_hash ),
			'New key should validate against stored hash'
		);
	}

	/**
	 * Test revoke API key succeeds for admin
	 */
	public function test_revoke_api_key_success(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// First generate a key.
		$this->call_ajax_handler( $this->handler, 'generate_api_key' );
		\update_option( 'silver_assist_graphql_service_user_id', 5 );

		// Revoke it.
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$response = $this->call_ajax_handler( $this->handler, 'revoke_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertTrue( $response['success'], 'Response should indicate success' );
		$this->assertNotEmpty( $response['data']['message'], 'Response should contain a message' );

		// Verify key and service user were cleared.
		$this->assertEmpty( \get_option( 'silver_assist_graphql_api_key' ), 'API key should be cleared' );
		$this->assertEquals( 0, (int) \get_option( 'silver_assist_graphql_service_user_id' ), 'Service user ID should be reset to 0' );
	}

	/**
	 * Test revoke API key fails without nonce
	 */
	public function test_revoke_api_key_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );

		$response = $this->call_ajax_handler( $this->handler, 'revoke_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertFalse( $response['success'], 'Response should indicate failure' );
	}

	/**
	 * Test revoke API key fails for subscriber
	 */
	public function test_revoke_api_key_fails_for_subscriber(): void {
		\wp_set_current_user( $this->subscriber_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'revoke_api_key' );

		$this->assertNotNull( $response, 'Response should not be null' );
		$this->assertFalse( $response['success'], 'Response should indicate failure' );
	}

	/**
	 * Test generated API key is valid hex string
	 */
	public function test_api_key_is_valid_hex(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'generate_api_key' );

		$api_key = $response['data']['api_key'];
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $api_key, 'API key should be a 64-character hex string' );
	}
}
