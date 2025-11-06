<?php
/**
 * Silver Assist Security Essentials - Security AJAX Handler Test
 *
 * TDD test suite for SecurityAjaxHandler to ensure proper AJAX handling
 * and security validation in the refactored admin architecture.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 */

use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;

/**
 * Security AJAX Handler Test Class
 *
 * Tests AJAX functionality extracted from AdminPanel during refactoring.
 *
 * @since 1.1.15
 */
class SecurityAjaxHandlerTest extends WP_UnitTestCase {

	/**
	 * Security AJAX handler instance
	 *
	 * @var SecurityAjaxHandler
	 * @since 1.1.15
	 */
	private SecurityAjaxHandler $ajax_handler;

	/**
	 * Security data provider mock
	 *
	 * @var SecurityDataProvider
	 * @since 1.1.15
	 */
	private SecurityDataProvider $security_data;

	/**
	 * Statistics provider mock
	 *
	 * @var StatisticsProvider
	 * @since 1.1.15
	 */
	private StatisticsProvider $statistics;

	/**
	 * Setup test environment
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		// Create data providers
		$this->security_data = new SecurityDataProvider();
		$this->statistics    = new StatisticsProvider();

		// Create AJAX handler
		$this->ajax_handler = new SecurityAjaxHandler( $this->security_data, $this->statistics );

		// Setup admin user
		wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );
	}

	/**
	 * Test AJAX handlers registration
	 *
	 * Verifies that all security AJAX handlers are properly registered.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_ajax_handlers_registration(): void {
		// Register handlers
		$this->ajax_handler->register_ajax_handlers();

		// Check that hooks are registered
		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_security_status' ),
			'Should register security status AJAX handler'
		);

		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_login_stats' ),
			'Should register login stats AJAX handler'
		);

		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_blocked_ips' ),
			'Should register blocked IPs AJAX handler'
		);

		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_security_logs' ),
			'Should register security logs AJAX handler'
		);

		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_auto_save' ),
			'Should register auto save AJAX handler'
		);

		$this->assertTrue(
			has_action( 'wp_ajax_silver_assist_validate_admin_path' ),
			'Should register admin path validation AJAX handler'
		);
	}

	/**
	 * Test security status AJAX handler
	 *
	 * Verifies that security status is properly retrieved and returned.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_get_security_status_ajax(): void {
		// Mock nonce validation
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'silver_assist_security_ajax' );

		// Capture output
		ob_start();
		try {
			$this->ajax_handler->get_security_status();
		} catch ( WPAjaxDieContinueException $e ) {
			// Expected for wp_send_json_success
		}
		$response = ob_get_clean();

		// Parse JSON response
		$data = json_decode( $response, true );

		$this->assertNotNull( $data, 'Should return valid JSON response' );
		$this->assertTrue( $data['success'], 'Should return successful response' );
		$this->assertArrayHasKey( 'data', $data, 'Should contain data array' );

		// Check required security status fields
		$status_data = $data['data'];
		$this->assertArrayHasKey( 'login_protection', $status_data );
		$this->assertArrayHasKey( 'password_strength', $status_data );
		$this->assertArrayHasKey( 'bot_protection', $status_data );
		$this->assertArrayHasKey( 'cookie_security', $status_data );
		$this->assertArrayHasKey( 'security_score', $status_data );
	}

	/**
	 * Test AJAX security validation
	 *
	 * Ensures that AJAX handlers properly validate nonces and permissions.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_ajax_security_validation(): void {
		// Test without nonce
		unset( $_REQUEST['_ajax_nonce'] );

		ob_start();
		try {
			$this->ajax_handler->get_security_status();
		} catch ( WPAjaxDieContinueException $e ) {
			// Expected for wp_send_json_error
		}
		$response = ob_get_clean();

		$data = json_decode( $response, true );
		$this->assertFalse( $data['success'], 'Should fail without valid nonce' );
	}

	/**
	 * Test login statistics AJAX handler
	 *
	 * Verifies that login statistics are properly retrieved.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_get_login_stats_ajax(): void {
		// Mock nonce validation
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'silver_assist_security_ajax' );

		ob_start();
		try {
			$this->ajax_handler->get_login_stats();
		} catch ( WPAjaxDieContinueException $e ) {
			// Expected for wp_send_json_success
		}
		$response = ob_get_clean();

		$data = json_decode( $response, true );

		$this->assertNotNull( $data, 'Should return valid JSON response' );
		$this->assertTrue( $data['success'], 'Should return successful response' );
		$this->assertArrayHasKey( 'data', $data, 'Should contain data array' );

		// Check statistics structure
		$stats_data = $data['data'];
		$this->assertArrayHasKey( 'stats', $stats_data );
		$this->assertArrayHasKey( 'last_updated', $stats_data );
	}

	/**
	 * Test blocked IPs AJAX handler
	 *
	 * Verifies that blocked IPs data is properly retrieved.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_get_blocked_ips_ajax(): void {
		// Mock nonce validation
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'silver_assist_security_ajax' );

		ob_start();
		try {
			$this->ajax_handler->get_blocked_ips();
		} catch ( WPAjaxDieContinueException $e ) {
			// Expected for wp_send_json_success
		}
		$response = ob_get_clean();

		$data = json_decode( $response, true );

		$this->assertNotNull( $data, 'Should return valid JSON response' );
		$this->assertTrue( $data['success'], 'Should return successful response' );
		$this->assertArrayHasKey( 'data', $data, 'Should contain data array' );

		// Check blocked IPs structure
		$blocked_data = $data['data'];
		$this->assertArrayHasKey( 'blocked_ips', $blocked_data );
		$this->assertArrayHasKey( 'total_count', $blocked_data );
	}

	/**
	 * Cleanup test environment
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function tearDown(): void {
		// Clean up any created data
		unset( $_REQUEST['_ajax_nonce'] );
		parent::tearDown();
	}
}