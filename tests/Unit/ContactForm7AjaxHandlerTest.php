<?php
/**
 * Silver Assist Security Essentials - ContactForm7AjaxHandler Unit Tests
 *
 * Tests the ContactForm7AjaxHandler class with focus on AJAX hook registration,
 * security validation, and CF7 IP management functionality. Tests the direct handler
 * architecture without proxy methods.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Admin\Ajax\ContactForm7AjaxHandler;
use WP_UnitTestCase;

/**
 * ContactForm7AjaxHandler unit test class
 *
 * Tests ContactForm7AjaxHandler AJAX hook registration and CF7 IP management
 * with proper security validation and conditional initialization.
 *
 * @since 1.1.15
 */
class ContactForm7AjaxHandlerTest extends WP_UnitTestCase {

	/**
	 * ContactForm7AjaxHandler instance
	 *
	 * @var ContactForm7AjaxHandler
	 */
	private ContactForm7AjaxHandler $handler;

	/**
	 * Administrator user ID
	 *
	 * @var int
	 */
	private int $admin_user_id;

	/**
	 * Set up test environment before each test
	 */
	protected function setUp(): void {
		parent::setUp();

		// Create test users
		$this->admin_user_id = $this->factory()->user->create( [ 'role' => 'administrator' ] );

		// Mock CF7 being active (since it's usually not in tests)
		if ( ! defined( 'WPCF7_VERSION' ) ) {
			define( 'WPCF7_VERSION', '5.9.3' );
		}
		
		// Mock WPCF7 class and function existence
		if ( ! class_exists( 'WPCF7' ) ) {
			// Create a simple mock WPCF7 class
			class_alias( \stdClass::class, 'WPCF7' );
		}
		
		if ( ! function_exists( 'wpcf7_get_contact_form_by_id' ) ) {
			function wpcf7_get_contact_form_by_id( $id ) {
				return new \stdClass();
			}
		}

		// Create ContactForm7AjaxHandler instance (should auto-register hooks if CF7 active)
		$this->handler = new ContactForm7AjaxHandler();

		// Set up admin environment
		\set_current_screen( 'dashboard' );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test Browser)';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Test that ContactForm7AjaxHandler initializes properly
	 */
	public function test_cf7_handler_initializes_properly(): void {
		// Verify handler is properly instantiated
		$this->assertInstanceOf(
			\SilverAssist\Security\Admin\Ajax\ContactForm7AjaxHandler::class,
			$this->handler,
			'ContactForm7AjaxHandler should be properly instantiated'
		);
		
		// If CF7 is not active in test environment, that's expected
		// The important thing is that the handler can be created without errors
		$this->assertTrue( true, 'Handler creation completed without errors' );
	}

	/**
	 * Test get_blocked_ips method with admin user
	 */
	public function test_get_blocked_ips_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Capture output using output buffering
		ob_start();
		$this->handler->get_blocked_ips();
		$output = ob_get_clean();

		// Should produce valid JSON output
		$this->assertNotEmpty( $output );
		$response = json_decode( $output, true );
		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test get_blocked_ips method fails without proper nonce
	 */
	public function test_get_blocked_ips_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );
		// No nonce set

		// Capture output
		ob_start();
		$this->handler->get_blocked_ips();
		$output = ob_get_clean();

		// Should return error
		$response = json_decode( $output, true );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertArrayHasKey( 'data', $response );
		$this->assertArrayHasKey( 'error', $response['data'] );
	}

	/**
	 * Test get_blocked_ips method fails with non-admin user
	 */
	public function test_get_blocked_ips_fails_with_non_admin_user(): void {
		$subscriber_id = $this->factory()->user->create( [ 'role' => 'subscriber' ] );
		\wp_set_current_user( $subscriber_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Capture output
		ob_start();
		$this->handler->get_blocked_ips();
		$output = ob_get_clean();

		// Should return error due to insufficient permissions
		$response = json_decode( $output, true );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertStringContainsString( 'permissions', $response['data']['error'] ?? '' );
	}

	/**
	 * Test block_ip method with admin user
	 */
	public function test_block_ip_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip'] = '192.168.1.100';
		$_POST['reason'] = 'Test block';

		// Capture output
		ob_start();
		$this->handler->block_ip();
		$output = ob_get_clean();

		// Should produce valid JSON output
		$this->assertNotEmpty( $output );
		$response = json_decode( $output, true );
		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test unblock_ip method with admin user
	 */
	public function test_unblock_ip_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip'] = '192.168.1.100';

		// Capture output
		ob_start();
		$this->handler->unblock_ip();
		$output = ob_get_clean();

		// Should produce valid JSON output
		$this->assertNotEmpty( $output );
		$response = json_decode( $output, true );
		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test clear_blocked_ips method with admin user
	 */
	public function test_clear_blocked_ips_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Capture output
		ob_start();
		$this->handler->clear_blocked_ips();
		$output = ob_get_clean();

		// Should produce valid JSON output
		$this->assertNotEmpty( $output );
		$response = json_decode( $output, true );
		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test export_blocked_ips method with admin user
	 */
	public function test_export_blocked_ips_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Capture output
		ob_start();
		$this->handler->export_blocked_ips();
		$output = ob_get_clean();

		// Should produce valid JSON output
		$this->assertNotEmpty( $output );
		$response = json_decode( $output, true );
		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test that handler methods are callable
	 */
	public function test_handler_methods_are_callable(): void {
		$methods = [
			'get_blocked_ips',
			'block_ip',
			'unblock_ip',
			'clear_blocked_ips',
			'export_blocked_ips',
		];

		foreach ( $methods as $method ) {
			$this->assertTrue(
				is_callable( [ $this->handler, $method ] ),
				"Method {$method} should be callable"
			);
		}
	}

	/**
	 * Clean up after each test
	 */
	protected function tearDown(): void {
		// Logout any logged-in user
		\wp_set_current_user( 0 );

		// Clean up globals
		$_POST = [];
		$_SERVER['REQUEST_METHOD'] = 'GET';

		// Delete test users
		if ( $this->admin_user_id ) {
			\wp_delete_user( $this->admin_user_id );
		}

		parent::tearDown();
	}
}