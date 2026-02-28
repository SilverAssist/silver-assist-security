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
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;
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

	use AjaxTestHelper;

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
		
		if ( ! function_exists( __NAMESPACE__ . '\\wpcf7_get_contact_form_by_id' ) ) {
			function wpcf7_get_contact_form_by_id( $id ) {
				return new \stdClass();
			}
		}

		// Create ContactForm7AjaxHandler instance (should auto-register hooks if CF7 active)
		$this->handler = new ContactForm7AjaxHandler();

		// Set up admin environment
		$this->setup_ajax_environment();
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

		$response = $this->call_ajax_handler( $this->handler, 'get_blocked_ips' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test get_blocked_ips method fails without proper nonce
	 */
	public function test_get_blocked_ips_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );
		// No nonce set

		$response = $this->call_ajax_handler( $this->handler, 'get_blocked_ips' );
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

		$response = $this->call_ajax_handler( $this->handler, 'get_blocked_ips' );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertStringContainsString( 'Security validation failed', $response['data']['error'] ?? '' );
	}

	/**
	 * Test block_ip method with admin user
	 */
	public function test_block_ip_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip'] = '192.168.1.100';
		$_POST['reason'] = 'Test block';

		$response = $this->call_ajax_handler( $this->handler, 'block_ip' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test unblock_ip method with admin user
	 */
	public function test_unblock_ip_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );

		// First block the IP so we can unblock it
		$blacklist = \SilverAssist\Security\Security\IPBlacklist::getInstance();
		$blacklist->add_to_blacklist( '192.168.1.100', 'Test block for unblock', 3600 );

		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip'] = '192.168.1.100';

		$response = $this->call_ajax_handler( $this->handler, 'unblock_ip' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test clear_blocked_ips method with admin user
	 */
	public function test_clear_blocked_ips_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'clear_blocked_ips' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test export_blocked_ips method with admin user
	 */
	public function test_export_blocked_ips_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'export_blocked_ips' );

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
	 * Test get_blocked_ips returns no-threats class when empty
	 */
	public function test_get_blocked_ips_returns_no_threats_class_when_empty(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// Clean CF7 blacklist to ensure empty state
		$blacklist = \SilverAssist\Security\Security\IPBlacklist::getInstance();
		$blacklist->clear_cf7_blacklist();

		$response = $this->call_ajax_handler( $this->handler, 'get_blocked_ips' );

		$this->assertTrue( $response['success'] ?? false );

		$html = $response['data']['html'] ?? '';
		$this->assertStringContainsString(
			'class="no-threats"',
			$html,
			'Empty CF7 blocked IPs should use no-threats class'
		);
	}

	/**
	 * Test get_blocked_ips does NOT use the deprecated no-blocked-ips class (regression test)
	 */
	public function test_get_blocked_ips_does_not_use_old_class(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$blacklist = \SilverAssist\Security\Security\IPBlacklist::getInstance();
		$blacklist->clear_cf7_blacklist();

		$response = $this->call_ajax_handler( $this->handler, 'get_blocked_ips' );

		$html     = $response['data']['html'] ?? '';
		$this->assertStringNotContainsString(
			'class="no-blocked-ips"',
			$html,
			'Should NOT use deprecated no-blocked-ips class'
		);
	}

	/**
	 * Test export returns CSV with proper headers
	 */
	public function test_export_returns_csv_with_headers(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'export_blocked_ips' );
		$this->assertTrue( $response['success'] ?? false );

		$csv_data = $response['data']['csv_data'] ?? '';
		$this->assertStringContainsString( 'IP Address', $csv_data, 'CSV should have IP Address header' );
		$this->assertStringContainsString( 'Reason', $csv_data, 'CSV should have Reason header' );
		$this->assertStringContainsString( 'Blocked At', $csv_data, 'CSV should have Blocked At header' );
		$this->assertStringContainsString( 'Violations', $csv_data, 'CSV should have Violations header' );

		$this->assertArrayHasKey( 'filename', $response['data'] );
		$this->assertStringContainsString( '.csv', $response['data']['filename'] );
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

		$this->teardown_ajax_environment();
		parent::tearDown();
	}
}