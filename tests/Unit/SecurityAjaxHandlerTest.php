<?php
/**
 * Silver Assist Security Essentials - SecurityAjaxHandler Unit Tests
 *
 * Tests the SecurityAjaxHandler class with focus on AJAX hook registration,
 * security validation, and data provider integration. Tests the direct handler
 * architecture without proxy methods.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;
use WP_UnitTestCase;

/**
 * SecurityAjaxHandler unit test class
 *
 * Tests SecurityAjaxHandler AJAX hook registration and request handling
 * with proper security validation and data provider integration.
 *
 * @since 1.1.15
 */
class SecurityAjaxHandlerTest extends WP_UnitTestCase {

	use AjaxTestHelper;

	/**
	 * SecurityAjaxHandler instance
	 *
	 * @var SecurityAjaxHandler
	 */
	private SecurityAjaxHandler $handler;

	/**
	 * SecurityDataProvider mock
	 *
	 * @var SecurityDataProvider
	 */
	private SecurityDataProvider $data_provider;

	/**
	 * StatisticsProvider mock
	 *
	 * @var StatisticsProvider
	 */
	private StatisticsProvider $stats_provider;

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

		// Initialize data providers
		$this->data_provider  = new SecurityDataProvider();
		$this->stats_provider = new StatisticsProvider();

		// Create SecurityAjaxHandler instance (should auto-register hooks)
		$this->handler = new SecurityAjaxHandler( $this->data_provider, $this->stats_provider );

		// Set up AJAX environment (wp_doing_ajax + die handler)
		$this->setup_ajax_environment();

		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test Browser)';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Test that AJAX hooks are automatically registered in constructor
	 */
	public function test_ajax_hooks_auto_registered(): void {
		// Verify all security AJAX hooks are registered
		$expected_hooks = [
			'wp_ajax_silver_assist_get_security_status',
			'wp_ajax_silver_assist_get_login_stats',
			'wp_ajax_silver_assist_get_blocked_ips',
			'wp_ajax_silver_assist_get_security_logs',
			'wp_ajax_silver_assist_auto_save',
			'wp_ajax_silver_assist_validate_admin_path',
		];

		foreach ( $expected_hooks as $hook ) {
			$this->assertTrue(
				\has_action( $hook ) !== false,
				"AJAX hook {$hook} should be registered"
			);
		}
	}

	/**
	 * Test get_security_status method with admin user
	 */
	public function test_get_security_status_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'get_security_status' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test get_security_status method fails without proper nonce
	 */
	public function test_get_security_status_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );
		// No nonce set

		$response = $this->call_ajax_handler( $this->handler, 'get_security_status' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertArrayHasKey( 'data', $response );
		$this->assertArrayHasKey( 'error', $response['data'] );
	}

	/**
	 * Test get_security_status method fails with non-admin user
	 */
	public function test_get_security_status_fails_with_non_admin_user(): void {
		$subscriber_id = $this->factory()->user->create( [ 'role' => 'subscriber' ] );
		\wp_set_current_user( $subscriber_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'get_security_status' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertStringContainsString( 'Security validation failed', $response['data']['error'] ?? '' );
	}

	/**
	 * Test get_login_stats method with admin user
	 */
	public function test_get_login_stats_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'get_login_stats' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
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
	 * Test validate_admin_path method with valid path
	 */
	public function test_validate_admin_path_with_valid_path(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['admin_path'] = 'secure-admin';

		$response = $this->call_ajax_handler( $this->handler, 'validate_admin_path' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
		$this->assertTrue( $response['data']['valid'] ?? false );
	}

	/**
	 * Test validate_admin_path method with forbidden path
	 */
	public function test_validate_admin_path_with_forbidden_path(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['admin_path'] = 'wp-admin'; // Forbidden path

		$response = $this->call_ajax_handler( $this->handler, 'validate_admin_path' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true );
		$this->assertFalse( $response['data']['valid'] ?? true );
	}

	/**
	 * Test auto_save method with admin user
	 */
	public function test_auto_save_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['silver_assist_login_attempts'] = '5';
		$_POST['silver_assist_lockout_duration'] = '900';

		$response = $this->call_ajax_handler( $this->handler, 'auto_save' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Test that handler methods are callable (including new endpoints)
	 */
	public function test_handler_methods_are_callable(): void {
		$methods = [
			'get_security_status',
			'get_login_stats',
			'get_blocked_ips',
			'get_security_logs',
			'auto_save',
			'validate_admin_path',
			'add_manual_ip',
			'unblock_ip',
		];

		foreach ( $methods as $method ) {
			$this->assertTrue(
				is_callable( [ $this->handler, $method ] ),
				"Method {$method} should be callable"
			);
		}
	}

	/**
	 * Test unblock_ip hook is registered
	 */
	public function test_unblock_ip_hook_registered(): void {
		$this->assertNotFalse(
			\has_action( 'wp_ajax_silver_assist_unblock_ip' ),
			'wp_ajax_silver_assist_unblock_ip should be registered'
		);
	}

	/**
	 * Test unblock_ip removes a blocked IP
	 */
	public function test_unblock_ip_removes_blocked_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		// First block the IP
		$blacklist = new \SilverAssist\Security\Security\IPBlacklist();
		$blacklist->add_to_blacklist( '10.50.50.1', 'Test block', 3600 );
		$this->assertTrue( $blacklist->is_blacklisted( '10.50.50.1' ) );

		$_POST['ip_address'] = '10.50.50.1';

		$response = $this->call_ajax_handler( $this->handler, 'unblock_ip' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false, 'Unblock should succeed' );
		$this->assertFalse( $blacklist->is_blacklisted( '10.50.50.1' ), 'IP should be unblocked' );
	}

	/**
	 * Test unblock_ip fails without nonce
	 */
	public function test_unblock_ip_fails_without_nonce(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['ip_address'] = '10.50.50.2';

		$response = $this->call_ajax_handler( $this->handler, 'unblock_ip' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true );
	}

	/**
	 * Test unblock_ip fails with empty IP
	 */
	public function test_unblock_ip_fails_with_empty_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = '';

		$response = $this->call_ajax_handler( $this->handler, 'unblock_ip' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true );
	}

	/**
	 * Test unblock_ip for unknown IP
	 */
	public function test_unblock_ip_for_unknown_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = '10.50.50.99';

		$response = $this->call_ajax_handler( $this->handler, 'unblock_ip' );

		$this->assertNotNull( $response, 'Should return a response without hanging' );
	}

	/**
	 * Test add_manual_ip blocks a valid IP
	 */
	public function test_add_manual_ip_blocks_valid_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = '10.50.50.3';
		$_POST['reason'] = 'Test manual block';

		$response = $this->call_ajax_handler( $this->handler, 'add_manual_ip' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false, 'Manual block should succeed' );

		// Verify IP is blocked
		$blacklist = new \SilverAssist\Security\Security\IPBlacklist();
		$this->assertTrue( $blacklist->is_blacklisted( '10.50.50.3' ) );

		// Cleanup
		$blacklist->remove_from_blacklist( '10.50.50.3' );
	}

	/**
	 * Test add_manual_ip rejects invalid IP format
	 */
	public function test_add_manual_ip_rejects_invalid_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = 'not-an-ip';

		$response = $this->call_ajax_handler( $this->handler, 'add_manual_ip' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true, 'Invalid IP should be rejected' );
	}

	/**
	 * Test add_manual_ip rejects empty IP
	 */
	public function test_add_manual_ip_rejects_empty_ip(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = '';

		$response = $this->call_ajax_handler( $this->handler, 'add_manual_ip' );

		$this->assertNotNull( $response );
		$this->assertFalse( $response['success'] ?? true, 'Empty IP should be rejected' );
	}

	/**
	 * Test get_security_logs returns valid data
	 */
	public function test_get_security_logs_with_admin_user(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$response = $this->call_ajax_handler( $this->handler, 'get_security_logs' );

		$this->assertNotNull( $response );
		$this->assertTrue( $response['success'] ?? false );
	}

	/**
	 * Clean up after each test
	 */
	protected function tearDown(): void {
		// Clean up test IPs
		$test_ips = [ '10.50.50.1', '10.50.50.2', '10.50.50.3', '10.50.50.99' ];
		foreach ( $test_ips as $ip ) {
			\delete_transient( 'ip_blacklist_' . md5( $ip ) );
		}
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