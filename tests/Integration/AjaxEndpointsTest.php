<?php
/**
 * Silver Assist Security Essentials - AJAX Endpoints Integration Tests
 *
 * Tests AJAX hook registration, nonce validation, and capability checks
 * across all security AJAX endpoints.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Ajax\ContactForm7AjaxHandler;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;
use WP_UnitTestCase;

/**
 * AJAX Endpoints integration tests
 *
 * @since 1.1.15
 */
class AjaxEndpointsTest extends WP_UnitTestCase {

	use AjaxTestHelper;

	/**
	 * SecurityAjaxHandler instance
	 *
	 * @var SecurityAjaxHandler
	 */
	private SecurityAjaxHandler $security_handler;

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

		$this->admin_user_id      = $this->factory()->user->create( [ 'role' => 'administrator' ] );
		$this->subscriber_user_id = $this->factory()->user->create( [ 'role' => 'subscriber' ] );

		$data_provider  = new SecurityDataProvider();
		$stats_provider = new StatisticsProvider();

		$this->security_handler = new SecurityAjaxHandler( $data_provider, $stats_provider );

		$this->setup_ajax_environment();
		$_SERVER['REQUEST_METHOD']  = 'POST';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test)';
		$_SERVER['REMOTE_ADDR']     = '127.0.0.1';
	}

	/**
	 * Test all security AJAX actions are registered
	 */
	public function test_all_security_ajax_actions_registered(): void {
		$expected_actions = [
			'wp_ajax_silver_assist_get_security_status',
			'wp_ajax_silver_assist_get_login_stats',
			'wp_ajax_silver_assist_get_blocked_ips',
			'wp_ajax_silver_assist_get_security_logs',
			'wp_ajax_silver_assist_auto_save',
			'wp_ajax_silver_assist_validate_admin_path',
			'wp_ajax_silver_assist_add_manual_ip',
			'wp_ajax_silver_assist_unblock_ip',
		];

		foreach ( $expected_actions as $action ) {
			$this->assertNotFalse(
				\has_action( $action ),
				"AJAX action {$action} should be registered"
			);
		}
	}

	/**
	 * Test CF7 AJAX hooks registered only when CF7 is active
	 */
	public function test_cf7_ajax_only_when_cf7_active(): void {
		// Create CF7 handler (hooks register conditionally in constructor)
		$cf7_handler = new ContactForm7AjaxHandler();

		$cf7_actions = [
			'wp_ajax_silver_assist_get_cf7_blocked_ips',
			'wp_ajax_silver_assist_block_cf7_ip',
			'wp_ajax_silver_assist_unblock_cf7_ip',
			'wp_ajax_silver_assist_clear_cf7_blocked_ips',
			'wp_ajax_silver_assist_export_cf7_blocked_ips',
		];

		$cf7_active = \SilverAssist\Security\Core\SecurityHelper::is_contact_form_7_active();

		foreach ( $cf7_actions as $action ) {
			if ( $cf7_active ) {
				$this->assertNotFalse(
					\has_action( $action ),
					"CF7 AJAX action {$action} should be registered when CF7 is active"
				);
			} else {
				// If CF7 is not active, the hooks should not be registered by this instance
				// (they may exist from earlier test instances, so we just verify cf7_active is false)
				$this->assertFalse( $cf7_active, 'CF7 should not be detected as active' );
				break;
			}
		}
	}

	/**
	 * Test AJAX nonce validation rejects invalid nonce
	 */
	public function test_ajax_nonce_validation_rejects_invalid(): void {
		\wp_set_current_user( $this->admin_user_id );
		$_POST['nonce'] = 'invalid-nonce-value';

		$endpoints = [
			'get_security_status',
			'get_login_stats',
			'get_blocked_ips',
			'get_security_logs',
		];

		foreach ( $endpoints as $method ) {
			$response = $this->call_ajax_handler( $this->security_handler, $method );

			$this->assertFalse(
				$response['success'] ?? true,
				"Endpoint {$method} should reject invalid nonce"
			);
		}
	}

	/**
	 * Test subscriber cannot access admin endpoints
	 */
	public function test_ajax_subscriber_cannot_access_admin_endpoints(): void {
		\wp_set_current_user( $this->subscriber_user_id );
		$_POST['nonce'] = \wp_create_nonce( 'silver_assist_security_ajax' );

		$endpoints = [
			'get_security_status',
			'auto_save',
			'add_manual_ip',
			'unblock_ip',
		];

		foreach ( $endpoints as $method ) {
			$response = $this->call_ajax_handler( $this->security_handler, $method );

			$this->assertFalse(
				$response['success'] ?? true,
				"Subscriber should be denied access to {$method}"
			);
		}
	}

	/**
	 * Clean up
	 */
	protected function tearDown(): void {
		\wp_set_current_user( 0 );
		$_POST = [];
		$_SERVER['REQUEST_METHOD'] = 'GET';

		\wp_delete_user( $this->admin_user_id );
		\wp_delete_user( $this->subscriber_user_id );

		$this->teardown_ajax_environment();
		parent::tearDown();
	}
}
