<?php
/**
 * Silver Assist Security Essentials - IP Block/Unblock Flow Integration Tests
 *
 * Tests complete IP management flows including manual blocking,
 * CF7 blocking, unblocking, and clearing operations end-to-end.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Tests\Helpers\AjaxTestHelper;
use WP_UnitTestCase;

/**
 * IP Block/Unblock flow integration tests
 *
 * @since 1.1.15
 */
class IPBlockUnblockFlowTest extends WP_UnitTestCase {

	use AjaxTestHelper;

	/**
	 * IPBlacklist instance
	 *
	 * @var IPBlacklist
	 */
	private IPBlacklist $blacklist;

	/**
	 * Admin user ID
	 *
	 * @var int
	 */
	private int $admin_user_id;

	/**
	 * Test IPs for cleanup
	 *
	 * @var array
	 */
	private array $test_ips = [];

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->blacklist     = new IPBlacklist();
		$this->admin_user_id = $this->factory()->user->create( [ 'role' => 'administrator' ] );
		$this->clean_blacklist_transients();
	}

	/**
	 * Clean blacklist transients
	 */
	private function clean_blacklist_transients(): void {
		global $wpdb;
		$wpdb->query(
			"DELETE FROM {$wpdb->options}
			WHERE option_name LIKE '_transient_ip_blacklist_%'
			OR option_name LIKE '_transient_timeout_ip_blacklist_%'
			OR option_name LIKE '_transient_ip_violations_%'
			OR option_name LIKE '_transient_timeout_ip_violations_%'
			OR option_name LIKE '_transient_cf7_total_attacks%'
			OR option_name LIKE '_transient_timeout_cf7_total_attacks%'"
		);
	}

	/**
	 * Track IP for cleanup
	 */
	private function track_ip( string $ip ): string {
		$this->test_ips[] = $ip;
		return $ip;
	}

	/**
	 * Test manual block then unblock flow
	 */
	public function test_manual_block_then_unblock_flow(): void {
		$ip = $this->track_ip( '10.60.60.1' );

		// Step 1: Block
		$this->blacklist->add_to_blacklist( $ip, 'Manual block test', 3600 );
		$this->assertTrue( $this->blacklist->is_blacklisted( $ip ), 'IP should be blocked' );

		// Step 2: Verify details
		$details = $this->blacklist->get_blacklist_details( $ip );
		$this->assertSame( $ip, $details['ip'] );
		$this->assertSame( 'Manual block test', $details['reason'] );

		// Step 3: Unblock
		$removed = $this->blacklist->remove_from_blacklist( $ip );
		$this->assertTrue( $removed, 'Remove should succeed' );

		// Step 4: Verify unblocked
		$this->assertFalse( $this->blacklist->is_blacklisted( $ip ), 'IP should be unblocked' );
	}

	/**
	 * Test CF7 block appears in CF7 list
	 */
	public function test_cf7_block_appears_in_cf7_list(): void {
		$cf7_ip = $this->track_ip( '10.60.60.2' );

		$this->blacklist->add_to_cf7_blacklist( $cf7_ip, 'CF7 spam test', 'cf7_manual' );

		$cf7_list = $this->blacklist->get_cf7_blocked_ips();
		$this->assertArrayHasKey( $cf7_ip, $cf7_list, 'CF7 IP should appear in CF7 list' );

		// Also verify it appears in general blacklist
		$this->assertTrue( $this->blacklist->is_blacklisted( $cf7_ip ) );
	}

	/**
	 * Test login block appears in general but not in CF7 list
	 */
	public function test_login_block_appears_in_general_not_cf7(): void {
		$login_ip = $this->track_ip( '10.60.60.3' );

		$this->blacklist->add_to_blacklist( $login_ip, 'Too many login attempts', 3600 );

		// Should be in general blacklist
		$this->assertTrue( $this->blacklist->is_blacklisted( $login_ip ) );

		// Should NOT be in CF7 list
		$cf7_list = $this->blacklist->get_cf7_blocked_ips();
		$this->assertArrayNotHasKey( $login_ip, $cf7_list, 'Login IP should not be in CF7 list' );
	}

	/**
	 * Test clear_cf7 preserves login blocks
	 */
	public function test_clear_cf7_preserves_login_blocks(): void {
		$cf7_ip   = $this->track_ip( '10.60.60.4' );
		$login_ip = $this->track_ip( '10.60.60.5' );

		$this->blacklist->add_to_cf7_blacklist( $cf7_ip, 'CF7 attack', 'cf7_auto' );
		$this->blacklist->add_to_blacklist( $login_ip, 'Too many login attempts', 3600 );

		// Clear CF7
		$cleared = $this->blacklist->clear_cf7_blacklist();
		$this->assertGreaterThanOrEqual( 1, $cleared );

		// Login IP should remain
		$this->assertTrue(
			$this->blacklist->is_blacklisted( $login_ip ),
			'Login IP should remain after clearing CF7 list'
		);
	}

	/**
	 * Test block/unblock via AJAX roundtrip
	 */
	public function test_block_unblock_via_ajax_roundtrip(): void {
		$ip = $this->track_ip( '10.60.60.6' );

		\wp_set_current_user( $this->admin_user_id );
		$this->setup_ajax_environment();
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Test)';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

		$data_provider  = new SecurityDataProvider();
		$stats_provider = new StatisticsProvider();
		$handler        = new SecurityAjaxHandler( $data_provider, $stats_provider );

		// Step 1: Block via AJAX
		$_POST['nonce']      = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = $ip;
		$_POST['reason']     = 'AJAX roundtrip test';

		$response = $this->call_ajax_handler( $handler, 'add_manual_ip' );

		$this->assertTrue( $response['success'] ?? false, 'Block via AJAX should succeed' );

		// Verify blocked
		$this->assertTrue( $this->blacklist->is_blacklisted( $ip ) );

		// Step 2: Unblock via AJAX
		$_POST['nonce']      = \wp_create_nonce( 'silver_assist_security_ajax' );
		$_POST['ip_address'] = $ip;

		$response = $this->call_ajax_handler( $handler, 'unblock_ip' );

		$this->assertTrue( $response['success'] ?? false, 'Unblock via AJAX should succeed' );

		// Verify unblocked
		$this->assertFalse( $this->blacklist->is_blacklisted( $ip ) );
	}

	/**
	 * Clean up
	 */
	protected function tearDown(): void {
		foreach ( $this->test_ips as $ip ) {
			\delete_transient( 'ip_blacklist_' . md5( $ip ) );
			\delete_transient( 'ip_violations_' . md5( $ip ) );
		}
		\delete_transient( 'cf7_total_attacks' );

		\wp_set_current_user( 0 );
		$_POST = [];
		$_SERVER['REQUEST_METHOD'] = 'GET';

		if ( $this->admin_user_id ) {
			\wp_delete_user( $this->admin_user_id );
		}

		$this->teardown_ajax_environment();
		parent::tearDown();
	}
}
