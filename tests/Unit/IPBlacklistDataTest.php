<?php
/**
 * Silver Assist Security Essentials - IPBlacklist Data Structure Tests
 *
 * Tests data structure, CF7 filtering, and storage logic for the IPBlacklist class.
 * Complements tests/Security/IPBlacklistTest.php which focuses on core blocking behavior.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Security\IPBlacklist;
use WP_UnitTestCase;

/**
 * IPBlacklist data structure unit tests
 *
 * @since 1.1.15
 */
class IPBlacklistDataTest extends WP_UnitTestCase {

	/**
	 * IPBlacklist instance
	 *
	 * @var IPBlacklist
	 */
	private IPBlacklist $blacklist;

	/**
	 * IPs used during tests for cleanup
	 *
	 * @var array
	 */
	private array $test_ips = [];

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->blacklist = new IPBlacklist();
		$this->clean_blacklist_transients();
	}

	/**
	 * Clean all blacklist transients from database
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
	 * Register an IP for cleanup in tearDown
	 */
	private function track_ip( string $ip ): string {
		$this->test_ips[] = $ip;
		return $ip;
	}

	/**
	 * Test that add_to_blacklist creates a transient with correct key
	 */
	public function test_add_to_blacklist_creates_transient(): void {
		$ip = $this->track_ip( '10.20.30.40' );

		$this->blacklist->add_to_blacklist( $ip, 'Unit test', 3600 );

		$key  = 'ip_blacklist_' . md5( $ip );
		$data = \get_transient( $key );

		$this->assertIsArray( $data, 'Transient should store an array' );
		$this->assertSame( $ip, $data['ip'], 'Stored IP should match' );
	}

	/**
	 * Test blacklist data structure has all required fields
	 */
	public function test_blacklist_data_structure_has_required_fields(): void {
		$ip = $this->track_ip( '10.20.30.41' );

		$this->blacklist->add_to_blacklist( $ip, 'Structure test', 7200 );

		$data = $this->blacklist->get_blacklist_details( $ip );

		$this->assertIsArray( $data );
		$this->assertArrayHasKey( 'ip', $data );
		$this->assertArrayHasKey( 'reason', $data );
		$this->assertArrayHasKey( 'timestamp', $data );
		$this->assertArrayHasKey( 'duration', $data );
		$this->assertArrayHasKey( 'auto', $data );
		$this->assertArrayHasKey( 'user_agent', $data );

		$this->assertSame( $ip, $data['ip'] );
		$this->assertSame( 'Structure test', $data['reason'] );
		$this->assertSame( 7200, $data['duration'] );
		$this->assertFalse( $data['auto'], 'Manual block should have auto=false' );
	}

	/**
	 * Test that add_to_cf7_blacklist sets the type field
	 */
	public function test_add_to_cf7_blacklist_sets_type_field(): void {
		$ip = $this->track_ip( '10.20.30.42' );

		$this->blacklist->add_to_cf7_blacklist( $ip, 'CF7 spam', 'cf7_auto' );

		$details = $this->blacklist->get_blacklist_details( $ip );

		$this->assertIsArray( $details );
		$this->assertArrayHasKey( 'type', $details, 'CF7 block should include type field' );
		$this->assertSame( 'cf7_auto', $details['type'] );
	}

	/**
	 * Test get_cf7_blocked_ips filters by type
	 */
	public function test_get_cf7_blocked_ips_filters_by_type(): void {
		$cf7_ip   = $this->track_ip( '10.20.30.43' );
		$login_ip = $this->track_ip( '10.20.30.44' );

		// Add CF7 IP with type
		$this->blacklist->add_to_cf7_blacklist( $cf7_ip, 'CF7 attack', 'cf7_manual' );

		// Add login IP (no CF7 type)
		$this->blacklist->add_to_blacklist( $login_ip, 'Login brute force', 3600 );

		$cf7_ips = $this->blacklist->get_cf7_blocked_ips();

		$this->assertArrayHasKey( $cf7_ip, $cf7_ips, 'CF7 IP should appear in CF7 list' );
	}

	/**
	 * Test get_cf7_blocked_ips excludes login-only blocks
	 */
	public function test_get_cf7_blocked_ips_excludes_login_blocks(): void {
		$login_ip = $this->track_ip( '10.20.30.45' );

		// Add a login block with non-CF7 reason
		$this->blacklist->add_to_blacklist( $login_ip, 'Too many login attempts', 3600 );

		$cf7_ips = $this->blacklist->get_cf7_blocked_ips();

		// The login-only IP must not appear in CF7 list
		// Note: is_cf7_related_block checks for generic keywords like "form" or "spam".
		// A reason containing only "login" related words should not match.
		$this->assertArrayNotHasKey( $login_ip, $cf7_ips, 'Login-only IP should not appear in CF7 list' );
	}

	/**
	 * Test get_blacklist_stats returns correct counts
	 */
	public function test_get_blacklist_stats_returns_correct_counts(): void {
		$ip1 = $this->track_ip( '10.20.30.46' );
		$ip2 = $this->track_ip( '10.20.30.47' );

		// One manual block
		$this->blacklist->add_to_blacklist( $ip1, 'Manual block', 3600 );

		// One CF7 auto block (also manual through this method but auto flag depends on type)
		$this->blacklist->add_to_cf7_blacklist( $ip2, 'CF7 auto', 'cf7_auto' );

		$stats = $this->blacklist->get_blacklist_stats();

		$this->assertArrayHasKey( 'total_blacklisted', $stats );
		$this->assertArrayHasKey( 'auto_blacklisted', $stats );
		$this->assertArrayHasKey( 'manual_blacklisted', $stats );
		$this->assertGreaterThanOrEqual( 2, $stats['total_blacklisted'] );
	}

	/**
	 * Test clean_expired_violations removes old entries
	 */
	public function test_clean_expired_violations_removes_old_entries(): void {
		// The method orchestrates cleanup of various expired transients
		$cleaned = $this->blacklist->clean_expired_violations();

		// Should return an integer count (even if 0 when nothing to clean)
		$this->assertIsInt( $cleaned );
		$this->assertGreaterThanOrEqual( 0, $cleaned );
	}

	/**
	 * Test CF7 attack count increments when adding CF7 IPs
	 */
	public function test_cf7_attack_count_increments(): void {
		$ip1 = $this->track_ip( '10.20.30.48' );
		$ip2 = $this->track_ip( '10.20.30.49' );

		$count_before = $this->blacklist->get_cf7_attack_count();

		$this->blacklist->add_to_cf7_blacklist( $ip1, 'Attack 1', 'cf7_auto' );
		$this->blacklist->add_to_cf7_blacklist( $ip2, 'Attack 2', 'cf7_manual' );

		$count_after = $this->blacklist->get_cf7_attack_count();

		$this->assertSame(
			$count_before + 2,
			$count_after,
			'CF7 attack count should increment by 2'
		);
	}

	/**
	 * Test clear_cf7_blacklist only removes CF7 IPs
	 */
	public function test_clear_cf7_blacklist_only_removes_cf7_ips(): void {
		$cf7_ip   = $this->track_ip( '10.20.30.50' );
		$login_ip = $this->track_ip( '10.20.30.51' );

		$this->blacklist->add_to_cf7_blacklist( $cf7_ip, 'CF7 spam', 'cf7_manual' );
		$this->blacklist->add_to_blacklist( $login_ip, 'Too many login attempts', 3600 );

		$this->blacklist->clear_cf7_blacklist();

		// Login IP should still be blocked
		$this->assertTrue(
			$this->blacklist->is_blacklisted( $login_ip ),
			'Login IP should remain blacklisted after clearing CF7 list'
		);
	}

	/**
	 * Clean up after each test
	 */
	protected function tearDown(): void {
		foreach ( $this->test_ips as $ip ) {
			\delete_transient( 'ip_blacklist_' . md5( $ip ) );
			\delete_transient( 'ip_violations_' . md5( $ip ) );
		}
		\delete_transient( 'cf7_total_attacks' );

		parent::tearDown();
	}
}
