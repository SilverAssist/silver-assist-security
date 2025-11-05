<?php
/**
 * Tests for IP Blacklist functionality
 *
 * Tests IP blacklisting, automatic blacklist based on violations,
 * and blacklist management functionality.
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.1.16
 */

use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * IP Blacklist Test class
 *
 * @since 1.1.16
 */
class IPBlacklistTest extends WP_UnitTestCase {

	/**
	 * Set up before each test
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();
		$this->clean_test_transients();
	}

	/**
	 * Clean up test transients using aggressive database cleanup
	 *
	 * @since 1.1.16
	 * @return void
	 */
	private function clean_test_transients(): void {
		global $wpdb;
		
		// Clean all IP blacklist and violation transients from database directly
		$wpdb->query(
			"DELETE FROM {$wpdb->options} 
			WHERE option_name LIKE '_transient_ip_blacklist_%' 
			OR option_name LIKE '_transient_timeout_ip_blacklist_%'
			OR option_name LIKE '_transient_ip_violations_%'
			OR option_name LIKE '_transient_timeout_ip_violations_%'"
		);
		
		// WordPress will handle object cache automatically in tests
	}

	/**
	 * Test manual IP blacklisting functionality
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_ip_blacklist_blocks_malicious_ip(): void {
		$blacklist = new IPBlacklist();
		$malicious_ip = '45.148.8.70'; // IP from the actual attack

		// Add IP to blacklist manually
		$blacklist->add_to_blacklist( $malicious_ip, 'Form spam attack detected', 3600 );

		// Should be blacklisted
		$this->assertTrue(
			$blacklist->is_blacklisted( $malicious_ip ),
			'Malicious IP should be blacklisted'
		);

		// Different IP should not be blacklisted
		$this->assertFalse(
			$blacklist->is_blacklisted( '192.168.1.100' ),
			'Clean IP should not be blacklisted'
		);
	}

	/**
	 * Test automatic blacklist after violation threshold
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_automatic_blacklist_after_threshold(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '10.0.0.' . rand(1, 254); // Generate unique IP

		// Ensure clean start
		$violations_key = "ip_violations_" . md5( $test_ip );
		$blacklist_key = "ip_blacklist_" . md5( $test_ip );
		\delete_transient( $violations_key );
		\delete_transient( $blacklist_key );

		// Verify starting with 0 violations
		$this->assertEquals( 0, $blacklist->get_violation_count( $test_ip ), 'Should start with 0 violations' );

		// Record multiple violations (default threshold: 5)
		for ( $i = 1; $i <= 4; $i++ ) {
			$blacklist->record_violation( $test_ip, 'Form spam' );
			$this->assertEquals( $i, $blacklist->get_violation_count( $test_ip ), "Should have {$i} violations" );
			$this->assertFalse(
				$blacklist->is_blacklisted( $test_ip ),
				"IP should not be blacklisted after {$i} violations"
			);
		}

		// 5th violation should trigger auto-blacklist
		$blacklist->record_violation( $test_ip, 'Form spam' );
		$this->assertTrue(
			$blacklist->is_blacklisted( $test_ip ),
			'IP should be auto-blacklisted after 5 violations'
		);
	}

	/**
	 * Test different violation types are tracked separately
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_violation_types_tracking(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '192.168.1.200';

		// Record different types of violations
		$violation_types = [
			'Form spam',
			'SQL injection',
			'Obsolete browser',
			'Rate limit exceeded',
			'Bot detection'
		];

		foreach ( $violation_types as $type ) {
			$blacklist->record_violation( $test_ip, $type );
		}

		// Should be auto-blacklisted after 5 violations
		$this->assertTrue(
			$blacklist->is_blacklisted( $test_ip ),
			'IP should be blacklisted after mixed violation types'
		);
	}

	/**
	 * Test blacklist expiration
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_blacklist_expiration(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '192.168.1.300';

		// Add with short expiration for testing
		$blacklist->add_to_blacklist( $test_ip, 'Test blacklist', 1 );

		// Should be blacklisted immediately
		$this->assertTrue( $blacklist->is_blacklisted( $test_ip ) );

		// Simulate expiration by clearing the transient
		$blacklist_key = "ip_blacklist_" . md5( $test_ip );
		\delete_transient( $blacklist_key );

		// Should no longer be blacklisted
		$this->assertFalse(
			$blacklist->is_blacklisted( $test_ip ),
			'IP should not be blacklisted after expiration'
		);
	}

	/**
	 * Test getting blacklist details
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_get_blacklist_details(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '45.148.8.70';
		$reason = 'Contact Form 7 spam attack';

		$blacklist->add_to_blacklist( $test_ip, $reason, 3600 );

		$details = $blacklist->get_blacklist_details( $test_ip );

		$this->assertIsArray( $details, 'Blacklist details should be an array' );
		$this->assertEquals( $test_ip, $details['ip'], 'IP should match' );
		$this->assertEquals( $reason, $details['reason'], 'Reason should match' );
		$this->assertArrayHasKey( 'timestamp', $details, 'Should have timestamp' );
		$this->assertArrayHasKey( 'duration', $details, 'Should have duration' );
	}

	/**
	 * Test removing IP from blacklist
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_remove_from_blacklist(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '192.168.1.400';

		// Add to blacklist
		$blacklist->add_to_blacklist( $test_ip, 'Test removal', 3600 );
		$this->assertTrue( $blacklist->is_blacklisted( $test_ip ) );

		// Remove from blacklist
		$blacklist->remove_from_blacklist( $test_ip );
		$this->assertFalse(
			$blacklist->is_blacklisted( $test_ip ),
			'IP should no longer be blacklisted after removal'
		);
	}

	/**
	 * Test violation count tracking
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_violation_count_tracking(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '10.0.1.' . (time() % 255); // Generate unique IP

		// Ensure clean start
		$violations_key = "ip_violations_" . md5( $test_ip );
		\delete_transient( $violations_key );

		// Should start with 0 violations
		$this->assertEquals( 0, $blacklist->get_violation_count( $test_ip ), 'Should start with 0 violations' );

		// Record 3 violations
		for ( $i = 1; $i <= 3; $i++ ) {
			$blacklist->record_violation( $test_ip, 'Test violation' );
			$count = $blacklist->get_violation_count( $test_ip );
			$this->assertEquals( $i, $count, "Violation count should be {$i}" );
		}
	}

	/**
	 * Test getting all blacklisted IPs
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_get_all_blacklisted_ips(): void {
		$blacklist = new IPBlacklist();
		$test_ips = [ '192.168.1.600', '192.168.1.601', '192.168.1.602' ];

		// Add multiple IPs to blacklist
		foreach ( $test_ips as $ip ) {
			$blacklist->add_to_blacklist( $ip, 'Test blacklist', 3600 );
		}

		$all_blacklisted = $blacklist->get_all_blacklisted_ips();

		$this->assertIsArray( $all_blacklisted, 'Should return array' );
		$this->assertGreaterThanOrEqual(
			count( $test_ips ),
			count( $all_blacklisted ),
			'Should include all test IPs'
		);

		// Check that all test IPs are in the list
		$blacklisted_ips = array_column( $all_blacklisted, 'ip' );
		foreach ( $test_ips as $ip ) {
			$this->assertContains(
				$ip,
				$blacklisted_ips,
				"Blacklisted IPs should include {$ip}"
			);
		}
	}

	/**
	 * Test violation window expiration
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function test_violation_window_expiration(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '10.0.2.' . (time() % 255); // Generate unique IP

		// Ensure clean start
		$violations_key = "ip_violations_" . md5( $test_ip );
		\delete_transient( $violations_key );

		// Should start with 0 violations
		$this->assertEquals( 0, $blacklist->get_violation_count( $test_ip ), 'Should start with 0 violations' );

		// Record violations
		$blacklist->record_violation( $test_ip, 'Test violation 1' );
		$blacklist->record_violation( $test_ip, 'Test violation 2' );

		$this->assertEquals( 2, $blacklist->get_violation_count( $test_ip ) );

		// Clear violations (simulate expiration)
		$violations_key = "ip_violations_" . md5( $test_ip );
		\delete_transient( $violations_key );

		// Should have no violations after window expires
		$this->assertEquals(
			0,
			$blacklist->get_violation_count( $test_ip ),
			'Violation count should reset after window expiration'
		);
	}

	/**
	 * Clean up after each test
	 *
	 * @since 1.1.16
	 * @return void
	 */
	public function tearDown(): void {
		// Clean up test IPs
		$test_ips = [
			'45.148.8.70', '45.148.8.71', '192.168.1.100', '192.168.1.200',
			'192.168.1.300', '192.168.1.400', '192.168.1.500', '192.168.1.501',
			'192.168.1.600', '192.168.1.601', '192.168.1.602',
			'192.168.1.700', '192.168.1.701'
		];

		foreach ( $test_ips as $ip ) {
			$blacklist_key = "ip_blacklist_" . md5( $ip );
			$violations_key = "ip_violations_" . md5( $ip );
			
			\delete_transient( $blacklist_key );
			\delete_transient( $violations_key );
		}

		parent::tearDown();
	}
}