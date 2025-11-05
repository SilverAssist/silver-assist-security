<?php
/**
 * CF7 IP Blacklist Integration Test
 *
 * Tests the CF7-specific IP blacklist functionality including
 * CF7 IP management, filtering, and statistics.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.16
 */

namespace SilverAssist\Security\Tests\Integration;

use WP_UnitTestCase;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Tests\Helpers\TestHelper;

/**
 * CF7 IP Blacklist test case
 */
class CF7AdminPanelTest extends WP_UnitTestCase {

	private IPBlacklist $ip_blacklist;

	public function setUp(): void {
		parent::setUp();
		
		$this->ip_blacklist = IPBlacklist::getInstance();
	}

	public function tearDown(): void {
		// Clean up any test data
		TestHelper::cleanup_test_transients();
		parent::tearDown();
	}

	/**
	 * Test CF7 blocked IPs retrieval
	 */
	public function test_cf7_blocked_ips_retrieval(): void {
		// Add some CF7-related blocked IPs
		$test_ip1 = '192.168.1.100';
		$test_ip2 = '10.0.0.50';
		
		$this->ip_blacklist->add_to_cf7_blacklist($test_ip1, 'CF7 spam attempt', 'cf7_auto');
		$this->ip_blacklist->add_to_cf7_blacklist($test_ip2, 'Form injection detected', 'cf7_manual');

		// Get CF7 blocked IPs
		$cf7_blocked = $this->ip_blacklist->get_cf7_blocked_ips();
		
		$this->assertIsArray($cf7_blocked);
		$this->assertGreaterThan(0, count($cf7_blocked));
		$this->assertArrayHasKey($test_ip1, $cf7_blocked);
		$this->assertArrayHasKey($test_ip2, $cf7_blocked);
		
		// Verify structure of returned data
		$this->assertArrayHasKey('blocked_at', $cf7_blocked[$test_ip1]);
		$this->assertArrayHasKey('reason', $cf7_blocked[$test_ip1]);
		$this->assertEquals('CF7 spam attempt', $cf7_blocked[$test_ip1]['reason']);
	}

	/**
	 * Test manual CF7 IP blocking
	 */
	public function test_manual_cf7_ip_blocking(): void {
		$test_ip = '203.0.113.45';
		
		// Test CF7 IP blocking
		$success = $this->ip_blacklist->add_to_cf7_blacklist($test_ip, 'Manually blocked via admin panel', 'cf7_manual');
		
		$this->assertTrue($success);
		$this->assertTrue($this->ip_blacklist->is_blacklisted($test_ip));
	}

	/**
	 * Test CF7 IP unblocking
	 */
	public function test_cf7_ip_unblocking(): void {
		$test_ip = '198.51.100.25';
		
		// First block the IP
		$this->ip_blacklist->add_to_cf7_blacklist($test_ip, 'Test block', 'cf7_manual');
		$this->assertTrue($this->ip_blacklist->is_blacklisted($test_ip));
		
		// Unblock the IP
		$success = $this->ip_blacklist->remove_from_blacklist($test_ip);
		
		$this->assertTrue($success);
		$this->assertFalse($this->ip_blacklist->is_blacklisted($test_ip));
	}

	/**
	 * Test clearing all CF7 blocked IPs
	 */
	public function test_clear_all_cf7_blocked_ips(): void {
		// Add multiple CF7-related blocked IPs
		$test_ips = ['192.168.2.100', '10.1.1.50', '172.16.0.25'];
		
		foreach ($test_ips as $ip) {
			$this->ip_blacklist->add_to_cf7_blacklist($ip, 'CF7 test block', 'cf7_manual');
		}

		// Verify all are blocked
		foreach ($test_ips as $ip) {
			$this->assertTrue($this->ip_blacklist->is_blacklisted($ip));
		}
		
		// Clear CF7 blacklist
		$cleared_count = $this->ip_blacklist->clear_cf7_blacklist();
		
		$this->assertGreaterThan(0, $cleared_count);
		
		// Verify all CF7 IPs are cleared
		$cf7_blocked = $this->ip_blacklist->get_cf7_blocked_ips();
		$this->assertEmpty($cf7_blocked);
	}

	/**
	 * Test CF7 attack count tracking
	 */
	public function test_cf7_attack_count_tracking(): void {
		// Initially should be 0
		$initial_count = $this->ip_blacklist->get_cf7_attack_count();
		
		// Add CF7 blocks which should increment attack count
		$this->ip_blacklist->add_to_cf7_blacklist('203.0.113.10', 'Spam form submission', 'cf7_auto');
		$this->ip_blacklist->add_to_cf7_blacklist('198.51.100.15', 'SQL injection attempt', 'cf7_auto');
		
		// Attack count should have increased
		$new_count = $this->ip_blacklist->get_cf7_attack_count();
		$this->assertGreaterThan($initial_count, $new_count);
	}

	/**
	 * Test CF7 related block detection
	 */
	public function test_cf7_related_block_detection(): void {
		// Add various types of blocks
		$this->ip_blacklist->add_to_cf7_blacklist('192.0.2.10', 'CF7 spam attempt', 'cf7_auto');
		$this->ip_blacklist->add_to_cf7_blacklist('192.0.2.11', 'Contact form abuse', 'cf7_manual');
		$this->ip_blacklist->add_to_cf7_blacklist('192.0.2.12', 'Form injection detected', 'cf7_auto');
		
		// Also add a non-CF7 block for comparison
		$this->ip_blacklist->add_to_blacklist('192.0.2.20', 'Login brute force', 3600);
		
		$cf7_blocked = $this->ip_blacklist->get_cf7_blocked_ips();
		
		// Should contain CF7-related blocks
		$this->assertArrayHasKey('192.0.2.10', $cf7_blocked);
		$this->assertArrayHasKey('192.0.2.11', $cf7_blocked);
		$this->assertArrayHasKey('192.0.2.12', $cf7_blocked);
		
		// Should not contain non-CF7 blocks
		$this->assertArrayNotHasKey('192.0.2.20', $cf7_blocked);
	}
}