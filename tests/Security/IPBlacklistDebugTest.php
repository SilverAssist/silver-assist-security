<?php
/**
 * Simple test for debugging IP Blacklist transient behavior
 *
 * @package SilverAssist\Security
 */

use SilverAssist\Security\Security\IPBlacklist;

class IPBlacklistDebugTest extends WP_UnitTestCase {
	
	public function setUp(): void {
		parent::setUp();
		$this->clean_all_transients();
	}

	public function tearDown(): void {
		$this->clean_all_transients();
		parent::tearDown();
	}

	private function clean_all_transients(): void {
		global $wpdb;
		$wpdb->query(
			"DELETE FROM {$wpdb->options} 
			WHERE option_name LIKE '_transient_ip_%'"
		);
	}

	public function test_debug_violation_count(): void {
		$blacklist = new IPBlacklist();
		$test_ip = '192.168.1.99';
		
		// Check initial count
		$initial_count = $blacklist->get_violation_count($test_ip);
		error_log("DEBUG: Initial count for {$test_ip}: {$initial_count}");
		
		// Record first violation
		$blacklist->record_violation($test_ip, 'Test violation');
		$count_after_first = $blacklist->get_violation_count($test_ip);
		error_log("DEBUG: Count after first violation: {$count_after_first}");
		
		// Check transient directly
		$violations_key = "ip_violations_" . md5($test_ip);
		$violations = \get_transient($violations_key);
		error_log("DEBUG: Direct transient value: " . print_r($violations, true));
		
		$this->assertEquals(0, $initial_count, 'Should start with 0 violations');
		$this->assertEquals(1, $count_after_first, 'Should have 1 violation after recording one');
	}
}