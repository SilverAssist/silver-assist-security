<?php
/**
 * Silver Assist Security Essentials - SecurityDataProvider Unit Tests
 *
 * Tests structure and correctness of data returned by SecurityDataProvider
 * including security status, blocked IPs, and security logs.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use WP_UnitTestCase;

/**
 * SecurityDataProvider unit tests
 *
 * @since 1.1.15
 */
class SecurityDataProviderTest extends WP_UnitTestCase {

	/**
	 * SecurityDataProvider instance
	 *
	 * @var SecurityDataProvider
	 */
	private SecurityDataProvider $provider;

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->provider = new SecurityDataProvider();
	}

	/**
	 * Test get_security_status returns all top-level keys
	 */
	public function test_get_security_status_returns_all_top_level_keys(): void {
		$status = $this->provider->get_security_status();

		$expected_keys = [
			'login_security',
			'admin_security',
			'graphql_security',
			'general_security',
			'form_protection',
			'overall',
		];

		foreach ( $expected_keys as $key ) {
			$this->assertArrayHasKey(
				$key,
				$status,
				"Security status should contain '{$key}' key"
			);
		}
	}

	/**
	 * Test get_blocked_ips returns correct structure
	 */
	public function test_get_blocked_ips_returns_correct_structure(): void {
		$result = $this->provider->get_blocked_ips();

		$this->assertArrayHasKey( 'blocked_ips', $result );
		$this->assertArrayHasKey( 'total_count', $result );
		$this->assertIsArray( $result['blocked_ips'] );
		$this->assertIsInt( $result['total_count'] );
	}

	/**
	 * Test get_blocked_ips includes time_left calculation
	 */
	public function test_get_blocked_ips_includes_time_left_calculation(): void {
		// Add a blocked IP first
		$blacklist = \SilverAssist\Security\Security\IPBlacklist::getInstance();
		$blacklist->add_to_blacklist( '10.99.99.1', 'Test block', 3600 );

		$result = $this->provider->get_blocked_ips();

		if ( $result['total_count'] > 0 ) {
			$first_ip = $result['blocked_ips'][0];
			$this->assertArrayHasKey( 'time_left', $first_ip, 'Blocked IP should have time_left' );
			$this->assertArrayHasKey( 'time_left_str', $first_ip, 'Blocked IP should have time_left_str' );
			$this->assertIsInt( $first_ip['time_left'] );
			$this->assertIsString( $first_ip['time_left_str'] );
		}

		// Cleanup
		$blacklist->remove_from_blacklist( '10.99.99.1' );
	}

	/**
	 * Test get_security_logs returns array structure
	 */
	public function test_get_security_logs_returns_array_structure(): void {
		$result = $this->provider->get_security_logs();

		$this->assertArrayHasKey( 'logs', $result );
		$this->assertArrayHasKey( 'total_count', $result );
		$this->assertArrayHasKey( 'message', $result );
		$this->assertIsArray( $result['logs'] );
		$this->assertIsInt( $result['total_count'] );
		$this->assertIsString( $result['message'] );
	}

	/**
	 * Test count_active_features returns integer
	 */
	public function test_count_active_features_returns_integer(): void {
		$count = $this->provider->count_active_features();

		$this->assertIsInt( $count );
		$this->assertGreaterThan( 0, $count, 'At least some features should be active' );
	}

	/**
	 * Test security status overall has statistics fields
	 */
	public function test_security_status_overall_has_statistics_fields(): void {
		$status  = $this->provider->get_security_status();
		$overall = $status['overall'];

		$this->assertArrayHasKey( 'blocked_ips_count', $overall );
		$this->assertArrayHasKey( 'failed_attempts_24h', $overall );
		$this->assertArrayHasKey( 'security_events_7d', $overall );
		$this->assertArrayHasKey( 'active_features', $overall );
		$this->assertArrayHasKey( 'total_features', $overall );
		$this->assertArrayHasKey( 'security_score', $overall );
		$this->assertArrayHasKey( 'last_updated', $overall );

		$this->assertIsInt( $overall['blocked_ips_count'] );
		$this->assertIsInt( $overall['active_features'] );
		$this->assertIsInt( $overall['total_features'] );
	}
}
