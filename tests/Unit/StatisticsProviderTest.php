<?php
/**
 * Silver Assist Security Essentials - StatisticsProvider Unit Tests
 *
 * Tests the StatisticsProvider class for correct return structures,
 * period statistics, and data integrity.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Admin\Data\StatisticsProvider;
use WP_UnitTestCase;

/**
 * StatisticsProvider unit tests
 *
 * @since 1.1.15
 */
class StatisticsProviderTest extends WP_UnitTestCase {

	/**
	 * StatisticsProvider instance
	 *
	 * @var StatisticsProvider
	 */
	private StatisticsProvider $provider;

	/**
	 * Set up test environment
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->provider = new StatisticsProvider();
	}

	/**
	 * Test get_login_statistics returns all period keys
	 */
	public function test_get_login_statistics_returns_all_periods(): void {
		$result = $this->provider->get_login_statistics();

		$this->assertArrayHasKey( 'stats', $result );
		$this->assertArrayHasKey( 'last_updated', $result );

		$stats = $result['stats'];
		$this->assertArrayHasKey( '24_hours', $stats );
		$this->assertArrayHasKey( '7_days', $stats );
		$this->assertArrayHasKey( '30_days', $stats );
	}

	/**
	 * Test each period stat has required fields
	 */
	public function test_period_stats_have_required_fields(): void {
		$result  = $this->provider->get_login_statistics();
		$periods = [ '24_hours', '7_days', '30_days' ];

		foreach ( $periods as $period_key ) {
			$period = $result['stats'][ $period_key ];

			$this->assertArrayHasKey( 'period', $period, "'{$period_key}' should have 'period'" );
			$this->assertArrayHasKey( 'failed_logins', $period, "'{$period_key}' should have 'failed_logins'" );
			$this->assertArrayHasKey( 'blocked_ips', $period, "'{$period_key}' should have 'blocked_ips'" );
			$this->assertArrayHasKey( 'bot_blocks', $period, "'{$period_key}' should have 'bot_blocks'" );
			$this->assertArrayHasKey( 'total_events', $period, "'{$period_key}' should have 'total_events'" );
		}
	}

	/**
	 * Test total_events is the sum of components
	 */
	public function test_total_events_is_sum_of_components(): void {
		$result  = $this->provider->get_login_statistics();
		$periods = [ '24_hours', '7_days', '30_days' ];

		foreach ( $periods as $period_key ) {
			$period = $result['stats'][ $period_key ];

			$expected_total = $period['failed_logins'] + $period['blocked_ips'] + $period['bot_blocks'];
			$this->assertSame(
				$expected_total,
				$period['total_events'],
				"total_events for '{$period_key}' should equal sum of failed_logins + blocked_ips + bot_blocks"
			);
		}
	}

	/**
	 * Test get_recent_failed_attempts returns an integer
	 */
	public function test_get_recent_failed_attempts_returns_integer(): void {
		$count = $this->provider->get_recent_failed_attempts();

		$this->assertIsInt( $count );
		$this->assertGreaterThanOrEqual( 0, $count );
	}

	/**
	 * Test get_blocked_ips_count returns an integer
	 */
	public function test_get_blocked_ips_count_returns_integer(): void {
		$count = $this->provider->get_blocked_ips_count();

		$this->assertIsInt( $count );
		$this->assertGreaterThanOrEqual( 0, $count );
	}
}
