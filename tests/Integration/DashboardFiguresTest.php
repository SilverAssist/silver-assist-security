<?php
/**
 * Dashboard figures behavior tests
 *
 * The dashboard must show what really happened: the expiry and violations of an
 * auto-blacklisted IP, real failed logins and blocks in the statistics, and admin
 * hiding as inactive when it is off (#148).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Core\SecurityEventCounter;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Security\LoginSecurity;
use WP_Error;
use WP_UnitTestCase;

/**
 * Test that the dashboard figures match real events
 */
class DashboardFiguresTest extends WP_UnitTestCase {

	/**
	 * IP used by the tests
	 *
	 * @var string
	 */
	private string $ip = '198.51.100.88';

	/**
	 * Clean state
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		\delete_option( SecurityEventCounter::OPTION );
		\delete_transient( 'ip_blacklist_' . md5( $this->ip ) );
		\delete_transient( 'ip_violations_' . md5( $this->ip ) );
		\delete_option( 'silver_assist_ip_blacklist_enabled' );
		\delete_option( 'silver_assist_ip_blacklist_threshold' );
		\delete_option( 'silver_assist_admin_hide_enabled' );
		\update_option( 'silver_assist_ip_blacklist_duration', 3600 );
		\update_option( 'silver_assist_login_attempts', 5 );
		$_SERVER['REMOTE_ADDR'] = $this->ip;
	}

	/**
	 * Clean state
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		\delete_transient( 'ip_blacklist_' . md5( $this->ip ) );
		\delete_transient( 'ip_violations_' . md5( $this->ip ) );
		\delete_option( SecurityEventCounter::OPTION );
		parent::tearDown();
	}

	/**
	 * An auto-blacklisted IP shows its real expiry and violation count
	 *
	 * @return void
	 */
	public function test_auto_blacklisted_ip_shows_real_expiry_and_violations(): void {
		$blacklist = new IPBlacklist();
		for ( $i = 0; $i < 5; $i++ ) {
			$blacklist->record_violation( $this->ip, 'test_violation' );
		}
		$record = $blacklist->get_blacklist_details( $this->ip );
		$this->assertIsArray( $record );

		$entry = ( new SecurityDataProvider() )->get_blocked_ips()['blocked_ips'][0];

		$this->assertSame( $this->ip, $entry['ip'] );
		$this->assertSame( 5, $entry['violations'], 'Violations are the recorded list, not a cast of an array to 1.' );
		$this->assertSame( \gmdate( 'Y-m-d H:i:s', $record['timestamp'] + 3600 ), $entry['expires_at'], 'Expiry is timestamp plus duration, not 15 minutes.' );
		$this->assertGreaterThan( 3500, $entry['time_left'] );
	}

	/**
	 * A manual block shows its own duration
	 *
	 * @return void
	 */
	public function test_manual_block_shows_its_duration(): void {
		( new IPBlacklist() )->add_to_blacklist( $this->ip, 'Manual block', 2 * HOUR_IN_SECONDS );

		$entry = ( new SecurityDataProvider() )->get_blocked_ips()['blocked_ips'][0];

		$this->assertGreaterThan( 7000, $entry['time_left'] );
		$this->assertSame( 1, $entry['violations'] );
	}

	/**
	 * Real failed logins and the lockout they cause reach the statistics
	 *
	 * @return void
	 */
	public function test_failed_logins_and_lockout_are_counted(): void {
		\remove_all_actions( 'wp_login_failed' );
		$property = new \ReflectionProperty( LoginSecurity::class, 'instance' );
		$property->setAccessible( true );
		$property->setValue( null, null );
		LoginSecurity::instance();

		for ( $i = 0; $i < 5; $i++ ) {
			\do_action( 'wp_login_failed', 'someone', new WP_Error( 'incorrect_password' ) );
		}
		// The lockout error itself fires the hook too and must not be counted.
		\do_action( 'wp_login_failed', 'someone', new WP_Error( 'incorrect_password' ) );

		$day = ( new StatisticsProvider() )->get_login_statistics()['stats']['24_hours'];

		$this->assertSame( 5, $day['failed_logins'] );
		$this->assertSame( 1, $day['blocked_ips'], 'The lockout is one blocked IP.' );
		$this->assertSame( 6, $day['total_events'] );
	}

	/**
	 * A blacklist block and a bot block reach the statistics
	 *
	 * @return void
	 */
	public function test_blacklist_and_bot_blocks_are_counted(): void {
		( new IPBlacklist() )->add_to_blacklist( $this->ip, 'Manual block', HOUR_IN_SECONDS );
		SecurityEventCounter::record( SecurityEventCounter::BOT_BLOCKED );

		$week = ( new StatisticsProvider() )->get_login_statistics()['stats']['7_days'];

		$this->assertSame( 1, $week['blocked_ips'] );
		$this->assertSame( 1, $week['bot_blocks'] );
	}

	/**
	 * Events older than the period are not counted and old buckets are pruned
	 *
	 * @return void
	 */
	public function test_periods_and_retention(): void {
		$old = intdiv( time() - 40 * DAY_IN_SECONDS, HOUR_IN_SECONDS );
		$two = intdiv( time() - 2 * DAY_IN_SECONDS, HOUR_IN_SECONDS );
		\update_option(
			SecurityEventCounter::OPTION,
			array(
				$old => array( SecurityEventCounter::FAILED_LOGIN => 9 ),
				$two => array( SecurityEventCounter::FAILED_LOGIN => 4 ),
			),
			false
		);

		$stats = ( new StatisticsProvider() )->get_login_statistics()['stats'];
		$this->assertSame( 0, $stats['24_hours']['failed_logins'] );
		$this->assertSame( 4, $stats['7_days']['failed_logins'] );
		$this->assertSame( 4, $stats['30_days']['failed_logins'] );

		SecurityEventCounter::record( SecurityEventCounter::FAILED_LOGIN );
		$this->assertArrayNotHasKey( $old, \get_option( SecurityEventCounter::OPTION ), 'Buckets older than 30 days are dropped.' );
	}

	/**
	 * Admin hiding off reports inactive, on reports active
	 *
	 * @return void
	 */
	public function test_admin_hide_status_follows_the_setting(): void {
		$provider = new SecurityDataProvider();
		$this->assertSame( 'inactive', $provider->get_security_status()['admin_security']['status'] );

		\update_option( 'silver_assist_admin_hide_enabled', 1 );
		$this->assertSame( 'active', ( new SecurityDataProvider() )->get_security_status()['admin_security']['status'] );
	}

	/**
	 * Polling the statistics writes no transient and reads no log file
	 *
	 * @return void
	 */
	public function test_statistics_poll_writes_no_transient_and_reads_no_log(): void {
		global $wpdb;
		$stats = new StatisticsProvider();
		$stats->get_login_statistics();

		$before = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_%'" );
		$writes = array();
		\add_action(
			'set_transient',
			static function ( $name ) use ( &$writes ) {
				$writes[] = $name;
			}
		);
		\add_action(
			'setted_transient',
			static function ( $name ) use ( &$writes ) {
				$writes[] = $name;
			}
		);

		sleep( 1 );
		$stats->get_login_statistics();

		$after = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_%'" );
		$this->assertSame( $before, $after );
		$this->assertSame( array(), $writes );

		$method = new \ReflectionClass( StatisticsProvider::class );
		$this->assertFalse( $method->hasMethod( 'count_bot_blocks_from_logs' ), 'Statistics no longer parse log files.' );
	}

	/**
	 * debug.log is listed once even when two paths resolve to the same file
	 *
	 * @return void
	 */
	public function test_log_paths_are_deduplicated(): void {
		$method = new \ReflectionMethod( SecurityDataProvider::class, 'get_log_file_paths' );
		$method->setAccessible( true );
		$paths = $method->invoke( new SecurityDataProvider() );

		$real = array_map(
			static function ( $path ) {
				return realpath( $path ) ?: $path;
			},
			$paths
		);
		$this->assertSame( $real, array_values( array_unique( $real ) ) );
	}
}
