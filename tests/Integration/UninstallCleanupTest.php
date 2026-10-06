<?php
/**
 * Deactivation and uninstall cleanup tests
 *
 * Uninstall must leave no option, transient, user meta or cron event written by the plugin (#151),
 * and must not touch data that belongs to other plugins.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\Activator;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Security\FormProtection;
use WP_UnitTestCase;

/**
 * Test the lifecycle cleanup handlers
 */
class UninstallCleanupTest extends WP_UnitTestCase {

	private const CRON_HOOK = 'silver_assist_security_cleanup';

	/**
	 * Transient keys (without the `_transient_` prefix) the plugin writes, one sample per family
	 *
	 * @return array<int, string>
	 */
	private function plugin_transient_keys(): array {
		$hash = md5( '203.0.113.9' );
		return array(
			'ip_blacklist_' . $hash,
			'ip_violations_' . $hash,
			'lockout_' . $hash,
			'login_attempts_' . $hash,
			'login_access_' . $hash,
			'bot_activity_' . $hash,
			'extended_bot_block_' . $hash,
			'graphql_rate_window_' . $hash,
			'graphql_rate_limit_' . $hash,
			'form_rate_' . $hash,
			'cf7_total_attacks',
			'bot_blocks_count_1700000000',
			'silver_assist_rest_window_' . $hash,
			'silver_assist_rest_limit_' . $hash,
			'silver_assist_blocked_ips_count',
			'silver-assist-security_version_check',
			'wp_github_updater_notice_silver-assist-security',
		);
	}

	/**
	 * Seed every key the plugin can write
	 *
	 * @return void
	 */
	private function seed_everything(): void {
		foreach ( DefaultConfig::get_defaults() as $option => $value ) {
			\update_option( $option, $value );
		}
		// Legacy option that older versions saved and that is not in the defaults.
		\update_option( 'silver_assist_ip_violation_threshold', 7 );

		foreach ( $this->plugin_transient_keys() as $key ) {
			\set_transient( $key, 'x', HOUR_IN_SECONDS );
		}

		// Form rate counter written by the real code path, and the key older versions wrote
		// (IP and prefix swapped, so the key starts with the raw IP).
		( new FormProtection() )->allow_form_submission( '203.0.113.9' );
		\set_transient( '203.0.113.9_' . md5( 'form_rate' ), 1, HOUR_IN_SECONDS );
		\set_transient( '2001:db8::1_' . md5( 'form_rate' ), 1, HOUR_IN_SECONDS );

		$user_id = self::factory()->user->create();
		\update_user_meta( $user_id, 'last_activity', time() );

		\wp_clear_scheduled_hook( self::CRON_HOOK );
		\wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
	}

	/**
	 * Count option rows that belong to the plugin
	 *
	 * @return array<int, string> Names of leftover rows.
	 */
	private function leftover_option_rows(): array {
		global $wpdb;

		$suffix = '%' . $wpdb->esc_like( '_' . md5( 'form_rate' ) );
		$names  = array();
		foreach ( array( 'silver\_assist\_%', '\_transient\_%', '\_transient\_timeout\_%' ) as $pattern ) {
			$rows = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $pattern ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$names = array_merge( $names, $rows );
		}
		$prefixes = array( 'ip_blacklist_', 'ip_violations_', 'lockout_', 'login_attempts_', 'login_access_', 'bot_activity_', 'extended_bot_block_', 'cf7_total_attacks', 'graphql_rate_', 'bot_blocks_count_', 'form_rate_', 'silver_assist_', 'silver-assist-security_', 'wp_github_updater_notice_silver-assist-security' );

		return array_values(
			array_filter(
				$names,
				static function ( string $name ) use ( $prefixes, $suffix ): bool {
					if ( str_starts_with( $name, 'silver_assist_' ) ) {
						return true;
					}
					$bare = preg_replace( '/^_transient_(timeout_)?/', '', $name, -1, $count );
					if ( 0 === $count ) {
						return false;
					}
					foreach ( $prefixes as $prefix ) {
						if ( str_starts_with( $bare, $prefix ) ) {
							return true;
						}
					}
					return str_ends_with( $bare, '_' . md5( 'form_rate' ) );
				}
			)
		);
	}

	/**
	 * Uninstall removes every option, transient (value and timeout rows), user meta and cron event
	 *
	 * @return void
	 */
	public function test_uninstall_leaves_nothing_behind(): void {
		$this->seed_everything();
		$this->assertNotEmpty( $this->leftover_option_rows(), 'seeding failed' );

		Activator::uninstall();

		$this->assertSame( array(), $this->leftover_option_rows() );

		global $wpdb;
		$this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'last_activity'" ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertFalse( \wp_next_scheduled( self::CRON_HOOK ) );
	}

	/**
	 * Uninstall does not remove other plugins' data
	 *
	 * @return void
	 */
	public function test_uninstall_keeps_unrelated_data(): void {
		$this->seed_everything();
		\update_option( 'other_plugin_setting', 'keep' );
		\set_transient( 'other_plugin_cache', 'keep', HOUR_IN_SECONDS );
		\set_transient( 'lockouts_report', 'keep', HOUR_IN_SECONDS );
		\update_user_meta( self::factory()->user->create(), 'other_meta', 'keep' );

		Activator::uninstall();

		$this->assertSame( 'keep', \get_option( 'other_plugin_setting' ) );
		$this->assertSame( 'keep', \get_transient( 'other_plugin_cache' ) );
		$this->assertSame( 'keep', \get_transient( 'lockouts_report' ) );
	}

	/**
	 * Deactivation unschedules the cleanup cron event
	 *
	 * @return void
	 */
	public function test_deactivate_clears_cron_event(): void {
		\wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		$this->assertNotFalse( \wp_next_scheduled( self::CRON_HOOK ) );

		Activator::deactivate();

		$this->assertFalse( \wp_next_scheduled( self::CRON_HOOK ) );
	}

	/**
	 * Activation only touches users with a session and does not load full user objects
	 *
	 * @return void
	 */
	public function test_activate_initializes_last_activity_for_sessions_only(): void {
		$with    = self::factory()->user->create();
		$without = self::factory()->user->create();
		\update_user_meta( $with, 'session_tokens', array( 'abc' => array( 'expiration' => time() + 3600 ) ) );

		\wp_cache_flush(); // A cold cache, as on a real activation request.
		global $wpdb;
		$queried = array();
		$spy     = static function ( $query ) use ( &$queried ) {
			$queried[] = $query;
			return $query;
		};
		\add_filter( 'query', $spy );
		Activator::activate();
		\remove_filter( 'query', $spy );

		// Loading full user rows (WP_User_Query with the default fields) primes the user cache with
		// `SELECT * FROM users WHERE ID IN (...)`, which on a large site means every user with a session.
		foreach ( $queried as $sql ) {
			$this->assertDoesNotMatchRegularExpression( '/SELECT\s+\*\s+FROM\s+' . preg_quote( $wpdb->users, '/' ) . '\s+WHERE\s+ID\s+IN\b/i', $sql, 'activation must not bulk-load full user rows' );
		}

		$this->assertNotEmpty( \get_user_meta( $with, 'last_activity', true ) );
		$this->assertEmpty( \get_user_meta( $without, 'last_activity', true ) );
	}
}
