<?php
/**
 * Silver Assist Security Essentials - Security Event Counter
 *
 * A small, bounded counter of security events (failed logins, IP blocks, bot blocks)
 * that the dashboard statistics read. It does not depend on WP_DEBUG logging.
 *
 * @package SilverAssist\Security\Core
 * @since 1.5.4
 */

namespace SilverAssist\Security\Core;

/**
 * Security Event Counter Class
 *
 * Events are counted into hourly buckets kept in one non-autoloaded option. Buckets
 * older than 30 days are dropped on every write, so storage is capped at 720 small
 * rows inside a single option no matter how much traffic arrives.
 *
 * @since 1.5.4
 */
class SecurityEventCounter {

	/**
	 * Option that holds the buckets
	 *
	 * @var string
	 */
	public const OPTION = 'silver_assist_security_event_counts';

	/**
	 * Event types
	 */
	public const FAILED_LOGIN = 'failed_logins';
	public const IP_BLOCKED   = 'blocked_ips';
	public const BOT_BLOCKED  = 'bot_blocks';

	/**
	 * How long buckets are kept, in seconds
	 *
	 * @var int
	 */
	private const RETENTION = 30 * DAY_IN_SECONDS;

	/**
	 * Count one event
	 *
	 * @param string $type Event type (one of the class constants).
	 * @return void
	 */
	public static function record( string $type ): void {
		$buckets = \get_option( self::OPTION, array() );
		$buckets = is_array( $buckets ) ? $buckets : array();
		$hour    = intdiv( time(), HOUR_IN_SECONDS );
		$oldest  = intdiv( time() - self::RETENTION, HOUR_IN_SECONDS );

		foreach ( array_keys( $buckets ) as $key ) {
			if ( (int) $key < $oldest ) {
				unset( $buckets[ $key ] );
			}
		}

		$buckets[ $hour ][ $type ] = (int) ( $buckets[ $hour ][ $type ] ?? 0 ) + 1;

		\update_option( self::OPTION, $buckets, false );
	}

	/**
	 * Count events since a timestamp
	 *
	 * Resolution is one hour: the hour containing the cutoff is included whole.
	 *
	 * @param string $type  Event type.
	 * @param int    $since Unix timestamp to count from.
	 * @return int Number of events.
	 */
	public static function count_since( string $type, int $since ): int {
		$buckets = \get_option( self::OPTION, array() );
		if ( ! is_array( $buckets ) ) {
			return 0;
		}

		$from  = intdiv( $since, HOUR_IN_SECONDS );
		$total = 0;
		foreach ( $buckets as $hour => $counts ) {
			if ( (int) $hour >= $from && is_array( $counts ) ) {
				$total += (int) ( $counts[ $type ] ?? 0 );
			}
		}

		return $total;
	}
}
