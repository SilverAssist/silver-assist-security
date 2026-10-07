<?php
/**
 * Silver Assist Security Essentials - IP Blacklist Management
 *
 * Provides IP blacklisting functionality with automatic blacklisting
 * based on violation thresholds and manual management capabilities.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.15
 * @author Silver Assist
 * @version 1.5.4
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityEventCounter;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * IP Blacklist class
 *
 * Manages IP blacklisting for malicious IPs and automatic blacklisting
 * based on violation patterns.
 *
 * Scope, by design: this is the Contact Form 7 flood protection, added after an attack that sent
 * submits within seconds of each other. `ContactForm7Integration::validate_cf7_submission()` is the
 * only caller of `is_blacklisted()`, so a blocked IP can still use the login, the front end, REST
 * and GraphQL. The login lockout by IP is a separate protection in `LoginSecurity` with its own
 * counters and dashboard figure; the two share only the client IP resolution and the IPv6 grouping
 * in `SecurityHelper` (see the README, "Two IP protections").
 *
 * @since 1.1.15
 */
class IPBlacklist {

	/**
	 * Class instance
	 *
	 * @var ?IPBlacklist
	 */
	private static ?IPBlacklist $instance = null;

	/**
	 * Option holding the blacklist index: key => Unix time the block ends
	 *
	 * Blocks are transients, which a persistent object cache keeps out of the options table, so they
	 * cannot be listed by scanning it. The index is a small, non-autoloaded option written on every
	 * block and pruned of expired entries as it is written.
	 */
	public const INDEX_OPTION = 'silver_assist_ip_blacklist_index';

	/**
	 * Most entries the index keeps (the ones ending soonest are dropped first)
	 *
	 * A block dropped from the index still applies; it is only missing from the list.
	 */
	private const INDEX_LIMIT = 1000;

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		// Initialize if needed.
	}

	/**
	 * Get singleton instance
	 *
	 * @since 1.1.15
	 * @return IPBlacklist
	 */
	public static function get_instance(): IPBlacklist {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- Deprecated camelCase alias kept for backward compatibility; see get_instance().
	/**
	 * Deprecated alias for get_instance()
	 *
	 * Kept for backward compatibility: this is a public accessor on a project
	 * that follows Semantic Versioning, so renaming it without a compatibility
	 * shim would break external code calling IPBlacklist::getInstance() directly.
	 *
	 * @deprecated 1.5.1 Use get_instance() instead.
	 * @since 1.1.15
	 * @return IPBlacklist
	 */
	public static function getInstance(): IPBlacklist {
		return self::get_instance();
	}

	/**
	 * Transient key of an IP's block (IPv6 addresses share their network prefix's key)
	 *
	 * @since 1.5.4
	 * @param string $ip IP address.
	 * @return string
	 */
	private function blacklist_key( string $ip ): string {
		return SecurityHelper::generate_ip_transient_key( 'ip_blacklist', $ip );
	}

	/**
	 * Read the blacklist index
	 *
	 * The first read after an upgrade, when the option does not exist yet, imports the blocks
	 * already stored in the options table (sites without a persistent object cache).
	 *
	 * @since 1.5.4
	 * @return array<string, int> Key => expiry timestamp.
	 */
	private function get_index(): array {
		$index = \get_option( self::INDEX_OPTION, false );

		if ( is_array( $index ) ) {
			return $index;
		}

		$index = array();
		if ( ! \wp_using_ext_object_cache() ) {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time import of blocks stored before the index existed.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
					$wpdb->esc_like( '_transient_timeout_ip_blacklist_' ) . '%'
				)
			);
			foreach ( (array) $rows as $row ) {
				$key           = substr( (string) $row->option_name, strlen( '_transient_timeout_' ) );
				$index[ $key ] = (int) $row->option_value;
			}
		}

		\update_option( self::INDEX_OPTION, $index, false );
		return $index;
	}

	/**
	 * Record a block in the index and prune the expired ones
	 *
	 * @since 1.5.4
	 * @param string $key      Transient key of the block.
	 * @param int    $duration Block duration in seconds.
	 * @return void
	 */
	private function index_add( string $key, int $duration ): void {
		$index         = $this->get_index();
		$index[ $key ] = time() + $duration;
		$index         = array_filter(
			$index,
			static function ( int $expiry ): bool {
				return $expiry > time();
			}
		);

		if ( count( $index ) > self::INDEX_LIMIT ) {
			asort( $index );
			$index = array_slice( $index, -self::INDEX_LIMIT, null, true );
		}

		\update_option( self::INDEX_OPTION, $index, false );
	}

	/**
	 * Remove a block from the index
	 *
	 * @since 1.5.4
	 * @param string $key Transient key of the block.
	 * @return void
	 */
	private function index_remove( string $key ): void {
		$index = $this->get_index();
		if ( isset( $index[ $key ] ) ) {
			unset( $index[ $key ] );
			\update_option( self::INDEX_OPTION, $index, false );
		}
	}

	/**
	 * Drop expired entries from the index
	 *
	 * @since 1.5.4
	 * @return int Number of entries dropped.
	 */
	private function prune_index(): int {
		$index  = $this->get_index();
		$active = array_filter(
			$index,
			static function ( int $expiry ): bool {
				return $expiry > time();
			}
		);

		if ( count( $active ) !== count( $index ) ) {
			\update_option( self::INDEX_OPTION, $active, false );
		}

		return count( $index ) - count( $active );
	}

	/**
	 * Add IP to blacklist manually
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist.
	 * @param string $reason Reason for blacklisting.
	 * @param int    $duration Duration in seconds.
	 * @return void
	 */
	public function add_to_blacklist( string $ip, string $reason, int $duration ): void {
		$blacklist_key  = $this->blacklist_key( $ip );
		$blacklist_data = array(
			'ip'         => $ip,
			'reason'     => $reason,
			'timestamp'  => time(),
			'duration'   => $duration,
			'auto'       => false,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
		);

		\set_transient( $blacklist_key, $blacklist_data, $duration );
		$this->index_add( $blacklist_key, $duration );
		SecurityEventCounter::record( SecurityEventCounter::IP_BLOCKED );

		SecurityHelper::log_security_event(
			'IP_BLACKLISTED',
			"IP added to blacklist: {$reason}",
			array(
				'ip'       => $ip,
				'reason'   => $reason,
				'duration' => $duration,
				'auto'     => false,
			)
		);
	}

	/**
	 * Check if IP is blacklisted
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to check.
	 * @return bool True if blacklisted, false otherwise
	 */
	public function is_blacklisted( string $ip ): bool {
		$blacklist_key = $this->blacklist_key( $ip );
		return \get_transient( $blacklist_key ) !== false;
	}

	/**
	 * Record security violation for IP
	 *
	 * Tracks violations and automatically blacklists IP when threshold is reached.
	 *
	 * @since 1.1.15
	 * @param string $ip IP address.
	 * @param string $type Type of violation.
	 * @return void
	 */
	public function record_violation( string $ip, string $type ): void {
		// Automatic blacklisting can be switched off in the admin; manual blocks still apply.
		if ( ! (bool) DefaultConfig::get_option( 'silver_assist_ip_blacklist_enabled' ) ) {
			return;
		}

		$violations_key    = SecurityHelper::generate_ip_transient_key( 'ip_violations', $ip );
		$stored_violations = \get_transient( $violations_key );
		$violations        = ( false !== $stored_violations && is_array( $stored_violations ) ) ? $stored_violations : array();

		$violation_window = (int) DefaultConfig::get_option( 'silver_assist_ip_violation_window' );
		$threshold        = $this->get_violation_threshold();

		$violations[] = array(
			'type'        => $type,
			'timestamp'   => time(),
			'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
			'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
		);

		\set_transient( $violations_key, $violations, $violation_window );

		SecurityHelper::log_security_event(
			'SECURITY_VIOLATION_RECORDED',
			"Security violation recorded: {$type}",
			array(
				'ip'               => $ip,
				'violation_type'   => $type,
				'total_violations' => count( $violations ),
				'threshold'        => $threshold,
			)
		);

		// Auto-blacklist if threshold reached.
		if ( count( $violations ) >= $threshold ) {
			$this->auto_blacklist_ip( $ip, $violations );
		}
	}

	/**
	 * Violations before an IP is automatically blacklisted
	 *
	 * Earlier versions saved the value as `silver_assist_ip_violation_threshold`, an option nothing
	 * read. A value saved there is still honored until the canonical option is saved.
	 *
	 * @since 1.5.4
	 * @return int
	 */
	private function get_violation_threshold(): int {
		$default = (int) DefaultConfig::get_default( 'silver_assist_ip_blacklist_threshold' );
		$legacy  = (int) \get_option( 'silver_assist_ip_violation_threshold', $default );

		return (int) \get_option( 'silver_assist_ip_blacklist_threshold', $legacy );
	}

	/**
	 * Automatically blacklist IP due to violations
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist.
	 * @param array  $violations Array of violations.
	 * @return void
	 */
	private function auto_blacklist_ip( string $ip, array $violations ): void {
		$violation_types = array_unique( array_column( $violations, 'type' ) );
		$duration        = (int) DefaultConfig::get_option( 'silver_assist_ip_blacklist_duration' );

		$reason = sprintf(
			'Auto-blacklist: %d violations (%s)',
			count( $violations ),
			implode( ', ', $violation_types )
		);

		$blacklist_key  = $this->blacklist_key( $ip );
		$blacklist_data = array(
			'ip'         => $ip,
			'reason'     => $reason,
			'timestamp'  => time(),
			'duration'   => $duration,
			'auto'       => true,
			'violations' => $violations,
		);

		\set_transient( $blacklist_key, $blacklist_data, $duration );
		$this->index_add( $blacklist_key, $duration );
		SecurityEventCounter::record( SecurityEventCounter::IP_BLOCKED );

		SecurityHelper::log_security_event(
			'IP_AUTO_BLACKLISTED',
			$reason,
			array(
				'ip'              => $ip,
				'violation_count' => count( $violations ),
				'violation_types' => $violation_types,
				'duration'        => $duration,
				'auto'            => true,
			)
		);
	}

	/**
	 * Get blacklist details for IP
	 *
	 * @since 1.1.15
	 * @param string $ip IP address.
	 * @return array|false Blacklist details or false if not blacklisted
	 */
	public function get_blacklist_details( string $ip ) {
		$blacklist_key = $this->blacklist_key( $ip );
		return \get_transient( $blacklist_key );
	}

	/**
	 * Remove IP from blacklist
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to remove.
	 * @return bool True if removed, false if not found
	 */
	public function remove_from_blacklist( string $ip ): bool {
		$blacklist_key   = $this->blacklist_key( $ip );
		$was_blacklisted = \get_transient( $blacklist_key ) !== false;

		if ( $was_blacklisted ) {
			\delete_transient( $blacklist_key );
			$this->index_remove( $blacklist_key );

			SecurityHelper::log_security_event(
				'IP_REMOVED_FROM_BLACKLIST',
				'IP manually removed from blacklist',
				array( 'ip' => $ip )
			);
		}

		return $was_blacklisted;
	}

	/**
	 * Get violation count for IP
	 *
	 * @since 1.1.15
	 * @param string $ip IP address.
	 * @return int Number of violations
	 */
	public function get_violation_count( string $ip ): int {
		$violations_key    = SecurityHelper::generate_ip_transient_key( 'ip_violations', $ip );
		$stored_violations = \get_transient( $violations_key );
		$violations        = ( false !== $stored_violations && is_array( $stored_violations ) ) ? $stored_violations : array();
		return count( $violations );
	}

	/**
	 * Get all blacklisted IPs
	 *
	 * Reads the blocks listed in the index through the transient API, so it works with and without a
	 * persistent object cache. Entries whose transient is gone are skipped.
	 *
	 * @since 1.1.15
	 * @since 1.5.4 Reads the index instead of scanning the options table.
	 * @return array Array of blacklisted IP data
	 */
	public function get_all_blacklisted_ips(): array {
		$blacklisted_ips = array();

		foreach ( array_keys( $this->get_index() ) as $key ) {
			$data = \get_transient( $key );
			if ( is_array( $data ) && isset( $data['ip'] ) ) {
				$blacklisted_ips[ $data['ip'] ] = $data;
			}
		}

		return $blacklisted_ips;
	}

	/**
	 * Clean expired violations and lockouts
	 *
	 * Removes expired IP lockouts, violation counts, and rate limit transients
	 * to prevent database bloat. This method should be called by a cron job.
	 *
	 * @since 1.1.15
	 * @return int Number of expired violations cleaned
	 */
	public function clean_expired_violations(): int {
		try {
			// Expired blocks drop out of the index in every setup.
			$cleaned_count = $this->prune_index();

			// Expired transient rows only exist in the options table. A persistent object cache expires
			// its own entries, so there is nothing to scan.
			if ( ! \wp_using_ext_object_cache() ) {
				$cleaned_count += $this->clean_expired_lockouts();
				$cleaned_count += $this->clean_expired_violation_counts();
				$cleaned_count += $this->clean_expired_rate_limits();
				$cleaned_count += $this->clean_expired_bot_blocks();
			}

			// Log cleanup results.
			SecurityHelper::log_security_event(
				'IP_CLEANUP_SUCCESS',
				"Successfully cleaned {$cleaned_count} expired IP violations",
				array(
					'cleaned_count' => $cleaned_count,
					'cleanup_time'  => \current_time( 'mysql' ),
				)
			);

			// Schedule next cleanup if not already scheduled.
			$this->schedule_next_cleanup();

			return $cleaned_count;

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'IP_CLEANUP_ERROR',
				"Failed to clean expired violations: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			return 0;
		}
	}

	/**
	 * Clean expired lockout transients
	 *
	 * @return int Number of lockouts cleaned
	 * @since 1.1.15
	 */
	private function clean_expired_lockouts(): int {
		global $wpdb;

		$current_time = time();
		$cleaned      = 0;

		// Get all lockout transients.
		$lockout_transients = $wpdb->get_results(
			"SELECT option_name, option_value 
			 FROM {$wpdb->options} 
			 WHERE option_name LIKE '_transient_timeout_lockout_%'"
		);

		foreach ( $lockout_transients as $transient ) {
			$expiry_time = (int) $transient->option_value;

			// If transient has expired, clean it up.
			if ( $expiry_time < $current_time ) {
				$transient_name = str_replace( '_transient_timeout_', '', $transient->option_name );

				// Delete both timeout and value transients.
				\delete_transient( $transient_name );
				++$cleaned;
			}
		}

		return $cleaned;
	}

	/**
	 * Clean expired violation count transients
	 *
	 * @return int Number of violation counts cleaned
	 * @since 1.1.15
	 */
	private function clean_expired_violation_counts(): int {
		global $wpdb;

		$current_time = time();
		$cleaned      = 0;

		// Get all violation count transients.
		$violation_transients = $wpdb->get_results(
			"SELECT option_name, option_value 
			 FROM {$wpdb->options} 
			 WHERE option_name LIKE '_transient_timeout_violations_%'"
		);

		foreach ( $violation_transients as $transient ) {
			$expiry_time = (int) $transient->option_value;

			if ( $expiry_time < $current_time ) {
				$transient_name = str_replace( '_transient_timeout_', '', $transient->option_name );
				\delete_transient( $transient_name );
				++$cleaned;
			}
		}

		return $cleaned;
	}

	/**
	 * Clean expired rate limit transients
	 *
	 * @return int Number of rate limits cleaned
	 * @since 1.1.15
	 */
	private function clean_expired_rate_limits(): int {
		global $wpdb;

		$current_time = time();
		$cleaned      = 0;

		// Pattern matches: login_attempts_, graphql_rate_limit_, etc.
		$rate_limit_patterns = array(
			'_transient_timeout_login_attempts_%',
			'_transient_timeout_login_window_%',
			'_transient_timeout_login_access_%',
			'_transient_timeout_graphql_rate_limit_%',
			'_transient_timeout_rate_limit_%',
		);

		foreach ( $rate_limit_patterns as $pattern ) {
			$rate_limit_transients = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_name, option_value 
					 FROM {$wpdb->options} 
					 WHERE option_name LIKE %s",
					$pattern
				)
			);

			foreach ( $rate_limit_transients as $transient ) {
				$expiry_time = (int) $transient->option_value;

				if ( $expiry_time < $current_time ) {
					$transient_name = str_replace( '_transient_timeout_', '', $transient->option_name );
					\delete_transient( $transient_name );
					++$cleaned;
				}
			}
		}

		return $cleaned;
	}

	/**
	 * Clean expired bot block transients
	 *
	 * @return int Number of bot blocks cleaned
	 * @since 1.1.15
	 */
	private function clean_expired_bot_blocks(): int {
		global $wpdb;

		$current_time = time();
		$cleaned      = 0;

		// Get bot blocking related transients.
		$bot_transients = $wpdb->get_results(
			"SELECT option_name, option_value 
			 FROM {$wpdb->options} 
			 WHERE option_name LIKE '_transient_timeout_%bot_block%'"
		);

		foreach ( $bot_transients as $transient ) {
			$expiry_time = (int) $transient->option_value;

			if ( $expiry_time < $current_time ) {
				$transient_name = str_replace( '_transient_timeout_', '', $transient->option_name );
				\delete_transient( $transient_name );
				++$cleaned;
			}
		}

		return $cleaned;
	}

	/**
	 * Schedule next cleanup if not already scheduled
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function schedule_next_cleanup(): void {
		// Check if cleanup is already scheduled.
		if ( ! \wp_next_scheduled( 'silver_assist_security_cleanup' ) ) {
			// Schedule daily cleanup at 3 AM local time.
			\wp_schedule_event(
				strtotime( 'tomorrow 3:00 AM' ),
				'daily',
				'silver_assist_security_cleanup'
			);

			SecurityHelper::log_security_event(
				'CLEANUP_SCHEDULED',
				'Scheduled daily IP violation cleanup',
				array( 'next_run' => \wp_next_scheduled( 'silver_assist_security_cleanup' ) )
			);
		}
	}

	/**
	 * Initialize cron cleanup on plugin activation
	 *
	 * This method should be called during plugin activation to set up
	 * the recurring cleanup job.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function init_cron_cleanup(): void {
		// Register the cron hook.
		\add_action( 'silver_assist_security_cleanup', array( __CLASS__, 'run_scheduled_cleanup' ) );

		// Schedule initial cleanup if not already scheduled.
		if ( ! \wp_next_scheduled( 'silver_assist_security_cleanup' ) ) {
			\wp_schedule_event(
				strtotime( 'tomorrow 3:00 AM' ),
				'daily',
				'silver_assist_security_cleanup'
			);
		}
	}

	/**
	 * Run scheduled cleanup (called by WordPress cron)
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public static function run_scheduled_cleanup(): void {
		$ip_blacklist = new self();
		$cleaned      = $ip_blacklist->clean_expired_violations();

		SecurityHelper::log_security_event(
			'SCHEDULED_CLEANUP_COMPLETED',
			"Scheduled IP cleanup completed, cleaned {$cleaned} expired violations",
			array(
				'cleaned_count' => $cleaned,
				'run_time'      => \current_time( 'mysql' ),
			)
		);
	}

	/**
	 * Get blacklist statistics
	 *
	 * @since 1.1.15
	 * @return array Statistics about blacklisted IPs
	 */
	public function get_blacklist_stats(): array {
		$all_blacklisted  = $this->get_all_blacklisted_ips();
		$auto_blacklisted = array_filter(
			$all_blacklisted,
			function ( $item ) {
				return isset( $item['auto'] ) && true === $item['auto'];
			}
		);

		return array(
			'total_blacklisted'  => count( $all_blacklisted ),
			'auto_blacklisted'   => count( $auto_blacklisted ),
			'manual_blacklisted' => count( $all_blacklisted ) - count( $auto_blacklisted ),
		);
	}

	/**
	 * Get CF7 specific blocked IPs
	 *
	 * @since 1.1.15
	 * @return array Array of CF7 blocked IPs with their data
	 */
	public function get_cf7_blocked_ips(): array {
		$all_blacklisted = $this->get_all_blacklisted_ips();
		$cf7_blocked     = array();

		foreach ( $all_blacklisted as $ip => $data ) {
			// Check if this is CF7 related (by type or reason keywords).
			$reason = $data['reason'] ?? '';
			$type   = $data['type'] ?? '';

			if ( strpos( $type, 'cf7' ) !== false || $this->is_cf7_related_block( $reason ) ) {
				$cf7_blocked[ $ip ] = array(
					'blocked_at' => $data['timestamp'] ?? time(),
					'reason'     => $reason,
					'violations' => $this->get_cf7_violation_count( $ip ),
					'user_agent' => $data['user_agent'] ?? 'Unknown',
				);
			}
		}

		return $cf7_blocked;
	}

	/**
	 * Get CF7 attack count
	 *
	 * @since 1.1.15
	 * @return int Total number of CF7 attacks
	 */
	public function get_cf7_attack_count(): int {
		$cf7_attacks_key = 'cf7_total_attacks';
		return (int) \get_transient( $cf7_attacks_key );
	}

	/**
	 * Clear all CF7 related blocked IPs
	 *
	 * @since 1.1.15
	 * @return int Number of IPs cleared
	 */
	public function clear_cf7_blacklist(): int {
		$cf7_blocked   = $this->get_cf7_blocked_ips();
		$cleared_count = 0;

		foreach ( $cf7_blocked as $ip => $data ) {
			$success = $this->remove_from_blacklist( $ip );
			if ( $success ) {
				++$cleared_count;
			}
		}

		SecurityHelper::log_security_event(
			'CF7_BLACKLIST_CLEARED',
			"Cleared {$cleared_count} CF7 blocked IPs",
			array( 'count' => $cleared_count )
		);

		return $cleared_count;
	}

	/**
	 * Add CF7-specific IP to blacklist
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist.
	 * @param string $reason Reason for blacklisting.
	 * @param string $type Type of block (cf7_manual, cf7_auto, etc).
	 * @return bool Success status
	 */
	public function add_to_cf7_blacklist( string $ip, string $reason, string $type = 'cf7_manual' ): bool {
		$duration = DefaultConfig::get_option( 'silver_assist_cf7_ip_block_duration' ) ? DefaultConfig::get_option( 'silver_assist_cf7_ip_block_duration' ) : 3600; // 1 hour default

		$blacklist_key  = $this->blacklist_key( $ip );
		$blacklist_data = array(
			'ip'         => $ip,
			'reason'     => $reason,
			'timestamp'  => time(),
			'duration'   => $duration,
			'auto'       => ( 'cf7_auto' === $type ),
			'type'       => $type,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
		);

		$success = \set_transient( $blacklist_key, $blacklist_data, $duration );

		if ( $success ) {
			$this->index_add( $blacklist_key, (int) $duration );

			// Increment CF7 attack count.
			$this->increment_cf7_attack_count();

			SecurityHelper::log_security_event(
				'CF7_IP_BLACKLISTED',
				"CF7 IP added to blacklist: {$reason}",
				array(
					'ip'       => $ip,
					'reason'   => $reason,
					'duration' => $duration,
					'type'     => $type,
					'auto'     => $blacklist_data['auto'],
				)
			);
		}

		return (bool) $success;
	}

	/**
	 * Check if a block reason is CF7 related
	 *
	 * @since 1.1.15
	 * @param string $reason Block reason.
	 * @return bool True if CF7 related
	 */
	private function is_cf7_related_block( string $reason ): bool {
		$cf7_keywords = array( 'cf7', 'contact form', 'form', 'spam', 'obsolete browser', 'sql injection' );
		$reason_lower = strtolower( $reason );

		foreach ( $cf7_keywords as $keyword ) {
			if ( strpos( $reason_lower, $keyword ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get CF7 violation count for specific IP
	 *
	 * @since 1.1.15
	 * @param string $ip IP address.
	 * @return int Violation count
	 */
	private function get_cf7_violation_count( string $ip ): int {
		$violations_key = SecurityHelper::generate_ip_transient_key( 'ip_violations', $ip );
		$violations     = \get_transient( $violations_key );

		if ( ! is_array( $violations ) ) {
			return 1;
		}

		$cf7_violations = array_filter(
			$violations,
			function ( $violation ) {
				return isset( $violation['type'] ) && strpos( $violation['type'], 'cf7' ) !== false;
			}
		);

		return count( $cf7_violations );
	}

	/**
	 * Increment CF7 attack count
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function increment_cf7_attack_count(): void {
		$cf7_attacks_key = 'cf7_total_attacks';
		$current_count   = (int) \get_transient( $cf7_attacks_key );
		\set_transient( $cf7_attacks_key, $current_count + 1, DAY_IN_SECONDS );
	}
}
