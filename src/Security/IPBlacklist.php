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
 * @version 1.1.15
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * IP Blacklist class
 *
 * Manages IP blacklisting for malicious IPs and automatic blacklisting
 * based on violation patterns.
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
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		// Initialize if needed
	}

	/**
	 * Get singleton instance
	 *
	 * @since 1.1.15
	 * @return IPBlacklist
	 */
	public static function getInstance(): IPBlacklist {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Add IP to blacklist manually
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist
	 * @param string $reason Reason for blacklisting
	 * @param int    $duration Duration in seconds
	 * @return void
	 */
	public function add_to_blacklist( string $ip, string $reason, int $duration ): void {
		$blacklist_key = "ip_blacklist_" . md5( $ip );
		$blacklist_data = [
			'ip' => $ip,
			'reason' => $reason,
			'timestamp' => time(),
			'duration' => $duration,
			'auto' => false,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
		];

		\set_transient( $blacklist_key, $blacklist_data, $duration );

		SecurityHelper::log_security_event(
			'IP_BLACKLISTED',
			"IP added to blacklist: {$reason}",
			[
				'ip' => $ip,
				'reason' => $reason,
				'duration' => $duration,
				'auto' => false,
			]
		);
	}

	/**
	 * Check if IP is blacklisted
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to check
	 * @return bool True if blacklisted, false otherwise
	 */
	public function is_blacklisted( string $ip ): bool {
		$blacklist_key = "ip_blacklist_" . md5( $ip );
		return \get_transient( $blacklist_key ) !== false;
	}

	/**
	 * Record security violation for IP
	 *
	 * Tracks violations and automatically blacklists IP when threshold is reached.
	 *
	 * @since 1.1.15
	 * @param string $ip IP address
	 * @param string $type Type of violation
	 * @return void
	 */
	public function record_violation( string $ip, string $type ): void {
		$violations_key = "ip_violations_" . md5( $ip );
		$stored_violations = \get_transient( $violations_key );
		$violations = ( $stored_violations !== false && is_array( $stored_violations ) ) ? $stored_violations : [];
		
		$violation_window = (int) DefaultConfig::get_option( 'silver_assist_ip_violation_window' );
		$threshold = (int) DefaultConfig::get_option( 'silver_assist_ip_blacklist_threshold' );

		$violations[] = [
			'type' => $type,
			'timestamp' => time(),
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
			'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
		];

		\set_transient( $violations_key, $violations, $violation_window );

		SecurityHelper::log_security_event(
			'SECURITY_VIOLATION_RECORDED',
			"Security violation recorded: {$type}",
			[
				'ip' => $ip,
				'violation_type' => $type,
				'total_violations' => count( $violations ),
				'threshold' => $threshold,
			]
		);

		// Auto-blacklist if threshold reached
		if ( count( $violations ) >= $threshold ) {
			$this->auto_blacklist_ip( $ip, $violations );
		}
	}

	/**
	 * Automatically blacklist IP due to violations
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist
	 * @param array  $violations Array of violations
	 * @return void
	 */
	private function auto_blacklist_ip( string $ip, array $violations ): void {
		$violation_types = array_unique( array_column( $violations, 'type' ) );
		$duration = (int) DefaultConfig::get_option( 'silver_assist_ip_blacklist_duration' );
		
		$reason = sprintf(
			'Auto-blacklist: %d violations (%s)',
			count( $violations ),
			implode( ', ', $violation_types )
		);

		$blacklist_key = "ip_blacklist_" . md5( $ip );
		$blacklist_data = [
			'ip' => $ip,
			'reason' => $reason,
			'timestamp' => time(),
			'duration' => $duration,
			'auto' => true,
			'violations' => $violations,
		];

		\set_transient( $blacklist_key, $blacklist_data, $duration );

		SecurityHelper::log_security_event(
			'IP_AUTO_BLACKLISTED',
			$reason,
			[
				'ip' => $ip,
				'violation_count' => count( $violations ),
				'violation_types' => $violation_types,
				'duration' => $duration,
				'auto' => true,
			]
		);
	}

	/**
	 * Get blacklist details for IP
	 *
	 * @since 1.1.15
	 * @param string $ip IP address
	 * @return array|false Blacklist details or false if not blacklisted
	 */
	public function get_blacklist_details( string $ip ) {
		$blacklist_key = "ip_blacklist_" . md5( $ip );
		return \get_transient( $blacklist_key );
	}

	/**
	 * Remove IP from blacklist
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to remove
	 * @return bool True if removed, false if not found
	 */
	public function remove_from_blacklist( string $ip ): bool {
		$blacklist_key = "ip_blacklist_" . md5( $ip );
		$was_blacklisted = \get_transient( $blacklist_key ) !== false;

		if ( $was_blacklisted ) {
			\delete_transient( $blacklist_key );

			SecurityHelper::log_security_event(
				'IP_REMOVED_FROM_BLACKLIST',
				'IP manually removed from blacklist',
				[ 'ip' => $ip ]
			);
		}

		return $was_blacklisted;
	}

	/**
	 * Get violation count for IP
	 *
	 * @since 1.1.15
	 * @param string $ip IP address
	 * @return int Number of violations
	 */
	public function get_violation_count( string $ip ): int {
		$violations_key = "ip_violations_" . md5( $ip );
		$stored_violations = \get_transient( $violations_key );
		$violations = ( $stored_violations !== false && is_array( $stored_violations ) ) ? $stored_violations : [];
		return count( $violations );
	}

	/**
	 * Get all blacklisted IPs
	 *
	 * Note: This is a simplified implementation. In a production environment,
	 * you might want to store blacklist keys in a separate index for efficiency.
	 *
	 * @since 1.1.15
	 * @return array Array of blacklisted IP data
	 */
	public function get_all_blacklisted_ips(): array {
		global $wpdb;

		// Query all transients that match our blacklist pattern
		// This is simplified - in production you'd want a more efficient approach
		$blacklisted_ips = [];
		
		// Get transients from database that match our pattern
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} 
				 WHERE option_name LIKE %s 
				 AND option_name NOT LIKE %s",
				'_transient_ip_blacklist_%',
				'_transient_timeout_ip_blacklist_%'
			)
		);

		foreach ( $results as $row ) {
			$data = maybe_unserialize( $row->option_value );
			if ( is_array( $data ) && isset( $data['ip'] ) ) {
				$blacklisted_ips[ $data['ip'] ] = $data;
			}
		}

		return $blacklisted_ips;
	}

	/**
	 * Clean expired violations
	 *
	 * This method would typically be called by a cron job.
	 *
	 * @since 1.1.15
	 * @return int Number of expired violations cleaned
	 */
	public function clean_expired_violations(): int {
		// This is a placeholder for cron-based cleanup
		// In real implementation, you'd scan for expired violation transients
		return 0;
	}

	/**
	 * Get blacklist statistics
	 *
	 * @since 1.1.15
	 * @return array Statistics about blacklisted IPs
	 */
	public function get_blacklist_stats(): array {
		$all_blacklisted = $this->get_all_blacklisted_ips();
		$auto_blacklisted = array_filter( $all_blacklisted, function( $item ) {
			return isset( $item['auto'] ) && $item['auto'] === true;
		});

		return [
			'total_blacklisted' => count( $all_blacklisted ),
			'auto_blacklisted' => count( $auto_blacklisted ),
			'manual_blacklisted' => count( $all_blacklisted ) - count( $auto_blacklisted ),
		];
	}

	/**
	 * Get CF7 specific blocked IPs
	 *
	 * @since 1.1.15
	 * @return array Array of CF7 blocked IPs with their data
	 */
	public function get_cf7_blocked_ips(): array {
		$all_blacklisted = $this->get_all_blacklisted_ips();
		$cf7_blocked = [];

		foreach ( $all_blacklisted as $ip => $data ) {
			// Check if this is CF7 related (by type or reason keywords)
			$reason = $data['reason'] ?? '';
			$type = $data['type'] ?? '';
			
			if ( strpos( $type, 'cf7' ) !== false || $this->is_cf7_related_block( $reason ) ) {
				$cf7_blocked[ $ip ] = [
					'blocked_at' => $data['timestamp'] ?? time(),
					'reason' => $reason,
					'violations' => $this->get_cf7_violation_count( $ip ),
					'user_agent' => $data['user_agent'] ?? 'Unknown',
				];
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
		$cf7_blocked = $this->get_cf7_blocked_ips();
		$cleared_count = 0;

		foreach ( $cf7_blocked as $ip => $data ) {
			$success = $this->remove_from_blacklist( $ip );
			if ( $success ) {
				$cleared_count++;
			}
		}

		SecurityHelper::log_security_event(
			'CF7_BLACKLIST_CLEARED',
			"Cleared {$cleared_count} CF7 blocked IPs",
			[ 'count' => $cleared_count ]
		);

		return $cleared_count;
	}

	/**
	 * Add CF7-specific IP to blacklist
	 *
	 * @since 1.1.15
	 * @param string $ip IP address to blacklist
	 * @param string $reason Reason for blacklisting
	 * @param string $type Type of block (cf7_manual, cf7_auto, etc)
	 * @return bool Success status
	 */
	public function add_to_cf7_blacklist( string $ip, string $reason, string $type = 'cf7_manual' ): bool {
		$duration = DefaultConfig::get_option( 'silver_assist_cf7_ip_block_duration' ) ?: 3600; // 1 hour default
		
		$blacklist_key = "ip_blacklist_" . md5( $ip );
		$blacklist_data = [
			'ip' => $ip,
			'reason' => $reason,
			'timestamp' => time(),
			'duration' => $duration,
			'auto' => ( $type === 'cf7_auto' ),
			'type' => $type,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
		];

		$success = \set_transient( $blacklist_key, $blacklist_data, $duration );

		if ( $success ) {
			// Increment CF7 attack count
			$this->increment_cf7_attack_count();

			SecurityHelper::log_security_event(
				'CF7_IP_BLACKLISTED',
				"CF7 IP added to blacklist: {$reason}",
				[
					'ip' => $ip,
					'reason' => $reason,
					'duration' => $duration,
					'type' => $type,
					'auto' => $blacklist_data['auto'],
				]
			);
		}

		return (bool) $success;
	}

	/**
	 * Check if a block reason is CF7 related
	 *
	 * @since 1.1.15
	 * @param string $reason Block reason
	 * @return bool True if CF7 related
	 */
	private function is_cf7_related_block( string $reason ): bool {
		$cf7_keywords = [ 'cf7', 'contact form', 'form', 'spam', 'obsolete browser', 'sql injection' ];
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
	 * @param string $ip IP address
	 * @return int Violation count
	 */
	private function get_cf7_violation_count( string $ip ): int {
		$violations_key = "ip_violations_" . md5( $ip );
		$violations = \get_transient( $violations_key );
		
		if ( ! is_array( $violations ) ) {
			return 1;
		}
		
		$cf7_violations = array_filter( $violations, function( $violation ) {
			return isset( $violation['type'] ) && strpos( $violation['type'], 'cf7' ) !== false;
		});
		
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
		$current_count = (int) \get_transient( $cf7_attacks_key );
		\set_transient( $cf7_attacks_key, $current_count + 1, DAY_IN_SECONDS );
	}
}