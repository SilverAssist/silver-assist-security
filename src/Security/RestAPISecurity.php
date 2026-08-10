<?php
/**
 * Silver Assist Security Essentials - REST API Security
 *
 * Implements REST API protection including batch endpoint restriction,
 * rate limiting for unauthenticated requests, and request validation.
 * Protects against REST API abuse patterns discovered in WP2Shell and similar exploits.
 *
 * @package SilverAssist\Security\Security
 * @since 1.5.0
 * @author Silver Assist
 * @version 1.5.0
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * REST API Security class
 *
 * Handles REST API security including batch endpoint restriction and rate limiting
 *
 * @since 1.5.0
 */
class RestAPISecurity {

	/**
	 * Whether batch endpoint restriction is enabled
	 *
	 * @var bool
	 */
	private bool $batch_endpoint_enabled;

	/**
	 * Whether REST API rate limiting is enabled
	 *
	 * @var bool
	 */
	private bool $rate_limiting_enabled;

	/**
	 * REST API rate limit (requests per window)
	 *
	 * @var int
	 */
	private int $rate_limit_requests;

	/**
	 * REST API rate limit window (seconds)
	 *
	 * @var int
	 */
	private int $rate_limit_window;

	/**
	 * Constructor
	 *
	 * @since 1.5.0
	 */
	public function __construct() {
		$this->init_configuration();
		$this->init();
	}

	/**
	 * Initialize configuration from defaults
	 *
	 * @since 1.5.0
	 * @return void
	 */
	private function init_configuration(): void {
		$this->batch_endpoint_enabled  = (bool) DefaultConfig::get_option( 'silver_assist_rest_batch_endpoint_protection' );
		$this->rate_limiting_enabled   = (bool) DefaultConfig::get_option( 'silver_assist_rest_rate_limiting_enabled' );
		$this->rate_limit_requests     = (int) DefaultConfig::get_option( 'silver_assist_rest_rate_limit_requests' );
		$this->rate_limit_window       = (int) DefaultConfig::get_option( 'silver_assist_rest_rate_limit_window' );
	}

	/**
	 * Initialize REST API security hooks
	 *
	 * @since 1.5.0
	 * @return void
	 */
	private function init(): void {
		// Restrict batch endpoint for unauthenticated users
		if ( $this->batch_endpoint_enabled ) {
			\add_filter( 'rest_pre_dispatch', array( $this, 'restrict_batch_endpoint' ), 10, 3 );
		}

		// Rate limiting for unauthenticated REST requests
		if ( $this->rate_limiting_enabled ) {
			\add_filter( 'rest_pre_dispatch', array( $this, 'rate_limit_rest_api' ), 11, 3 );
		}
	}

	/**
	 * Restrict REST API batch endpoint for unauthenticated users
	 *
	 * The batch endpoint (/wp-json/batch/v1) can be exploited to chain multiple
	 * requests and bypass security restrictions. Since our sites use WPGraphQL
	 * for headless frontend delivery, the REST API batch endpoint serves no
	 * legitimate unauthenticated use case.
	 *
	 * @since 1.5.0
	 * @param mixed                     $response Response (could be WP_Error, WP_REST_Response, or pre-response).
	 * @param \WP_REST_Server          $server   REST server instance.
	 * @param \WP_REST_Request         $request  REST request object.
	 * @return mixed Original response or error
	 */
	public function restrict_batch_endpoint( $response, \WP_REST_Server $server, \WP_REST_Request $request ) {
		// Preserve any pre-existing error responses from earlier filters
		if ( \is_wp_error( $response ) ) {
			return $response;
		}

		// Only restrict if user is not authenticated
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$route = $request->get_route();

		// Check if this is a batch endpoint request (/batch/v1 or /batch/v1/...)
		if ( \strpos( $route, '/batch/v1' ) === 0 && ( \strlen( $route ) === 9 || $route[9] === '/' ) ) {
			return new \WP_Error(
				'rest_batch_disabled',
				'Batch requests require authentication.',
				array( 'status' => 403 )
			);
		}

		return $response;
	}

	/**
	 * Rate limit unauthenticated REST API requests
	 *
	 * Implements IP-based rate limiting for unauthenticated users to prevent
	 * abuse and enumeration attacks via the REST API.
	 *
	 * @since 1.5.0
	 * @param mixed                     $response Response (could be WP_Error, WP_REST_Response, or pre-response).
	 * @param \WP_REST_Server          $server   REST server instance.
	 * @param \WP_REST_Request         $request  REST request object.
	 * @return mixed Original response or error
	 */
	public function rate_limit_rest_api( $response, \WP_REST_Server $server, \WP_REST_Request $request ) {
		// Preserve any pre-existing error responses from earlier filters
		if ( \is_wp_error( $response ) ) {
			return $response;
		}

		// Only apply rate limiting to unauthenticated requests
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$client_ip = $this->get_client_ip();
		if ( empty( $client_ip ) ) {
			return $response;
		}

		// Use fixed-window rate limiting with explicit timestamp
		// Generate consistent transient keys using established SecurityHelper path
		$window_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_window', $client_ip );
		$count_key  = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', $client_ip );

		$current_time = \time();

		// Get the window start time (check if window has expired)
		$window_start = (int) \get_transient( $window_key );

		// Check if this is a new or expired window
		if ( ! $window_start || ( $current_time - $window_start ) >= $this->rate_limit_window ) {
			// Start new window
			// Critical: store start time with TTL and do NOT update it again
			// This prevents transient TTL reset that would extend the window indefinitely
			\set_transient( $window_key, $current_time, $this->rate_limit_window );
			\set_transient( $count_key, 1, $this->rate_limit_window );
			// Also initialize in cache for atomic increment
			\wp_cache_set( $count_key, 1, '' );
			$request_count = 1;
		} else {
			// Window still active - use atomic increment for race condition safety
			// Try to use wp_cache_incr for atomic increment (requires persistent cache)
			$request_count = \wp_cache_incr( $count_key, 1, '' );

			if ( false === $request_count ) {
				// Persistent cache not available (common on shared hosting).
				// Use MySQL atomic UPDATE on the underlying transient option row.
				// InnoDB row-level locking makes this safe against concurrent floods.
				// The transient TTL lives in a separate _transient_timeout_* option,
				// so this UPDATE does not reset the fixed window expiration.
				global $wpdb;
				$option_name = "_transient_{$count_key}";
				$updated     = $wpdb->query(
					$wpdb->prepare(
						"UPDATE {$wpdb->options} SET option_value = CAST(option_value AS UNSIGNED) + 1 WHERE option_name = %s",
						$option_name
					)
				);

				if ( 1 === (int) $updated ) {
					$request_count = (int) $wpdb->get_var(
						$wpdb->prepare(
							"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
							$option_name
						)
					);
				} else {
					// Row missing (transient expired between checks) — reinitialize.
					\set_transient( $count_key, 1, $this->rate_limit_window );
					$request_count = 1;
				}
			}
		}

		// Return 429 if limit exceeded
		if ( $request_count > $this->rate_limit_requests ) {
			return new \WP_Error(
				'rest_rate_limit_exceeded',
				'Too many requests. Please try again later.',
				array( 'status' => 429 )
			);
		}

		return $response;
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real client IP considering only trusted proxies.
	 * Only honors forwarded headers (CF-Connecting-IP, X-Forwarded-For) if REMOTE_ADDR
	 * is from a known trusted proxy (Cloudflare, etc).
	 *
	 * @since 1.5.0
	 * @return string Client IP address or empty string if not found
	 */
	private function get_client_ip(): string {
		// Get the direct connection IP
		$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		// If REMOTE_ADDR is from a trusted proxy, check forwarded headers
		if ( $remote_addr && $this->is_from_trusted_proxy( $remote_addr ) ) {
			// Try Cloudflare header first
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$ip = \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				if ( \filter_var( $ip, \FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}

			// Try X-Forwarded-For header
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$forwarded_ips = \array_map( 'trim', \explode( ',', \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) );
				if ( ! empty( $forwarded_ips[0] ) ) {
					$ip = $forwarded_ips[0];
					if ( \filter_var( $ip, \FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		// Fall back to REMOTE_ADDR if no trusted forwarded header found
		return ( \filter_var( $remote_addr, \FILTER_VALIDATE_IP ) ) ? $remote_addr : '';
	}

	/**
	 * Check if REMOTE_ADDR is from a trusted proxy
	 *
	 * Verifies that the direct connection IP is from a known trusted service
	 * (e.g., Cloudflare, AWS ELB, etc) before trusting forwarded headers.
	 *
	 * @since 1.5.0
	 * @param string $remote_addr The REMOTE_ADDR IP to check.
	 * @return bool True if IP is from a trusted proxy, false otherwise
	 */
	private function is_from_trusted_proxy( string $remote_addr ): bool {
		// Cloudflare official IP ranges (https://www.cloudflare.com/ips/)
		// Updated: 2026 official published ranges
		$cloudflare_ips = array(
			// IPv4 ranges
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'104.16.0.0/12',
			'108.162.192.0/18',
			'131.0.72.0/22',
			'141.101.64.0/18',      // Official range (was missing)
			'162.158.0.0/15',
			'172.64.0.0/13',
			'173.245.48.0/20',
			'188.114.96.0/20',
			'190.93.240.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			// IPv6 ranges
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);

		// Allow site owners to override with custom trusted proxies via filter
		$trusted_ips = \apply_filters( 'silver_assist_trusted_proxy_cidrs', $cloudflare_ips );

		// Check against trusted proxy CIDR ranges
		return $this->is_ip_in_range( $remote_addr, $trusted_ips );
	}

	/**
	 * Check if IP is within CIDR ranges
	 *
	 * @since 1.5.0
	 * @param string $ip    The IP address to check.
	 * @param array  $cidrs Array of CIDR ranges to check against.
	 * @return bool True if IP is in range, false otherwise
	 */
	private function is_ip_in_range( string $ip, array $cidrs ): bool {
		if ( ! \filter_var( $ip, \FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $cidrs as $cidr ) {
			if ( $this->is_ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if IP is within a specific CIDR range
	 *
	 * @since 1.5.0
	 * @param string $ip   The IP address to check.
	 * @param string $cidr The CIDR range (e.g., "192.168.1.0/24").
	 * @return bool True if IP is in range, false otherwise
	 */
	private function is_ip_in_cidr( string $ip, string $cidr ): bool {
		// Handle IPv6
		if ( \filter_var( $ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6 ) ) {
			return $this->is_ipv6_in_cidr( $ip, $cidr );
		}

		// Handle IPv4
		if ( ! \strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}

		list( $subnet, $bits ) = \explode( '/', $cidr );
		$ip_long = \ip2long( $ip );
		$subnet_long = \ip2long( $subnet );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		$mask = -1 << ( 32 - (int) $bits );
		$subnet_long &= $mask;
		$ip_long &= $mask;

		return $ip_long === $subnet_long;
	}

	/**
	 * Check if IPv6 is within CIDR range
	 *
	 * @since 1.5.0
	 * @param string $ip   The IPv6 address to check.
	 * @param string $cidr The IPv6 CIDR range.
	 * @return bool True if IP is in range, false otherwise
	 */
	private function is_ipv6_in_cidr( string $ip, string $cidr ): bool {
		if ( ! \strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}

		list( $subnet, $bits ) = \explode( '/', $cidr );
		$bits = (int) $bits;

		// Convert to binary representation
		$ip_bin = \inet_pton( $ip );
		$subnet_bin = \inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Create bitmask: calculate bytes and remainder bits
		$bytes = (int) ( $bits / 8 );       // Full bytes
		$remainder_bits = $bits % 8;        // Remaining bits in last byte

		$mask = \str_repeat( \chr( 255 ), $bytes );
		if ( $remainder_bits > 0 ) {
			// High-bit mask formula: 255 << (8 - remainder_bits)
			$mask .= \chr( 255 << ( 8 - $remainder_bits ) );
		}
		$mask .= \str_repeat( \chr( 0 ), 16 - \strlen( $mask ) );

		return ( $ip_bin & $mask ) === ( $subnet_bin & $mask );
	}
}
