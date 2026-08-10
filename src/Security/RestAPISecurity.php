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
		$this->batch_endpoint_enabled = (bool) DefaultConfig::get_option( 'silver_assist_rest_batch_endpoint_protection' );
		$this->rate_limiting_enabled  = (bool) DefaultConfig::get_option( 'silver_assist_rest_rate_limiting_enabled' );
		$this->rate_limit_requests    = (int) DefaultConfig::get_option( 'silver_assist_rest_rate_limit_requests' );
		$this->rate_limit_window      = (int) DefaultConfig::get_option( 'silver_assist_rest_rate_limit_window' );
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

		// Fixed-window rate limiting with two transients per client:
		//   - $window_key stores the window start timestamp (also acts as the claim lock).
		//   - $count_key  stores the request counter, incremented atomically.
		$window_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_window', $client_ip );
		$count_key  = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', $client_ip );

		$current_time  = \time();
		$request_count = $this->atomic_increment( $window_key, $count_key, $current_time );

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
	 * Atomically increment the rate-limit counter for a client
	 *
	 * Uses `INSERT IGNORE` (persistent-cache path uses `wp_cache_add`) to claim
	 * the first request in a new window, guaranteeing that exactly one caller
	 * initializes the window while every other caller is routed through the
	 * atomic increment path. This closes the flood-bypass window that opens at
	 * every window boundary when initialization is done via a non-atomic
	 * read-then-write sequence.
	 *
	 * @since 1.5.0
	 * @param string $window_key   Transient key for the window start timestamp.
	 * @param string $count_key    Transient key for the request counter.
	 * @param int    $current_time Current Unix timestamp.
	 * @return int Request count for this window (>= 1).
	 */
	private function atomic_increment( string $window_key, string $count_key, int $current_time ): int {
		$ttl = $this->rate_limit_window;

		// Persistent object cache: `wp_cache_add` is atomic across processes.
		// We claim the window by adding the *counter* key (not the window key) so
		// that any loser is guaranteed to find a valid counter to increment — no
		// gap between claim and counter-seeding for concurrent losers to slip into.
		if ( \wp_using_ext_object_cache() ) {
			if ( \wp_cache_add( $count_key, 1, '', $ttl ) ) {
				\wp_cache_set( $window_key, $current_time, '', $ttl );
				\set_transient( $count_key, 1, $ttl );
				\set_transient( $window_key, $current_time, $ttl );
				return 1;
			}

			$count = \wp_cache_incr( $count_key, 1, '' );
			if ( false !== $count ) {
				return (int) $count;
			}
			// Cache evicted the counter mid-window. Reclaim atomically so that if
			// several requests observe the miss simultaneously, only one caller
			// wins the `wp_cache_add` and returns 1; every loser is guaranteed to
			// find the reseeded counter and increment it instead of also returning 1.
			if ( \wp_cache_add( $count_key, 1, '', $ttl ) ) {
				\set_transient( $count_key, 1, $ttl );
				return 1;
			}
			$count = \wp_cache_incr( $count_key, 1, '' );
			return false === $count ? 1 : (int) $count;
		}

		// No persistent cache: rely on the UNIQUE index of `wp_options.option_name`
		// (`INSERT IGNORE`) and InnoDB row-level locking (`UPDATE ... value = value + 1`).
		global $wpdb;

		$count_option   = "_transient_{$count_key}";
		$count_timeout  = "_transient_timeout_{$count_key}";
		$window_option  = "_transient_{$window_key}";
		$window_timeout = "_transient_timeout_{$window_key}";
		$expiry         = $current_time + $ttl;

		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no'), (%s, %s, 'no'), (%s, %s, 'no'), (%s, %s, 'no')",
				$window_option,
				(string) $current_time,
				$window_timeout,
				(string) $expiry,
				$count_option,
				'1',
				$count_timeout,
				(string) $expiry
			)
		);

		if ( $inserted > 0 ) {
			// We won the claim (at least one row was newly inserted).
			return 1;
		}

		// Rows already exist. Detect an expired window: WordPress does not sweep
		// `_transient_timeout_*` rows unless someone reads the transient, but we hit
		// the options table directly, so we must expire and reset the window ourselves.
		// The count_timeout row doubles as the atomic reset lock: exactly one caller
		// transitions its value from "<= now" to the new expiry via the WHERE clause.
		$reset_won = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) <= %d",
				(string) $expiry,
				$count_timeout,
				$current_time
			)
		);
		if ( 1 === $reset_won ) {
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) $current_time, $window_option ) );
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) $expiry, $window_timeout ) );
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", '1', $count_option ) );
			return 1;
		}

		// Window is still active (or another caller just reset it) — atomically increment.
		$updated = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = CAST(option_value AS UNSIGNED) + 1 WHERE option_name = %s",
				$count_option
			)
		);

		if ( 1 === $updated ) {
			return (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
					$count_option
				)
			);
		}

		// Row vanished (transient GC between claim and increment) — reseed.
		\set_transient( $window_key, $current_time, $ttl );
		\set_transient( $count_key, 1, $ttl );
		return 1;
	}

	/**
	 * Get client IP address
	 *
	 * `X-Forwarded-For` is honored only when REMOTE_ADDR belongs to a configured
	 * trusted proxy (this plugin's target infrastructure sits behind AWS
	 * CloudFront + ALB; each site declares its VPC/edge CIDRs via
	 * `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` or the filter of the same name).
	 * The chain is parsed right-to-left so trusted proxy hops are discarded and
	 * the first untrusted address is used as the client IP.
	 *
	 * @since 1.5.0
	 * @return string Client IP address or empty string if not found
	 */
	private function get_client_ip(): string {
		$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		if ( $remote_addr && $this->is_from_trusted_proxy( $remote_addr ) && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$client_ip = $this->extract_forwarded_client_ip(
				\sanitize_text_field( \wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) )
			);
			if ( '' !== $client_ip ) {
				return $client_ip;
			}
		}

		return ( \filter_var( $remote_addr, \FILTER_VALIDATE_IP ) ) ? $remote_addr : '';
	}

	/**
	 * Extract the real client IP from an `X-Forwarded-For` chain
	 *
	 * Walks the chain right-to-left, discarding trusted proxy hops. The first
	 * untrusted address is treated as the client IP; this prevents spoofing via
	 * attacker-controlled leftmost values that a proxy may have appended to.
	 *
	 * @since 1.5.0
	 * @param string $header Raw `X-Forwarded-For` header value.
	 * @return string The client IP, or empty string if the chain contains no valid untrusted IP.
	 */
	private function extract_forwarded_client_ip( string $header ): string {
		$hops = \array_values(
			\array_filter(
				\array_map( 'trim', \explode( ',', $header ) ),
				static fn( string $hop ): bool => '' !== $hop
			)
		);

		for ( $i = \count( $hops ) - 1; $i >= 0; $i-- ) {
			$hop = $hops[ $i ];
			if ( ! \filter_var( $hop, \FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( $this->is_from_trusted_proxy( $hop ) ) {
				continue;
			}
			return $hop;
		}

		return '';
	}

	/**
	 * Check whether REMOTE_ADDR belongs to a configured trusted proxy
	 *
	 * Trusted CIDRs come from two sources (merged, in this order):
	 * 1. The `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` constant defined in `wp-config.php`,
	 *    accepted as a comma-separated string or an array — the recommended way to
	 *    declare the VPC / CloudFront edge ranges for each environment.
	 * 2. The `silver_assist_trusted_proxy_cidrs` filter, for programmatic overrides.
	 *
	 * There is no baked-in default: until a site declares its proxies, forwarded
	 * headers are ignored and REMOTE_ADDR is used verbatim.
	 *
	 * @since 1.5.0
	 * @param string $remote_addr The REMOTE_ADDR IP to check.
	 * @return bool True if IP is from a trusted proxy, false otherwise
	 */
	private function is_from_trusted_proxy( string $remote_addr ): bool {
		$configured = array();

		if ( \defined( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS' ) ) {
			$raw = \constant( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS' );
			if ( \is_string( $raw ) ) {
				$configured = \array_values( \array_filter( \array_map( 'trim', \explode( ',', $raw ) ) ) );
			} elseif ( \is_array( $raw ) ) {
				$configured = \array_values( \array_filter( \array_map( 'strval', $raw ) ) );
			}
		}

		/**
		 * Filters the list of trusted proxy CIDRs.
		 *
		 * @since 1.5.0
		 * @param string[] $configured CIDRs already collected from `SILVER_ASSIST_TRUSTED_PROXY_CIDRS`.
		 */
		$trusted_ips = \apply_filters( 'silver_assist_trusted_proxy_cidrs', $configured );

		if ( empty( $trusted_ips ) || ! \is_array( $trusted_ips ) ) {
			return false;
		}

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

		$parts = \explode( '/', $cidr );

		// Reject CIDRs that contain extra slashes (e.g. "192.0.2.0/0/typo") so a
		// stray path component cannot be dropped and silently trust every address.
		if ( 2 !== \count( $parts ) ) {
			return false;
		}
		list( $subnet, $bits ) = $parts;

		// Reject non-numeric or out-of-range prefixes so a typo like "/foo" or "/99" cannot silently trust every IPv4.
		if ( ! \ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( $bits < 0 || $bits > 32 ) {
			return false;
		}

		$ip_long     = \ip2long( $ip );
		$subnet_long = \ip2long( $subnet );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		if ( 0 === $bits ) {
			return true;
		}

		$mask         = -1 << ( 32 - $bits );
		$subnet_long &= $mask;
		$ip_long     &= $mask;

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

		$parts = \explode( '/', $cidr );

		// Reject CIDRs with extra slashes (e.g. "2001:db8::/0/typo") so a stray
		// path component cannot be dropped and silently trust every IPv6 sender.
		if ( 2 !== \count( $parts ) ) {
			return false;
		}
		list( $subnet, $bits ) = $parts;

		// Reject non-numeric or out-of-range prefixes so a typo like "/foo" or "/200" cannot trust every IPv6 or raise a ValueError in str_repeat().
		if ( ! \ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( $bits < 0 || $bits > 128 ) {
			return false;
		}

		// Convert to binary representation
		$ip_bin     = \inet_pton( $ip );
		$subnet_bin = \inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Create bitmask: calculate bytes and remainder bits
		$bytes          = (int) ( $bits / 8 );       // Full bytes
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
