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
	public function restrict_batch_endpoint( $response, $server, $request ) {
		// Only restrict if user is not authenticated
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$route = $request->get_route();

		// Check if this is a batch endpoint request
		if ( \strpos( $route, '/batch/v1' ) === 0 ) {
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
	public function rate_limit_rest_api( $response, $server, $request ) {
		// Only apply rate limiting to unauthenticated requests
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$client_ip = $this->get_client_ip();
		if ( empty( $client_ip ) ) {
			return $response;
		}

		// Check rate limit using transients
		$rate_limit_key = 'silver_assist_rest_limit_' . \sanitize_text_field( $client_ip );
		$request_count  = (int) \get_transient( $rate_limit_key );

		// Increment counter
		if ( 0 === $request_count ) {
			// First request in this window
			\set_transient( $rate_limit_key, 1, $this->rate_limit_window );
		} else {
			if ( $request_count >= $this->rate_limit_requests ) {
				// Rate limit exceeded
				return new \WP_Error(
					'rest_rate_limit_exceeded',
					'Too many requests. Please try again later.',
					array( 'status' => 429 )
				);
			}

			// Increment counter (without resetting the expiration)
			\set_transient( $rate_limit_key, $request_count + 1, $this->rate_limit_window );
		}

		return $response;
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real client IP considering proxies and CDNs.
	 * Matches logic from existing SecurityHelper or IPBlacklist.
	 *
	 * @since 1.5.0
	 * @return string Client IP address or empty string if not found
	 */
	private function get_client_ip(): string {
		// Use SecurityHelper if available, otherwise implement inline
		if ( \method_exists( SecurityHelper::class, 'get_client_ip' ) ) {
			return SecurityHelper::get_client_ip();
		}

		// Fallback implementation
		$ip = '';

		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			// Cloudflare
			$ip = \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// Other proxies
			$forwarded_ips = \array_map( 'trim', \explode( ',', \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) );
			$ip            = ! empty( $forwarded_ips[0] ) ? $forwarded_ips[0] : '';
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			// Direct connection
			$ip = \sanitize_text_field( \wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return \filter_var( $ip, \FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
