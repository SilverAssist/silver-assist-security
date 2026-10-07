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
 * @version 1.5.4
 */

namespace SilverAssist\Security\Security;

use SilverAssist\PluginKernel\Interfaces\LoadableInterface;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * REST API Security class
 *
 * Handles REST API security including batch endpoint restriction and rate limiting
 *
 * @since 1.5.0
 */
class RestAPISecurity implements LoadableInterface {

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

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
		$this->register_hooks();
	}

	/**
	 * Get singleton instance
	 *
	 * @since 1.5.1
	 * @return self
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * LoadableInterface entry point
	 *
	 * A no-op: hook registration already happens unconditionally in the
	 * constructor (see register_hooks()), which instance() triggers the
	 * first time it constructs this singleton.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public function init(): void {
	}

	/**
	 * Get loading priority
	 *
	 * @since 1.5.1
	 * @return int
	 */
	public function get_priority(): int {
		return 10;
	}

	/**
	 * Whether this component should load
	 *
	 * Matches pre-kernel behavior, where Plugin::init_security_components()
	 * only constructed RestAPISecurity if at least one of its two
	 * sub-features was enabled.
	 *
	 * @since 1.5.1
	 * @return bool
	 */
	public function should_load(): bool {
		return $this->batch_endpoint_enabled || $this->rate_limiting_enabled;
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
	 * Register REST API security hooks
	 *
	 * @since 1.5.0
	 * @return void
	 */
	private function register_hooks(): void {
		// Restrict batch endpoint for unauthenticated users.
		if ( $this->batch_endpoint_enabled ) {
			\add_filter( 'rest_pre_dispatch', array( $this, 'restrict_batch_endpoint' ), 10, 3 );
		}

		// Rate limiting for unauthenticated REST requests.
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
	 * @param mixed            $response Response (could be WP_Error, WP_REST_Response, or pre-response).
	 * @param \WP_REST_Server  $server   REST server instance.
	 * @param \WP_REST_Request $request  REST request object.
	 * @return mixed Original response or error
	 */
	public function restrict_batch_endpoint( $response, \WP_REST_Server $server, \WP_REST_Request $request ) {
		// Preserve any pre-existing error responses from earlier filters.
		if ( \is_wp_error( $response ) ) {
			return $response;
		}

		// Only restrict if user is not authenticated.
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$route = $request->get_route();

		// Check if this is a batch endpoint request (/batch/v1 or /batch/v1/...).
		if ( 0 === \strpos( $route, '/batch/v1' ) && ( 9 === \strlen( $route ) || '/' === $route[9] ) ) {
			return new \WP_Error(
				'rest_batch_disabled',
				'Batch requests require authentication.',
				array( 'status' => 403 )
			);
		}

		return $response;
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the rest_pre_dispatch filter signature.
	/**
	 * Rate limit unauthenticated REST API requests
	 *
	 * Implements IP-based rate limiting for unauthenticated users to prevent
	 * abuse and enumeration attacks via the REST API.
	 *
	 * @since 1.5.0
	 * @param mixed            $response Response (could be WP_Error, WP_REST_Response, or pre-response).
	 * @param \WP_REST_Server  $server   REST server instance.
	 * @param \WP_REST_Request $request  REST request object.
	 * @return mixed Original response or error
	 */
	public function rate_limit_rest_api( $response, \WP_REST_Server $server, \WP_REST_Request $request ) {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// Preserve any pre-existing error responses from earlier filters.
		if ( \is_wp_error( $response ) ) {
			return $response;
		}

		// Only apply rate limiting to unauthenticated requests.
		if ( \is_user_logged_in() ) {
			return $response;
		}

		$client_ip = $this->get_client_ip();
		if ( empty( $client_ip ) ) {
			return $response;
		}

		// Fixed-window rate limiting with two transients per client:
		// - $window_key stores the window start timestamp (also acts as the claim lock).
		// - $count_key  stores the request counter, incremented atomically.
		$window_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_window', $client_ip );
		$count_key  = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', $client_ip );

		$current_time  = \time();
		$request_count = $this->atomic_increment( $window_key, $count_key, $current_time );

		// Return 429 if limit exceeded.
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
	 * Delegates to `SecurityHelper::increment_rate_window()`, shared with the GraphQL limiter.
	 *
	 * @since 1.5.0
	 * @param string $window_key   Transient key for the window start timestamp.
	 * @param string $count_key    Transient key for the request counter.
	 * @param int    $current_time Current Unix timestamp.
	 * @return int Request count for this window (>= 1).
	 */
	private function atomic_increment( string $window_key, string $count_key, int $current_time ): int {
		return SecurityHelper::increment_rate_window( $window_key, $count_key, $current_time, $this->rate_limit_window );
	}

	/**
	 * Get client IP address
	 *
	 * Delegates to the single implementation in `SecurityHelper::get_client_ip()`, which honors
	 * `X-Forwarded-For` only from trusted proxies (`SILVER_ASSIST_TRUSTED_PROXY_CIDRS` or the
	 * filter of the same name; internal load balancers when none are declared).
	 *
	 * @since 1.5.0
	 * @since 1.5.4 Delegates to `SecurityHelper::get_client_ip()`.
	 * @return string Client IP address or empty string if it cannot be determined
	 */
	private function get_client_ip(): string {
		$client_ip = SecurityHelper::get_client_ip();

		return '0.0.0.0' === $client_ip ? '' : $client_ip;
	}
}
