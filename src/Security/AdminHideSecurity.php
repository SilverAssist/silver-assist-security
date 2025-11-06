<?php
/**
 * Silver Assist Security Essentials - Admin Hide Security
 *
 * Hides WordPress admin and login pages from unauthorized users by implementing
 * custom URL rewriting and 404 responses for default admin paths.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.4
 * @author Silver Assist
 * @version 1.1.15
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\SecurityHelper;

// Prevent direct access
defined( 'ABSPATH' ) || exit;

/**
 * Class AdminHideSecurity
 *
 * Implements admin hiding functionality to protect WordPress admin area
 * from unauthorized access by redirecting to 404 for unknown users.
 *
 * @since 1.1.4
 */
class AdminHideSecurity {

	/**
	 * Whether admin hiding is enabled
	 *
	 * @var bool
	 */
	private bool $admin_hide_enabled;

	/**
	 * Custom admin path (without leading/trailing slashes)
	 *
	 * @var string
	 */
	private string $custom_admin_path;

	/**
	 * Query string parameter for validation
	 *
	 * @var string
	 */
	private string $validation_param;

	/**
	 * Constructor
	 *
	 * @since 1.1.4
	 */
	public function __construct() {
		$this->init_configuration();
		$this->init();
	}

	/**
	 * Initialize configuration from WordPress options
	 *
	 * @since 1.1.4
	 * @return void
	 */
	private function init_configuration(): void {
		// Check for emergency disable constant first - this overrides all database settings
		// Users can add define('SILVER_ASSIST_HIDE_ADMIN', false); to wp-config.php
		// to regain admin access if they forget their custom admin path
		if ( \defined( 'SILVER_ASSIST_HIDE_ADMIN' ) && SILVER_ASSIST_HIDE_ADMIN === false ) {
			$this->admin_hide_enabled = false;
			$this->custom_admin_path  = 'silver-admin';
			$this->validation_param   = 'silver_auth';
			return;
		}

		$this->admin_hide_enabled = (bool) DefaultConfig::get_option( 'silver_assist_admin_hide_enabled' );
		$this->custom_admin_path  = \sanitize_title( DefaultConfig::get_option( 'silver_assist_admin_hide_path' ) );
		$this->validation_param   = 'silver_auth';

		// Validate custom path using centralized validator
		if ( empty( $this->custom_admin_path ) || PathValidator::is_forbidden_path( $this->custom_admin_path ) ) {
			$this->custom_admin_path = 'silver-admin';
		}
	}

	/**
	 * Initialize hooks and filters
	 *
	 * @since 1.1.4
	 * @return void
	 */
	private function init(): void {
		if ( ! $this->admin_hide_enabled ) {
			return;
		}

		// Handle requests using setup_theme like professional plugin
		\add_action( 'setup_theme', array( $this, 'handle_specific_page_requests' ) );

		// Filter generated URLs to include access tokens
		\add_filter( 'site_url', array( $this, 'filter_generated_url' ), 100, 2 );
		\add_filter( 'admin_url', array( $this, 'filter_admin_url' ), 100, 2 );
		\add_filter( 'wp_redirect', array( $this, 'filter_redirect' ) );
		\add_filter( 'logout_redirect', array( $this, 'handle_logout_redirect' ), 10, 3 );

		// Remove WordPress default admin redirect behavior
		\remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Handle wp-login.php page access specifically
	 *
	 * @since 1.1.4
	 * @return void
	 */
	public function handle_login_page_access(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login page access check, no form submission.
		$action = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';

		// Allow specific actions that should work without admin hide protection.
		$allowed_actions = DefaultConfig::get_legitimate_actions( true ); // Include logout.

		if ( in_array( $action, $allowed_actions, true ) ) {
			return;
		}

		// Block access if not validated
		$this->block_access( 'login' );
	}

	/**
	 * Handle wp-admin page access specifically
	 *
	 * @since 1.1.4
	 * @return void
	 */
	public function handle_admin_page_access(): void {
		$this->block_access( 'login' );
	}

	/**
	 * Handle custom admin path requests
	 *
	 * @since 1.1.4
	 * @return void
	 */
	public function handle_custom_admin_requests(): void {
		// Skip if doing cron or AJAX
		if ( \wp_doing_cron() || \wp_doing_ajax() ) {
			return;
		}

		$request_path = $this->get_request_path();

		// Check if this is our custom admin path
		$clean_custom_path  = ltrim( $this->custom_admin_path, '/' );
		$clean_request_path = ltrim( $request_path, '/' );

		if ( $clean_request_path === $clean_custom_path ) {
			$this->handle_custom_admin_access();
		}
	}

	/**
	 * Handle specific page requests early in WordPress lifecycle
	 *
	 * @since 1.1.4
	 * @return void
	 */
	public function handle_specific_page_requests(): void {
		// Double-check if admin hiding is enabled
		if ( ! $this->admin_hide_enabled ) {
			return;
		}

		// Skip if doing cron or AJAX
		if ( \wp_doing_cron() || \wp_doing_ajax() ) {
			return;
		}

		$request_path = $this->get_request_path();

		if ( strpos( $request_path, '/' ) !== false ) {
			[$request_path] = explode( '/', $request_path );
		}

		$this->handle_request_path( $request_path );
	}
	/**
	 * Get the current request path
	 *
	 * @since 1.1.4
	 * @return string The request path
	 */
	private function get_request_path(): string {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// Parse just the path part, removing query parameters.
		$path = \wp_parse_url( $request_uri, PHP_URL_PATH );

		// Remove WordPress home path from the beginning if present.
		$home_root = \wp_parse_url( \home_url(), PHP_URL_PATH );
		if ( $home_root === null || $home_root === false ) {
			$home_root = '/';
		}
		if ( $home_root !== '/' && is_string( $path ) && strpos( $path, $home_root ) === 0 ) {
			$path = substr( $path, strlen( $home_root ) );
		}

		// Clean leading/trailing slashes.
		$cleaned_path = is_string( $path ) ? trim( $path, '/' ) : '';

		return $cleaned_path;
	}

	/**
	 * Handle determining if we need to block or redirect the request path
	 *
	 * @since 1.1.4
	 * @param string $request_path The request path to handle
	 * @return void
	 */
	private function handle_request_path( string $request_path ): void {
		// Check custom admin path - remove leading slash if present
		$clean_custom_path  = ltrim( $this->custom_admin_path, '/' );
		$clean_request_path = ltrim( $request_path, '/' );

		if ( $clean_request_path === $clean_custom_path ) {
			$this->handle_custom_admin_access();
		} elseif (
			in_array( $clean_request_path, array( 'wp-login.php', 'wp-login' ), true ) ||
			strpos( $clean_request_path, 'wp-login.php' ) !== false
		) {
			$this->handle_login_page_access();
		} elseif (
			$clean_request_path === 'wp-admin' || strpos( $clean_request_path, 'wp-admin/' ) === 0 ||
			strpos( $clean_request_path, 'wp-admin' ) === 0
		) {
			$this->handle_wp_admin_page();
		}
	}

	/**
	 * Handle request for custom admin path
	 *
	 * @since 1.1.4
	 * @return void
	 */
	private function handle_custom_admin_access(): void {
		// If user is already logged in, redirect to admin.
		if ( \is_user_logged_in() && \current_user_can( 'manage_options' ) ) {
			\wp_safe_redirect( \admin_url() );
			exit;
		}

		// Redirect to login with token
		$this->do_redirect_with_token( 'login', 'wp-login.php' );
	}

	/**
	 * Handle request for wp-admin pages
	 *
	 * @since 1.1.4
	 * @return void
	 */
	private function handle_wp_admin_page(): void {
		$this->block_access( 'login' );
	}

	/**
	 * Block access if user is not logged in and request is not validated
	 *
	 * @since 1.1.4
	 * @param string $type The type of access being blocked
	 * @return void
	 */
	private function block_access( string $type = 'login' ): void {
		if ( \is_user_logged_in() ) {
			return;
		}

		if ( $this->is_validated( $type ) ) {
			return;
		}

		// Send 404 response
		$this->send_404_response();
	}

	/**
	 * Add or update auth token in URL query parameters
	 *
	 * @since 1.1.4
	 * @param array|string $source_params Source parameters (array from $_GET or query string from URL)
	 * @param string       $token The token to add
	 * @return array Clean query variables array with token
	 */
	private function build_query_with_token( $source_params, string $token ): array {
		$query_vars = array();

		if ( is_array( $source_params ) ) {
			// Source is $_GET array
			$query_vars = $source_params;
		} elseif ( is_string( $source_params ) && ! empty( $source_params ) ) {
			// Source is query string from URL
			parse_str( $source_params, $query_vars );
		}

		// Remove existing auth token to prevent duplicates
		unset( $query_vars[ $this->validation_param ] );

		// Add the new token
		$query_vars[ $this->validation_param ] = $token;

		return $query_vars;
	}

	/**
	 * Redirect with token to ensure access is validated
	 *
	 * @since 1.1.4
	 * @param string $type The type of access token needed
	 * @param string $path The path to redirect to
	 * @return void
	 */
	private function do_redirect_with_token( string $type, string $path ): void {
		// Set cookie for future requests
		$this->set_access_cookie( $type );

		// Build clean query parameters with token
		$token = $this->get_access_token( $type );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Using custom token validation system.
		$query_vars = $this->build_query_with_token( $_GET, $token );
		$query      = http_build_query( $query_vars, '', '&' );

		// Build redirect URL
		$url = \site_url( $path . ( strpos( $path, '?' ) === false ? '?' : '&' ) . $query );

		\wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Filter generated URLs to add access tokens
	 *
	 * @since 1.1.4
	 * @param string $url The complete URL
	 * @param string $path The path submitted by the originating function
	 * @return string The URL with conditionally added access token
	 */
	public function filter_generated_url( string $url, string $path ): string {
		// Double-check if admin hiding is enabled
		if ( ! $this->admin_hide_enabled ) {
			return $url;
		}

		[$clean_path] = explode( '?', $path );

		if ( $clean_path === 'wp-login.php' ) {
			// List of actions that should not get access tokens (they need to work normally)
			$allowed_actions = DefaultConfig::get_admin_hide_bypass_actions(); // Exclude logout for URL tokens

			// Check if this path contains any of the allowed actions
			foreach ( $allowed_actions as $action ) {
				if ( strpos( $path, "action={$action}" ) !== false ) {
					return $url; // Don't add tokens to these actions
				}
			}

			// Special handling for registration
			$url = $this->add_token_to_url( $url, strpos( $path, 'action=register' ) !== false ? 'register' : 'login' );
		}

		return $url;
	}

	/**
	 * Filter admin URLs to include tokens when necessary
	 *
	 * @since 1.1.4
	 * @param string $url Complete admin URL
	 * @param string $path Path passed to admin_url function
	 * @return string Modified URL
	 */
	public function filter_admin_url( string $url, string $path ): string {
		// Double-check if admin hiding is enabled
		if ( ! $this->admin_hide_enabled ) {
			return $url;
		}

		// Add token to profile update URLs
		if ( strpos( $path, 'profile.php?newuseremail=' ) === 0 ) {
			$url = $this->add_token_to_url( $url, 'login' );
		}

		return $url;
	}

	/**
	 * Filter redirect URLs to include access tokens
	 *
	 * @since 1.1.4
	 * @param string $location The redirect location
	 * @return string Modified location with access token
	 */
	public function filter_redirect( string $location ): string {
		// Double-check if admin hiding is enabled
		if ( ! $this->admin_hide_enabled ) {
			return $location;
		}

		return $this->filter_generated_url( $location, $location );
	}

	/**
	 * Add access token to URL
	 *
	 * @since 1.1.4
	 * @param string $url The URL to modify
	 * @param string $type The type of access token
	 * @return string Modified URL with token
	 */
	private function add_token_to_url( string $url, string $type ): string {
		$token = $this->get_access_token( $type );

		// Parse URL to handle existing parameters properly
		$parsed_url = \wp_parse_url( $url );
		if ( ! is_array( $parsed_url ) || ! isset( $parsed_url['scheme'], $parsed_url['host'] ) ) {
			return $url; // Return original URL if parsing fails
		}

		// Build clean query parameters with token using unified method
		$query_vars = $this->build_query_with_token( $parsed_url['query'] ?? '', $token );

		// Build the clean URL
		$base_url = $parsed_url['scheme'] . '://' . $parsed_url['host'];
		if ( ! empty( $parsed_url['port'] ) ) {
			$base_url .= ':' . $parsed_url['port'];
		}
		if ( ! empty( $parsed_url['path'] ) ) {
			$base_url .= $parsed_url['path'];
		}

		// Add query parameters
		$query_string = http_build_query( $query_vars, '', '&' );
		$final_url    = "{$base_url}?{$query_string}";

		return $final_url;
	}

	/**
	 * Check if current request is validated
	 *
	 * @since 1.1.4
	 * @param string $type The type of validation to check
	 * @return bool True if validated
	 */
	private function is_validated( string $type ): bool {
		$token = $this->get_access_token( $type );

		// Check query parameter
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Using custom token validation system.
		if ( isset( $_REQUEST[ $this->validation_param ] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Using custom token validation system.
			$received_token = \sanitize_text_field( \wp_unslash( $_REQUEST[ $this->validation_param ] ) );
			if ( $received_token === $token ) {
				$this->set_access_cookie( $type );
				return true;
			}
		}

		// Check cookie
		$cookie_hash = defined( 'COOKIEHASH' ) ? COOKIEHASH : \md5( \site_url() );
		$cookie_name = "silver_admin_session_{$type}_{$cookie_hash}";
		if ( isset( $_COOKIE[ $cookie_name ] ) ) {
			$cookie_token = \sanitize_text_field( \wp_unslash( $_COOKIE[ $cookie_name ] ) );
			if ( $cookie_token === $token ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get access token for type
	 *
	 * @since 1.1.4
	 * @param string $type The type of access token
	 * @return string The access token
	 */
	private function get_access_token( string $type ): string {
		if ( $type === 'login' ) {
			return $this->custom_admin_path;
		}

		return $this->custom_admin_path;
	}

	/**
	 * Set access cookie
	 *
	 * @since 1.1.4
	 * @param string $type The type of access cookie
	 * @param int    $duration Cookie duration in seconds
	 * @return void
	 */
	private function set_access_cookie( string $type, int $duration = 3600 ): void {
		$expires      = time() + $duration;
		$cookie_hash  = defined( 'COOKIEHASH' ) ? COOKIEHASH : \md5( \site_url() );
		$cookie_name  = "silver_admin_session_{$type}_{$cookie_hash}";
		$cookie_value = $this->get_access_token( $type );

		$home_root = \wp_parse_url( \home_url(), PHP_URL_PATH );
		if ( $home_root === null || $home_root === false ) {
			$home_root = '/';
		}
		$cookie_domain = defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '';

		\setcookie(
			$cookie_name,
			$cookie_value,
			$expires,
			$home_root,
			$cookie_domain,
			\is_ssl(),
			true
		);
	}

	/**
	 * Handle logout redirect to include auth token
	 *
	 * @since 1.1.4
	 * @param string $redirect_to The redirect destination URL
	 * @param string $requested_redirect_to The requested redirect destination URL
	 * @param mixed  $user The user object
	 * @return string Modified redirect URL
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Parameters required by WordPress hook.
	public function handle_logout_redirect( string $redirect_to, string $requested_redirect_to, $user ): string {
		// Double-check if admin hiding is enabled
		if ( ! $this->admin_hide_enabled ) {
			return $redirect_to;
		}

		// Generate validation token for the logout redirect
		$validation_token = $this->get_access_token( 'login' );

		// If redirecting to wp-login.php, add our auth token
		if ( strpos( $redirect_to, '/wp-login.php' ) !== false ) {
			// Manually add the query parameter
			$separator   = strpos( $redirect_to, '?' ) !== false ? '&' : '?';
			$redirect_to = $redirect_to . $separator . $this->validation_param . '=' . rawurlencode( $validation_token );
		}

		return $redirect_to;
	}

	/**
	 * Send 404 response and exit
	 *
	 * @since 1.1.4
	 * @return void
	 */
	private function send_404_response(): void {
		SecurityHelper::send_404_response();
	}

	/**
	 * Get current custom admin path
	 *
	 * @since 1.1.4
	 * @return string The custom admin path
	 */
	public function get_custom_admin_path(): string {
		return $this->custom_admin_path;
	}

	/**
	 * Get admin hide status
	 *
	 * @since 1.1.4
	 * @return bool True if admin hiding is enabled
	 */
	public function is_admin_hide_enabled(): bool {
		return $this->admin_hide_enabled;
	}

	/**
	 * Get forbidden paths list
	 *
	 * @since 1.1.4
	 * @return array List of forbidden paths
	 */
	public function get_forbidden_paths(): array {
		return PathValidator::get_forbidden_paths();
	}

	/**
	 * Validate custom admin path
	 *
	 * @since 1.1.4
	 * @param string $path The path to validate
	 * @return bool True if path is valid
	 */
	public function validate_custom_path( string $path ): bool {
		$result = PathValidator::validate_admin_path( $path );
		return $result['is_valid'];
	}
}
