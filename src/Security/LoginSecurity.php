<?php
/**
 * Silver Assist Security Essentials - Login Security Protection
 *
 * Implements comprehensive login security including failed attempt tracking,
 * IP-based lockouts, session timeout management, and password strength enforcement.
 * Provides protection against brute force attacks and unauthorized access.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.14
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Login Security class
 *
 * Handles login attempt limiting, lockouts, and login form security
 *
 * @since 1.1.1
 */
class LoginSecurity {


	/**
	 * Maximum login attempts
	 *
	 * @var int
	 */
	private int $max_attempts;

	/**
	 * Lockout duration in seconds
	 *
	 * @var int
	 */
	private int $lockout_duration;

	/**
	 * Session timeout in minutes
	 *
	 * @var int
	 */
	private int $session_timeout;

	/**
	 * Plugin version for cache busting
	 *
	 * @var string
	 */
	private string $plugin_version;

	/**
	 * Constructor
	 *
	 * @since 1.1.1
	 */
	public function __construct() {
		$this->plugin_version = SILVER_ASSIST_SECURITY_VERSION;
		$this->init_configuration();
		$this->init();
	}

	/**
	 * Initialize configuration
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init_configuration(): void {
		$this->max_attempts     = (int) DefaultConfig::get_option( 'silver_assist_login_attempts' );
		$this->lockout_duration = (int) DefaultConfig::get_option( 'silver_assist_lockout_duration' );
		$this->session_timeout  = (int) DefaultConfig::get_option( 'silver_assist_session_timeout' );
	}

	/**
	 * Initialize login security
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init(): void {
		// Login form hooks
		\add_action( 'login_form', [ $this, 'add_login_form_security' ] );
		\add_action( 'login_init', [ $this, 'setup_login_protection' ] );

		// Bot and crawler protection
		\add_action( 'login_init', [ $this, 'block_suspicious_bots' ], 5 );
		\add_action( 'wp_login_failed', [ $this, 'track_bot_behavior' ] );

		// Login attempt tracking
		\add_action( 'wp_login_failed', [ $this, 'handle_failed_login' ] );
		\add_filter( 'authenticate', [ $this, 'check_login_lockout' ], 30, 3 );
		\add_action( 'wp_login', [ $this, 'handle_successful_login' ], 10, 2 );

		// Session management
		\add_action( 'init', [ $this, 'setup_session_timeout' ] );
		\add_action( 'wp_logout', [ $this, 'clear_login_attempts' ] );

		// Clear login attempts after successful password changes
		\add_action( 'password_reset', [ $this, 'clear_login_attempts_on_password_change' ], 10, 2 );
		\add_action( 'profile_update', [ $this, 'clear_login_attempts_on_profile_update' ], 10, 2 );

		// Password reset security
		$this->init_password_security();

		// Add password strength JavaScript for live validation
		\add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_password_scripts' ] );
	}

	/**
	 * Enqueue password strength scripts for live validation
	 *
	 * @since 1.1.5
	 * @param string $hook_suffix Current admin page hook suffix
	 * @return void
	 */
	public function enqueue_password_scripts( string $hook_suffix ): void {
		// Only load on user profile pages
		if ( ! in_array( $hook_suffix, [ 'profile.php', 'user-edit.php', 'user-new.php' ], true ) ) {
			return;
		}

		// Check if password strength enforcement is enabled
		if ( ! DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' ) ) {
			return;
		}

		// Enqueue WordPress password strength meter
		\wp_enqueue_script( 'password-strength-meter' );

		// Enqueue CSS variables
		\wp_enqueue_style(
			'silver-assist-variables',
			$this->get_asset_url( 'assets/css/variables.css' ),
			[],
			$this->plugin_version
		);

		// Enqueue custom password validation styles
		\wp_enqueue_style(
			'silver-assist-password-validation',
			$this->get_asset_url( 'assets/css/password-validation.css' ),
			[ 'silver-assist-variables' ],
			$this->plugin_version
		);

		// Enqueue custom password validation script
		\wp_enqueue_script(
			'silver-assist-password-validation',
			$this->get_asset_url( 'assets/js/password-validation.js' ),
			[ 'jquery', 'password-strength-meter' ],
			$this->plugin_version,
			true
		);

		// Localize script with translated error message
		\wp_localize_script(
			'silver-assist-password-validation',
			'silverAssistSecurity',
			[
				'passwordError'        => \__( 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.', 'silver-assist-security' ),
				'passwordSuccess'      => \__( 'Password meets security requirements', 'silver-assist-security' ),
				'hideWeakConfirmation' => true, // Flag to indicate weak password confirmation should be hidden
			]
		);
	}

	/**
	 * Get asset URL with minification support
	 *
	 * Returns minified version when SCRIPT_DEBUG is not true, regular version otherwise.
	 *
	 * @since 1.1.10
	 * @param string $asset_path The relative path to the asset (e.g., 'assets/css/password-validation.css')
	 * @return string The full URL to the asset
	 */
	private function get_asset_url( string $asset_path ): string {
		return SecurityHelper::get_asset_url( $asset_path );
	}

	/**
	 * Initialize password security features
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init_password_security(): void {
		$password_strength_enforcement = DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' );

		if ( $password_strength_enforcement ) {
			\add_action( 'user_profile_update_errors', [ $this, 'validate_password_strength' ], 10, 3 );
			\add_action( 'validate_password_reset', [ $this, 'validate_password_strength_reset' ], 10, 2 );
		}
	}

	/**
	 * Add security fields to login form
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function add_login_form_security(): void {
		// Add nonce field
		\wp_nonce_field( 'secure_login_action', 'secure_login_nonce' );

		// Add honeypot field (hidden from users)
		echo '<p style="position: absolute; left: -9999px;">';
		echo '<label for="website_url">' . esc_html( \__( 'Website URL (leave blank):', 'silver-assist-security' ) ) . '</label>';
		echo '<input type="text" name="website_url" id="website_url" value="" tabindex="-1" autocomplete="off" />';
		echo '</p>';
	}

	/**
	 * Setup login protection
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function setup_login_protection(): void {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			return;
		}

		// Check honeypot
		if ( isset( $_POST['website_url'] ) && ! empty( $_POST['website_url'] ) ) {
			\wp_die( esc_html( \__( 'Security check failed.', 'silver-assist-security' ) ) );
		}

		// Verify nonce
		if ( isset( $_POST['log'] ) && function_exists( 'wp_verify_nonce' ) ) {
			$nonce = isset( $_POST['secure_login_nonce'] ) ? \sanitize_text_field( \wp_unslash( $_POST['secure_login_nonce'] ) ) : '';
			if ( ! \wp_verify_nonce( $nonce, 'secure_login_action' ) ) {
				SecurityHelper::log_security_event( 'NONCE_VERIFICATION_FAILED', 'Nonce verification failed for login attempt', [] );
			}
		}
	}

	/**
	 * Handle failed login attempt
	 *
	 * @since 1.1.1
	 * @param string $username Username that failed login
	 * @return void
	 */
	public function handle_failed_login( string $username ): void {
		$ip  = SecurityHelper::get_client_ip();
		$key = SecurityHelper::generate_ip_transient_key( 'login_attempts', $ip );

		$attempts = \get_transient( $key );
		if ( $attempts === false ) {
			$attempts = 0;
		}
		++$attempts;

		\set_transient( $key, $attempts, $this->lockout_duration );

		if ( $attempts >= $this->max_attempts ) {
			// Log the lockout using centralized security logging
			SecurityHelper::log_security_event(
				'LOGIN_LOCKOUT',
				"IP locked out after {$attempts} failed login attempts",
				[
					'username'         => $username,
					'attempts'         => $attempts,
					'max_attempts'     => $this->max_attempts,
					'lockout_duration' => $this->lockout_duration,
				]
			);

			// Set lockout flag
			$lockout_key = SecurityHelper::generate_ip_transient_key( 'lockout', $ip );
			\set_transient( $lockout_key, true, $this->lockout_duration );
		}
	}

	/**
	 * Check if user is locked out
	 *
	 * @since 1.1.1
	 * @param \WP_User|\WP_Error|null $user User object or error
	 * @param string                  $username Username
	 * @param string                  $password Password
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_login_lockout( $user, string $username, string $password ) {
		// Skip if no username/password provided
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$ip           = SecurityHelper::get_client_ip();
		$lockout_key  = SecurityHelper::generate_ip_transient_key( 'lockout', $ip );
		$attempts_key = SecurityHelper::generate_ip_transient_key( 'login_attempts', $ip );

		// Check if IP is locked out
		if ( \get_transient( $lockout_key ) ) {
			$attempts = \get_transient( $attempts_key );
			if ( $attempts === false ) {
				$attempts = 0;
			}
			$remaining_time = $this->get_remaining_lockout_time( $lockout_key );

			return new \WP_Error(
				'login_locked',
				sprintf(
					/* translators: %d: number of minutes remaining until unlock */
					\__( 'Too many failed login attempts. Try again in %d minutes.', 'silver-assist-security' ),
					ceil( $remaining_time / 60 )
				)
			);
		}

		return $user;
	}

	/**
	 * Handle successful login
	 *
	 * @since 1.1.1
	 * @param string   $user_login Username
	 * @param \WP_User $user User object
	 * @return void
	 */
	public function handle_successful_login( string $user_login, \WP_User $user ): void {
		// Clear login attempts on successful login
		$this->clear_login_attempts();

		// Clear any previous session metadata to prevent login loops
		\delete_user_meta( $user->ID, 'last_activity' );

		// Set fresh session timeout for new login session
		$this->set_session_timeout();
	}

	/**
	 * Setup session timeout
	 *
	 * Manages automatic logout when session timeout is exceeded. Behavior differs
	 * between admin and frontend:
	 * - Admin area: Logs out and redirects to login with session_expired=1
	 * - Frontend: Silently logs out without redirect to preserve user experience
	 *
	 * @since 1.1.1
	 * @updated 1.1.10 Added frontend/admin differentiation
	 * @return void
	 */
	public function setup_session_timeout(): void {
		if ( ! \is_user_logged_in() ) {
			return;
		}

		$user_id       = \get_current_user_id();
		$last_activity = \get_user_meta( $user_id, 'last_activity', true );
		$timeout       = $this->session_timeout * 60; // Convert to seconds

		// Skip timeout check if we're in the login process or just logged in
		if ( $this->is_in_login_process() ) {
			// Initialize/update last activity for new session
			\update_user_meta( $user_id, 'last_activity', time() );
			return;
		}

		// Only check timeout if last_activity exists and is not empty
		// This prevents logout during plugin activation when last_activity hasn't been set yet
		if ( $last_activity && is_numeric( $last_activity ) && (int) $last_activity > 0 ) {
			$time_since_last_activity = time() - (int) $last_activity;

			// Only logout if timeout exceeded and not in admin area during plugin management
			if (
				$time_since_last_activity > $timeout &&
				( ! \is_admin() ||
					// phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- Checking plugin management context, not processing form data.
					( ! \current_user_can( 'activate_plugins' ) && ! isset( $_GET['page'] ) && ! isset( $_POST['action'] ) ) )
			) {
				// Clear session metadata before logout to prevent loops
				\delete_user_meta( $user_id, 'last_activity' );
				\wp_logout();

				// Only redirect to login if user is in admin area
				// Frontend users should stay on their current page after silent logout
				if ( \is_admin() ) {
					\wp_safe_redirect( \wp_login_url() . '?session_expired=1' );
					exit;
				}
				// For frontend, just return without redirect to allow normal page rendering
				return;
			}
		}

		// Always update last activity for logged-in users
		\update_user_meta( $user_id, 'last_activity', time() );
	}

	/**
	 * Check if we're currently in a login process
	 *
	 * @since 1.1.8
	 * @return bool True if in login process
	 */
	private function is_in_login_process(): bool {
		global $pagenow;

		// Check if we're on wp-login.php
		if ( $pagenow === 'wp-login.php' ) {
			return true;
		}

		// Check if this is a login POST request
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checking if this is a login request context, not processing form data.
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset( $_POST['log'] ) ) {
			return true;
		}

		// Check if this is immediately after login (within 30 seconds)
		$user_id    = \get_current_user_id();
		$last_login = \get_user_meta( $user_id, 'session_tokens', true );
		if ( is_array( $last_login ) ) {
			$most_recent_token = end( $last_login );
			if ( isset( $most_recent_token['login'] ) && ( time() - $most_recent_token['login'] ) < 30 ) {
				return true;
			}
		}

		// Check for specific login-related actions
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking action type, not processing form data.
		$action        = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';
		$login_actions = [ 'login', 'logout', 'register', 'resetpass', 'rp', 'lostpassword' ];
		if ( in_array( $action, $login_actions, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Set session timeout
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function set_session_timeout(): void {
		if ( \is_user_logged_in() ) {
			\update_user_meta( \get_current_user_id(), 'last_activity', time() );
		}
	}

	/**
	 * Clear login attempts for current IP
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function clear_login_attempts(): void {
		$ip           = SecurityHelper::get_client_ip();
		$attempts_key = SecurityHelper::generate_ip_transient_key( 'login_attempts', $ip );
		$lockout_key  = SecurityHelper::generate_ip_transient_key( 'lockout', $ip );

		\delete_transient( $attempts_key );
		\delete_transient( $lockout_key );
	}

	/**
	 * Clear login attempts after successful password reset
	 *
	 * @since 1.1.9
	 * @param \WP_User $user User object
	 * @param string   $new_pass New password
	 * @return void
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	public function clear_login_attempts_on_password_change( \WP_User $user, string $new_pass ): void {
		// Clear any existing login attempts for the current IP
		$this->clear_login_attempts();

		SecurityHelper::log_security_event(
			'LOGIN_ATTEMPTS_CLEARED',
			sprintf( 'Login attempts cleared after password reset for user: %s', $user->user_login ),
			[ 'user_login' => $user->user_login ]
		);
	}

	/**
	 * Clear login attempts after profile update (includes password changes from admin)
	 *
	 * @since 1.1.9
	 * @param int      $user_id User ID
	 * @param \WP_User $old_user_data Old user data before update
	 * @return void
	 */
	public function clear_login_attempts_on_profile_update( int $user_id, \WP_User $old_user_data ): void {
		// Only clear if password was actually changed
		$new_user = \get_userdata( $user_id );
		if ( $new_user && $new_user->user_pass !== $old_user_data->user_pass ) {
			// Clear any existing login attempts for the current IP
			$this->clear_login_attempts();

			SecurityHelper::log_security_event(
				'LOGIN_ATTEMPTS_CLEARED',
				sprintf( 'Login attempts cleared after profile password change for user: %s', $new_user->user_login ),
				[ 'user_login' => $new_user->user_login ]
			);
		}
	}

	/**
	 * Validate password strength
	 *
	 * @since 1.1.1
	 * @param \WP_Error          $errors Errors object
	 * @param bool               $update Whether this is a user update
	 * @param \stdClass|\WP_User $user User object (stdClass for new users, WP_User for updates)
	 * @return void
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	public function validate_password_strength( \WP_Error $errors, bool $update, \stdClass|\WP_User $user ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress handles nonce verification for user profile updates.
		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WordPress handles nonce verification for user profile updates.
			$password = \sanitize_text_field( \wp_unslash( $_POST['pass1'] ) );

			if ( ! $this->is_strong_password( $password ) ) {
				$errors->add(
					'weak_password',
					\__( 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.', 'silver-assist-security' )
				);
			}
		}
	}

	/**
	 * Validate password strength on reset
	 *
	 * @since 1.1.1
	 * @param \WP_Error          $errors Errors object
	 * @param \stdClass|\WP_User $user User object (can be stdClass or WP_User depending on context)
	 * @return void
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	public function validate_password_strength_reset( \WP_Error $errors, \stdClass|\WP_User $user ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress handles nonce verification for password reset forms.
		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WordPress handles nonce verification for password reset forms.
			$password = \sanitize_text_field( \wp_unslash( $_POST['pass1'] ) );

			if ( ! $this->is_strong_password( $password ) ) {
				$errors->add(
					'weak_password',
					\__( 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.', 'silver-assist-security' )
				);
			}
		}
	}

	/**
	 * Check if password is strong
	 *
	 * @since 1.1.1
	 * @param string $password Password to check
	 * @return bool
	 */
	private function is_strong_password( string $password ): bool {
		return SecurityHelper::is_strong_password( $password );
	}

	/**
	 * Get client IP address
	 *
	 * @since 1.1.1
	 * @return string
	 */
	private function get_client_ip(): string {
		return SecurityHelper::get_client_ip();
	}

	/**
	 * Get remaining lockout time
	 *
	 * @since 1.1.1
	 * @param string $lockout_key Lockout transient key
	 * @return int Remaining time in seconds
	 */
	private function get_remaining_lockout_time( string $lockout_key ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct query needed for transient timeout value.
		$transient_timeout = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				"_transient_timeout_{$lockout_key}"
			)
		);

		if ( $transient_timeout ) {
			return (int) max( 0, $transient_timeout - time() );
		}

		return 0;
	}

	/**
	 * Block suspicious bots and crawlers from accessing login page
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function block_suspicious_bots(): void {
		// Check if bot protection is enabled
		$bot_protection_enabled = DefaultConfig::get_option( 'silver_assist_bot_protection' );
		if ( ! $bot_protection_enabled ) {
			return;
		}

		// Skip bot protection for logged-in users
		if ( \is_user_logged_in() ) {
			return;
		}

		// Skip bot protection for legitimate WordPress actions
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking action type for bot detection, not processing form data.
		$action             = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';
		$legitimate_actions = DefaultConfig::get_bot_protection_bypass_actions();

		if ( in_array( $action, $legitimate_actions, true ) ) {
			return;
		}

		// Skip if this is a password reset confirmation (has key parameter)
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking password reset context, not processing form data.
		if ( isset( $_GET['key'] ) && isset( $_GET['login'] ) ) {
			return;
		}

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$ip         = $this->get_client_ip();

		// List of known bot/crawler patterns
		$bot_patterns = [
			'bot',
			'crawler',
			'spider',
			'scraper',
			'scan',
			'probe',
			'wget',
			'curl',
			'python',
			'php',
			'perl',
			'java',
			'masscan',
			'nmap',
			'nikto',
			'sqlmap',
			'gobuster',
			'dirb',
			'dirbuster',
			'wpscan',
			'nuclei',
			'httpx',
		];

		// Check if user agent matches bot patterns
		$is_bot = false;
		foreach ( $bot_patterns as $pattern ) {
			if ( stripos( $user_agent, $pattern ) !== false ) {
				$is_bot = true;
				break;
			}
		}

		// Additional checks for suspicious behavior (but more lenient for users)
		if ( ! $is_bot ) {
			// Check for empty or very short user agents (common in bots)
			if ( empty( $user_agent ) || strlen( $user_agent ) < 10 ) {
				$is_bot = true;
			}

			// Check for missing common browser headers (but be more lenient)
			if ( ! isset( $_SERVER['HTTP_ACCEPT'] ) && ! isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) && ! isset( $_SERVER['HTTP_ACCEPT_ENCODING'] ) ) {
				$is_bot = true;
			}

			// More lenient rate limiting - allow more requests for legitimate users
			$access_key    = "login_access_{md5($ip)}";
			$recent_access = \get_transient( $access_key );
			if ( $recent_access === false ) {
				$recent_access = 0;
			}

			// Increase threshold to 15 requests per minute (was 5) to accommodate:
			// - Password changes with redirects
			// - Logout confirmations
			// - Multiple login attempts by legitimate users
			if ( $recent_access > 15 ) {
				$is_bot = true;
			}

			// Update rate limiting counter (more lenient)
			\set_transient( $access_key, $recent_access + 1, 60 );
		}

		// Only block if definitively identified as bot/crawler
		if ( $is_bot ) {
			$this->track_bot_behavior(); // Use existing method
			$this->send_404_response();
		}
	}

	/**
	 * Track bot behavior for additional security measures
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function track_bot_behavior(): void {
		$ip         = $this->get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown';

		// Log bot activity for security monitoring
		$bot_log_key  = "bot_activity_{md5($ip)}";
		$bot_activity = \get_transient( $bot_log_key );
		if ( $bot_activity === false ) {
			$bot_activity = [];
		}

		$bot_activity[] = [
			'time'       => time(),
			'user_agent' => $user_agent,
			'method'     => isset( $_SERVER['REQUEST_METHOD'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
			'uri'        => isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
		];

		// Keep only last 10 activities
		if ( count( $bot_activity ) > 10 ) {
			$bot_activity = array_slice( $bot_activity, -10 );
		}

		\set_transient( $bot_log_key, $bot_activity, 3600 ); // Store for 1 hour

		// If too many bot activities, extend blocking
		if ( count( $bot_activity ) > 3 ) {
			$extended_block_key = "extended_bot_block_{md5($ip)}";
			\set_transient( $extended_block_key, true, 7200 ); // Block for 2 hours
		}
	}

	/**
	 * Send 404 Not Found response to bots
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function send_404_response(): void {
		// Log the blocked access attempt
		SecurityHelper::log_security_event(
			'BOT_BLOCKED',
			'Bot/crawler blocked from login page',
			[
				'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown',
				'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			]
		);

		// Use centralized 404 response without WordPress template to avoid conflicts
		SecurityHelper::send_404_response( false );
	}
}
