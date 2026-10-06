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
 * @version 1.5.3
 */

namespace SilverAssist\Security\Security;

use SilverAssist\PluginKernel\Interfaces\LoadableInterface;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityEventCounter;
use SilverAssist\Security\Core\SecurityHelper;
use WP_Error;
use WP_User;

/**
 * Login Security class
 *
 * Handles login attempt limiting, lockouts, and login form security
 *
 * @since 1.1.1
 */
class LoginSecurity implements LoadableInterface {

	/**
	 * Minimum seconds between two last_activity writes for one user
	 *
	 * @since 1.5.4
	 */
	private const ACTIVITY_WRITE_INTERVAL = 60;

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

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
	 * first time it constructs this singleton. Declared to satisfy
	 * LoadableInterface without registering every hook a second time when
	 * the plugin kernel calls this after instance().
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
	 * Always loads — matches pre-kernel behavior, where Plugin::init_security_components()
	 * constructed LoginSecurity unconditionally.
	 *
	 * @since 1.5.1
	 * @return bool
	 */
	public function should_load(): bool {
		return true;
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
	 * Register WordPress hooks for login security
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function register_hooks(): void {
		// Login form hooks.
		\add_action( 'login_form', array( $this, 'add_login_form_security' ) );
		\add_action( 'login_init', array( $this, 'setup_login_protection' ) );

		// Bot and crawler protection.
		\add_action( 'login_init', array( $this, 'block_suspicious_bots' ), 5 );

		// Login attempt tracking.
		\add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		\add_filter( 'authenticate', array( $this, 'check_login_lockout' ), 30, 3 );
		\add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );

		// Session management.
		\add_action( 'init', array( $this, 'setup_session_timeout' ) );
		\add_action( 'wp_logout', array( $this, 'clear_login_attempts' ) );

		// Enforce session cookie lifetime and hide "Remember Me" checkbox.
		\add_filter( 'auth_cookie_expiration', array( $this, 'enforce_session_cookie_lifetime' ), 10, 3 );
		\add_action( 'login_enqueue_scripts', array( $this, 'hide_remember_me' ) );

		// Clear login attempts after successful password changes.
		\add_action( 'password_reset', array( $this, 'clear_login_attempts_on_password_change' ), 10, 2 );
		\add_action( 'profile_update', array( $this, 'clear_login_attempts_on_profile_update' ), 10, 2 );

		// Password reset security.
		$this->init_password_security();

		// Add password strength JavaScript for live validation.
		\add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_password_scripts' ) );
	}

	/**
	 * Enqueue password strength scripts for live validation
	 *
	 * @since 1.1.5
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_password_scripts( string $hook_suffix ): void {
		// Only load on user profile pages.
		if ( ! in_array( $hook_suffix, array( 'profile.php', 'user-edit.php', 'user-new.php' ), true ) ) {
			return;
		}

		// Check if password strength enforcement is enabled.
		if ( ! DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' ) ) {
			return;
		}

		// Enqueue WordPress password strength meter.
		\wp_enqueue_script( 'password-strength-meter' );

		// Enqueue CSS variables.
		\wp_enqueue_style(
			'silver-assist-variables',
			$this->get_asset_url( 'assets/css/variables.css' ),
			array(),
			$this->plugin_version
		);

		// Enqueue custom password validation styles.
		\wp_enqueue_style(
			'silver-assist-password-validation',
			$this->get_asset_url( 'assets/css/password-validation.css' ),
			array( 'silver-assist-variables' ),
			$this->plugin_version
		);

		// Enqueue custom password validation script.
		\wp_enqueue_script(
			'silver-assist-password-validation',
			$this->get_asset_url( 'assets/js/password-validation.js' ),
			array( 'jquery', 'password-strength-meter' ),
			$this->plugin_version,
			true
		);

		// Localize script with translated error message.
		\wp_localize_script(
			'silver-assist-password-validation',
			'silverAssistSecurity',
			array(
				'passwordError'        => \__( 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.', 'silver-assist-security' ),
				'passwordSuccess'      => \__( 'Password meets security requirements', 'silver-assist-security' ),
				'hideWeakConfirmation' => true, // Flag to indicate weak password confirmation should be hidden.
			)
		);
	}

	/**
	 * Get asset URL with minification support
	 *
	 * Returns minified version when SCRIPT_DEBUG is not true, regular version otherwise.
	 *
	 * @since 1.1.10
	 * @param string $asset_path The relative path to the asset (e.g., 'assets/css/password-validation.css').
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
			\add_action( 'user_profile_update_errors', array( $this, 'validate_password_strength' ), 10, 3 );
			\add_action( 'validate_password_reset', array( $this, 'validate_password_strength_reset' ), 10, 2 );
			\add_filter( 'rest_request_before_callbacks', array( $this, 'validate_rest_password_strength' ), 10, 3 );
		}
	}

	/**
	 * Add security fields to login form
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function add_login_form_security(): void {
		// Add nonce field.
		\wp_nonce_field( 'secure_login_action', 'secure_login_nonce' );

		// Add honeypot field (hidden from users).
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
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		// Check honeypot.
		if ( isset( $_POST['website_url'] ) && ! empty( $_POST['website_url'] ) ) {
			\wp_die( esc_html( \__( 'Security check failed.', 'silver-assist-security' ) ) );
		}

		// Verify nonce.
		if ( isset( $_POST['log'] ) && function_exists( 'wp_verify_nonce' ) ) {
			$nonce = isset( $_POST['secure_login_nonce'] ) ? \sanitize_text_field( \wp_unslash( $_POST['secure_login_nonce'] ) ) : '';
			if ( ! \wp_verify_nonce( $nonce, 'secure_login_action' ) ) {
				// Log only, on purpose: login pages are often served from a page cache or CDN, so the nonce
				// printed in the form can be stale for a real person. Enforcing it would lock out legitimate
				// users; password guessing is stopped by the per-IP lockout instead.
				SecurityHelper::log_security_event( 'NONCE_VERIFICATION_FAILED', 'Nonce verification failed for login attempt', array() );
			}
		}
	}

	/**
	 * Handle failed login attempt
	 *
	 * @since 1.1.1
	 * @param string $username Username that failed login.
	 * @return void
	 */
	public function handle_failed_login( string $username ): void {
		$ip = SecurityHelper::get_client_ip();

		// Core also fires wp_login_failed for the lockout error itself. Counting that
		// attempt would renew the lockout, so a locked-out person who keeps trying (or an
		// attacker sharing their IP) would never be let back in.
		if ( \get_transient( SecurityHelper::generate_ip_transient_key( 'lockout', $ip ) ) ) {
			return;
		}

		SecurityEventCounter::record( SecurityEventCounter::FAILED_LOGIN );

		// Atomic fixed-window counter: parallel failures each get their own count, so they cannot
		// overwrite each other and slip past the limit. The window opens at the first failure and lasts
		// the lockout duration. The count is read from the return value (a persistent object cache keeps
		// it outside the transient).
		$attempts = SecurityHelper::increment_rate_window(
			SecurityHelper::generate_ip_transient_key( 'login_window', $ip ),
			SecurityHelper::generate_ip_transient_key( 'login_attempts', $ip ),
			time(),
			$this->lockout_duration
		);

		if ( $attempts >= $this->max_attempts ) {
			// Log the lockout using centralized security logging.
			SecurityHelper::log_security_event(
				'LOGIN_LOCKOUT',
				"IP locked out after {$attempts} failed login attempts",
				array(
					'username'         => $username,
					'attempts'         => $attempts,
					'max_attempts'     => $this->max_attempts,
					'lockout_duration' => $this->lockout_duration,
				)
			);

			// Set the lockout flag (its value stays `true`: the admin statistics count rows holding "1").
			// The companion transient holds the Unix time the lockout ends, so the remaining time can be
			// read through the transient API (a persistent object cache has no timeout rows).
			$lockout_key = SecurityHelper::generate_ip_transient_key( 'lockout', $ip );
			if ( false === \get_transient( $lockout_key ) ) {
				\set_transient( $lockout_key, true, $this->lockout_duration );
				\set_transient( SecurityHelper::generate_ip_transient_key( 'lockout_until', $ip ), time() + $this->lockout_duration, $this->lockout_duration );
				SecurityEventCounter::record( SecurityEventCounter::IP_BLOCKED );
			}
		}
	}

	/**
	 * Whether login screen error markup is the lockout notice
	 *
	 * @since 1.5.4
	 * @param string $markup Error markup built by wp-login.php.
	 * @return bool
	 */
	public static function is_lockout_notice( string $markup ): bool {
		/* translators: %d: number of minutes remaining until unlock */
		$template = \__( 'Too many failed login attempts. Try again in %d minutes.', 'silver-assist-security' );
		$prefix   = trim( explode( '%d', $template, 2 )[0] );

		return '' !== $prefix && false !== strpos( $markup, $prefix );
	}

	/**
	 * Check if user is locked out
	 *
	 * @since 1.1.1
	 * @param WP_User|WP_Error|null $user User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public function check_login_lockout( $user, string $username, string $password ) {
		// Skip if no username/password provided.
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$ip          = SecurityHelper::get_client_ip();
		$lockout_key = SecurityHelper::generate_ip_transient_key( 'lockout', $ip );

		// Check if IP is locked out.
		if ( \get_transient( $lockout_key ) ) {
			$remaining_time = $this->get_remaining_lockout_time( $ip );

			return new WP_Error(
				'login_locked',
				sprintf(
					/* translators: %d: number of minutes remaining until unlock */
					\__( 'Too many failed login attempts. Try again in %d minutes.', 'silver-assist-security' ),
					max( 1, (int) ceil( $remaining_time / 60 ) )
				)
			);
		}

		return $user;
	}

	/**
	 * Handle successful login
	 *
	 * @since 1.1.1
	 * @param string  $user_login Username.
	 * @param WP_User $user User object.
	 * @return void
	 */
	public function handle_successful_login( string $user_login, WP_User $user ): void {
		// Clear login attempts on successful login.
		$this->clear_login_attempts();

		// Clear any previous session metadata to prevent login loops.
		\delete_user_meta( $user->ID, 'last_activity' );

		// Set fresh session timeout for new login session.
		$this->set_session_timeout();
	}

	/**
	 * Setup session timeout
	 *
	 * Idle timeout means: no real user activity for the configured minutes. Every
	 * logged-in request is checked, administrators included, and a request past the
	 * limit ends the session. Only foreground requests count as activity: page views,
	 * form posts and REST writes refresh `last_activity`; Heartbeat and other background
	 * polling (REST reads, admin-ajax GET) do not, so an open tab goes idle like any other.
	 * The refresh is written at most once per ACTIVITY_WRITE_INTERVAL seconds.
	 *
	 * Where the visitor lands: wp-admin page views redirect to login with
	 * session_expired=1; AJAX and REST requests are only logged out (the response then
	 * carries the usual "not logged in" answer); front end pages are logged out silently.
	 *
	 * Interplay with the auth cookie lifetime: the cookie lasts exactly the timeout from
	 * the login (see enforce_session_cookie_lifetime()) and WordPress does not renew it on
	 * activity, so in practice a session also ends that long after login. The idle check
	 * is the sliding bound that still applies when another plugin lengthens the cookie.
	 *
	 * @since 1.1.1
	 * @updated 1.1.10 Added frontend/admin differentiation
	 * @updated 1.5.4 Administrators included, background requests are not activity, throttled writes
	 * @return void
	 */
	public function setup_session_timeout(): void {
		if ( ! \is_user_logged_in() ) {
			return;
		}

		$user_id       = \get_current_user_id();
		$last_activity = \get_user_meta( $user_id, 'last_activity', true );
		$timeout       = $this->session_timeout * 60; // Convert to seconds.

		// Skip timeout check if we're in the login process or just logged in.
		if ( $this->is_in_login_process() ) {
			// Initialize/update last activity for new session.
			$this->touch_last_activity( $user_id, $last_activity );
			return;
		}

		// Only check timeout if last_activity exists and is not empty
		// This prevents logout during plugin activation when last_activity hasn't been set yet.
		if ( $last_activity && is_numeric( $last_activity ) && (int) $last_activity > 0 ) {
			$time_since_last_activity = time() - (int) $last_activity;

			if ( $time_since_last_activity > $timeout ) {
				// Clear session metadata before logout to prevent loops.
				\delete_user_meta( $user_id, 'last_activity' );
				\wp_logout();

				// Only redirect page views in wp-admin; AJAX, REST and front end requests continue logged out.
				if ( \is_admin() && ! \wp_doing_ajax() && ! $this->is_rest_request() ) {
					\wp_safe_redirect( \add_query_arg( 'session_expired', '1', \wp_login_url() ) );
					exit;
				}
				return;
			}
		}

		if ( $this->is_background_request() ) {
			return;
		}

		$this->touch_last_activity( $user_id, $last_activity );
	}

	/**
	 * Record user activity, at most once per ACTIVITY_WRITE_INTERVAL seconds
	 *
	 * @since 1.5.4
	 * @param int   $user_id       User ID.
	 * @param mixed $last_activity Stored last_activity value.
	 * @return void
	 */
	private function touch_last_activity( int $user_id, mixed $last_activity ): void {
		$now = time();

		if ( is_numeric( $last_activity ) && (int) $last_activity > 0 && ( $now - (int) $last_activity ) < self::ACTIVITY_WRITE_INTERVAL ) {
			return;
		}

		\update_user_meta( $user_id, 'last_activity', $now );
	}

	/**
	 * Whether this request is background polling rather than user activity
	 *
	 * Heartbeat ticks and REST or admin-ajax reads fire on their own while a tab is open.
	 * The `silver_assist_security_is_background_request` filter can reclassify a request.
	 *
	 * @since 1.5.4
	 * @return bool
	 */
	private function is_background_request(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? \strtoupper( \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$read   = in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- Classifying the request, not processing form data.
		$action = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';

		$background = false;
		if ( \wp_doing_ajax() ) {
			$background = 'heartbeat' === $action || $read;
		} elseif ( $this->is_rest_request() ) {
			$background = $read;
		}

		/**
		 * Filters whether the current request is background polling (not user activity).
		 *
		 * @since 1.5.4
		 * @param bool $background Whether the request is background polling.
		 */
		return (bool) \apply_filters( 'silver_assist_security_is_background_request', $background );
	}

	/**
	 * Whether this is a REST API request
	 *
	 * Runs on `init`, before WordPress defines REST_REQUEST, so it reads the URL like core does.
	 *
	 * @since 1.5.4
	 * @return bool
	 */
	private function is_rest_request(): bool {
		if ( \wp_is_serving_rest_request() ) {
			return true;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Classifying the request, not processing form data.
		if ( isset( $_GET['rest_route'] ) ) {
			return true;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) \wp_parse_url( $uri, PHP_URL_PATH );

		return str_contains( $path, '/' . \rest_get_url_prefix() . '/' );
	}

	/**
	 * Check if we're currently in a login process
	 *
	 * @since 1.1.8
	 * @return bool True if in login process
	 */
	private function is_in_login_process(): bool {
		global $pagenow;

		// Check if we're on wp-login.php.
		if ( 'wp-login.php' === $pagenow ) {
			return true;
		}

		// Check if this is a login POST request.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checking if this is a login request context, not processing form data.
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST['log'] ) ) {
			return true;
		}

		// Check if this is immediately after login (within 30 seconds).
		$user_id    = \get_current_user_id();
		$last_login = \get_user_meta( $user_id, 'session_tokens', true );
		if ( is_array( $last_login ) ) {
			$most_recent_token = end( $last_login );
			if ( isset( $most_recent_token['login'] ) && ( time() - $most_recent_token['login'] ) < 30 ) {
				return true;
			}
		}

		// Check for specific login-related actions.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking action type, not processing form data.
		$action        = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';
		$login_actions = array( 'login', 'logout', 'register', 'resetpass', 'rp', 'lostpassword' );
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
		$ip = SecurityHelper::get_client_ip();

		\delete_transient( SecurityHelper::generate_ip_transient_key( 'login_attempts', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'login_window', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'lockout', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'lockout_until', $ip ) );
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	/**
	 * Clear login attempts after successful password reset
	 *
	 * @since 1.1.9
	 * @param WP_User $user User object.
	 * @param string  $new_pass New password.
	 * @return void
	 */
	public function clear_login_attempts_on_password_change( WP_User $user, string $new_pass ): void {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// Clear any existing login attempts for the current IP.
		$this->clear_login_attempts();

		SecurityHelper::log_security_event(
			'LOGIN_ATTEMPTS_CLEARED',
			sprintf( 'Login attempts cleared after password reset for user: %s', $user->user_login ),
			array( 'user_login' => $user->user_login )
		);
	}

	/**
	 * Clear login attempts after profile update (includes password changes from admin)
	 *
	 * @since 1.1.9
	 * @param int     $user_id User ID.
	 * @param WP_User $old_user_data Old user data before update.
	 * @return void
	 */
	public function clear_login_attempts_on_profile_update( int $user_id, WP_User $old_user_data ): void {
		// Only clear if password was actually changed.
		$new_user = \get_userdata( $user_id );
		if ( $new_user && $new_user->user_pass !== $old_user_data->user_pass ) {
			// Clear any existing login attempts for the current IP.
			$this->clear_login_attempts();

			SecurityHelper::log_security_event(
				'LOGIN_ATTEMPTS_CLEARED',
				sprintf( 'Login attempts cleared after profile password change for user: %s', $new_user->user_login ),
				array( 'user_login' => $new_user->user_login )
			);
		}
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	/**
	 * Validate password strength on the profile and new user forms
	 *
	 * Checks the value WordPress stores (`wp_unslash( $_POST['pass1'] )`, which edit_user()
	 * saves untouched), not a sanitized copy.
	 *
	 * @since 1.1.1
	 * @updated 1.5.4 Validate the raw value
	 * @param WP_Error          $errors Errors object.
	 * @param bool              $update Whether this is a user update.
	 * @param \stdClass|WP_User $user User object (stdClass for new users, WP_User for updates).
	 * @return void
	 */
	public function validate_password_strength( WP_Error $errors, bool $update, \stdClass|WP_User $user ): void {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress handles nonce verification for user profile updates.
		if ( isset( $_POST['pass1'] ) && is_string( $_POST['pass1'] ) && '' !== $_POST['pass1'] ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords must be checked as typed; sanitizing would change them.
			$password = \wp_unslash( $_POST['pass1'] );

			if ( ! $this->is_strong_password( $password ) ) {
				$errors->add( 'weak_password', self::get_weak_password_message() );
			}
		}
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress hook.
	/**
	 * Validate password strength on reset
	 *
	 * The reset screen (wp-login.php) passes `$_POST['pass1']` to reset_password() as it is,
	 * so that exact string is checked.
	 *
	 * @since 1.1.1
	 * @updated 1.5.4 Validate the raw value
	 * @param WP_Error          $errors Errors object.
	 * @param \stdClass|WP_User $user User object (can be stdClass or WP_User depending on context).
	 * @return void
	 */
	public function validate_password_strength_reset( WP_Error $errors, \stdClass|WP_User $user ): void {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress handles nonce verification for password reset forms.
		if ( isset( $_POST['pass1'] ) && is_string( $_POST['pass1'] ) && '' !== $_POST['pass1'] ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passwords must be checked as submitted; sanitizing would change them.
			$password = $_POST['pass1'];

			if ( ! $this->is_strong_password( $password ) ) {
				$errors->add( 'weak_password', self::get_weak_password_message() );
			}
		}
	}

	/**
	 * Enforce the password policy on the REST user routes
	 *
	 * Covers POST, PUT and PATCH on /wp/v2/users, /wp/v2/users/{id} and /wp/v2/users/me.
	 * The `rest_pre_insert_user` filter cannot do this: the users controller does not look
	 * at a WP_Error returned from it. Instead this runs after argument validation and before
	 * the route callback, and the password is checked exactly as sent. Requests without a
	 * password pass through. WP-CLI, wp_insert_user() and wp_set_password() are not covered
	 * (see the README, "Password policy").
	 *
	 * @since 1.5.4
	 * @param mixed            $response Response so far (a WP_Error stops the request).
	 * @param array<mixed>     $handler  Route handler (unused).
	 * @param \WP_REST_Request $request  Request object.
	 * @return mixed The response unchanged, or a 400 WP_Error for a weak password.
	 */
	public function validate_rest_password_strength( $response, $handler, $request ) {
		unset( $handler );

		if ( \is_wp_error( $response ) || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}

		if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			return $response;
		}

		if ( ! preg_match( '#^/wp/v2/users(?:/(?:me|\d+))?$#', $request->get_route() ) ) {
			return $response;
		}

		$password = $request->get_param( 'password' );
		if ( ! is_string( $password ) || '' === $password ) {
			return $response;
		}

		if ( ! $this->is_strong_password( $password ) ) {
			return new WP_Error( 'weak_password', self::get_weak_password_message(), array( 'status' => 400 ) );
		}

		return $response;
	}

	/**
	 * The message shown for a password that breaks the policy
	 *
	 * @since 1.5.4
	 * @return string
	 */
	private static function get_weak_password_message(): string {
		return \__( 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.', 'silver-assist-security' );
	}

	/**
	 * Check if password is strong
	 *
	 * @since 1.1.1
	 * @param string $password Password to check.
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
	 * Reads the end time stored in the `lockout_until` transient, which works with and without a
	 * persistent object cache. A lockout stored by an earlier version has no end time; it is reported
	 * as zero (shown as one minute).
	 *
	 * @since 1.1.1
	 * @param string $ip Client IP address.
	 * @return int Remaining time in seconds
	 */
	private function get_remaining_lockout_time( string $ip ): int {
		$until = \get_transient( SecurityHelper::generate_ip_transient_key( 'lockout_until', $ip ) );

		return is_numeric( $until ) ? max( 0, (int) $until - time() ) : 0;
	}

	/**
	 * Block suspicious bots and crawlers from accessing login page
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function block_suspicious_bots(): void {
		// Check if bot protection is enabled.
		$bot_protection_enabled = DefaultConfig::get_option( 'silver_assist_bot_protection' );
		if ( ! $bot_protection_enabled ) {
			return;
		}

		// Skip bot protection for logged-in users.
		if ( \is_user_logged_in() ) {
			return;
		}

		// Skip bot protection for legitimate WordPress actions.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking action type for bot detection, not processing form data.
		$action             = isset( $_REQUEST['action'] ) ? \sanitize_text_field( \wp_unslash( $_REQUEST['action'] ) ) : '';
		$legitimate_actions = DefaultConfig::get_bot_protection_bypass_actions();

		if ( in_array( $action, $legitimate_actions, true ) ) {
			return;
		}

		// Skip if this is a password reset confirmation (has key parameter).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking password reset context, not processing form data.
		if ( isset( $_GET['key'] ) && isset( $_GET['login'] ) ) {
			return;
		}

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$ip         = $this->get_client_ip();

		// Known bot, crawler, scanner and scripting-client user agents (whole-word matching).
		$is_bot = SecurityHelper::matches_bot_user_agent( $user_agent );

		// Additional checks for suspicious behavior (but more lenient for users).
		if ( ! $is_bot ) {
			// Check for empty or very short user agents (common in bots).
			if ( empty( $user_agent ) || strlen( $user_agent ) < 10 ) {
				$is_bot = true;
			}

			// Check for missing common browser headers (but be more lenient).
			if ( ! isset( $_SERVER['HTTP_ACCEPT'] ) && ! isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) && ! isset( $_SERVER['HTTP_ACCEPT_ENCODING'] ) ) {
				$is_bot = true;
			}

			// Per-IP request rate limit for the login page.
			if ( $this->is_login_page_rate_limited( $ip ) ) {
				$is_bot = true;
			}
		}

		// Only block if definitively identified as bot/crawler.
		if ( $is_bot ) {
			$this->track_bot_behavior(); // Use existing method.
			$this->send_404_response();
		}
	}

	/**
	 * Count a login page request from an IP and report whether it is over the limit
	 *
	 * The 16th request within a minute from one IP is the first one treated as bot
	 * traffic (404). The counter is a fixed window per IP: it starts at the first
	 * request and ends a minute later, whatever happens in between, so a monitor
	 * hitting the page once a minute is never blocked. The threshold accommodates
	 * password changes with redirects, logout confirmations and several login
	 * attempts by a legitimate user, but several people sharing one IP (office,
	 * VPN) share this budget.
	 *
	 * @since 1.5.4
	 * @param string $ip Client IP address.
	 * @return bool True when this request exceeds the limit.
	 */
	public function is_login_page_rate_limited( string $ip ): bool {
		$hits = SecurityHelper::increment_rate_window(
			SecurityHelper::generate_ip_transient_key( 'login_access_window', $ip ),
			SecurityHelper::generate_ip_transient_key( 'login_access', $ip ),
			time(),
			60
		);

		return $hits > 15;
	}

	/**
	 * Record a request blocked as bot traffic, for security monitoring
	 *
	 * Called only for requests `block_suspicious_bots()` turned away, never for ordinary failed
	 * logins (those are counted by the login lockout). It is a log, not a block: an earlier
	 * `extended_bot_block_*` flag was written after four entries but nothing ever read it, so it was
	 * removed rather than enforced, because a two-hour block on an IP shared by a whole office is a
	 * heavier penalty than the 404 plus the per-minute limit already give.
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function track_bot_behavior(): void {
		$ip         = $this->get_client_ip();
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown';

		// Log bot activity for security monitoring.
		$bot_log_key  = SecurityHelper::generate_ip_transient_key( 'bot_activity', $ip );
		$bot_activity = \get_transient( $bot_log_key );
		if ( false === $bot_activity ) {
			$bot_activity = array();
		}

		$bot_activity[] = array(
			'time'       => time(),
			'user_agent' => $user_agent,
			'method'     => isset( $_SERVER['REQUEST_METHOD'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
			'uri'        => isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
		);

		// Keep only last 10 activities.
		if ( count( $bot_activity ) > 10 ) {
			$bot_activity = array_slice( $bot_activity, -10 );
		}

		\set_transient( $bot_log_key, $bot_activity, 3600 ); // Store for 1 hour.
	}

	/**
	 * Send 404 Not Found response to bots
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function send_404_response(): void {
		SecurityEventCounter::record( SecurityEventCounter::BOT_BLOCKED );

		// Log the blocked access attempt.
		SecurityHelper::log_security_event(
			'BOT_BLOCKED',
			'Bot/crawler blocked from login page',
			array(
				'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown',
				'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			)
		);

		// Use centralized 404 response without WordPress template to avoid conflicts.
		SecurityHelper::send_404_response( false );
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by WordPress filter signature.
	/**
	 * Force the auth cookie expiration to match the configured session timeout.
	 *
	 * Overrides WordPress default of 2 days (or 14 days with "Remember Me")
	 * so the cookie never outlives the plugin's session timeout setting.
	 *
	 * @since 1.1.15
	 * @param int  $expiration Default expiration in seconds.
	 * @param int  $user_id    User ID.
	 * @param bool $remember   Whether "Remember Me" was checked.
	 * @return int Session timeout in seconds.
	 */
	public function enforce_session_cookie_lifetime( int $expiration, int $user_id, bool $remember ): int {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		return $this->session_timeout * 60;
	}

	/**
	 * Hide the "Remember Me" checkbox on the login form.
	 *
	 * Since the plugin enforces a fixed session timeout, the checkbox
	 * would be misleading. Hooked to `login_enqueue_scripts`.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function hide_remember_me(): void {
		echo '<style>.forgetmenot { display: none !important; }</style>';
	}
}
