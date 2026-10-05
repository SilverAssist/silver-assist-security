<?php
/**
 * Silver Assist Security Essentials - General WordPress Security
 *
 * Implements general WordPress security hardening including security headers,
 * version hiding, user enumeration protection, and cookie security configuration.
 * Provides foundational security measures for WordPress installations.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.5.3
 */

namespace SilverAssist\Security\Security;

use SilverAssist\PluginKernel\Interfaces\LoadableInterface;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * General Security class
 *
 * Handles general WordPress security features like headers, version hiding, etc.
 *
 * @since 1.1.1
 */
class GeneralSecurity implements LoadableInterface {


	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Constructor
	 *
	 * @since 1.1.1
	 */
	public function __construct() {
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
	 * Always loads — matches pre-kernel behavior, where Plugin::init_security_components()
	 * constructed GeneralSecurity unconditionally.
	 *
	 * @since 1.5.1
	 * @return bool
	 */
	public function should_load(): bool {
		return true;
	}

	/**
	 * Register WordPress hooks for general security
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function register_hooks(): void {
		// Security headers.
		\add_action( 'send_headers', array( $this, 'add_security_headers' ) );
		// send_headers only fires for front-end requests; wp-admin, the login screen
		// and REST responses skip it, so send the same headers from their own hooks.
		\add_action( 'admin_init', array( $this, 'add_security_headers' ) );
		\add_action( 'login_init', array( $this, 'add_security_headers' ) );
		\add_filter( 'rest_pre_serve_request', array( $this, 'add_rest_security_headers' ) );

		// Hide WordPress version.
		\add_filter( 'the_generator', array( $this, 'remove_version' ) );

		// Remove unnecessary headers.
		\add_action( 'init', array( $this, 'remove_unnecessary_headers' ) );

		// Remove version from scripts and styles.
		\add_filter( 'script_loader_src', array( $this, 'remove_version_query_string' ), 10, 2 );
		\add_filter( 'style_loader_src', array( $this, 'remove_version_query_string' ), 10, 2 );

		// Disable XML-RPC.
		\add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_methods' ) );
		\add_filter( 'xmlrpc_enabled', array( $this, 'filter_xmlrpc_enabled' ) );

		// Configure secure cookies.
		\add_action( 'init', array( $this, 'configure_secure_cookies' ) );
		\add_filter( 'secure_auth_cookie', array( $this, 'force_secure_cookies' ) );
		\add_filter( 'secure_logged_in_cookie', array( $this, 'force_secure_logged_in_cookie' ) );

		// Disable user enumeration.
		\add_action( 'init', array( $this, 'disable_user_enumeration' ) );

		// Hide login errors.
		\add_filter( 'login_errors', array( $this, 'hide_login_errors' ) );

		// Remove admin bar for non-admins.
		\add_action( 'after_setup_theme', array( $this, 'remove_admin_bar_for_non_admins' ) );

		// Disable file editing.
		$this->disable_file_editing();

		// Remove WordPress branding.
		\add_action( 'wp_before_admin_bar_render', array( $this, 'remove_wp_logo' ) );
		\add_filter( 'admin_footer_text', array( $this, 'change_admin_footer' ) );
	}

	/**
	 * Get the security headers for the current request
	 *
	 * @since 1.5.4
	 * @return array<string, string> Header name => value.
	 */
	public function get_security_headers(): array {
		$headers = array(
			'X-Content-Type-Options' => 'nosniff',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'X-XSS-Protection'       => '1; mode=block',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'geolocation=(), microphone=(), camera=()',
		);

		// HSTS for HTTPS sites (only in production, not in development environments)
		// Includes preload directive to allow submission to browser HSTS preload lists.
		if ( \is_ssl() && ! $this->is_development_environment() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
		}

		/**
		 * Filters the security headers sent with every response.
		 *
		 * Use it to relax a header an integration needs (for example
		 * `Permissions-Policy: geolocation=(self)` for a store locator) or to
		 * remove one by unsetting its key.
		 *
		 * @since 1.5.4
		 * @param array<string, string> $headers Header name => value.
		 */
		$headers = \apply_filters( 'silver_assist_security_headers', $headers );

		return $headers;
	}

	/**
	 * Add security headers
	 *
	 * Runs on `send_headers` (front end), `admin_init` (wp-admin, admin-ajax),
	 * `login_init` (wp-login.php) and before a REST response is served.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 Also sent in wp-admin, on the login screen and for REST responses.
	 * @return void
	 */
	public function add_security_headers(): void {
		$this->send_headers_now( $this->get_security_headers() );
	}

	/**
	 * Send the security headers before a REST response and pass the flag through
	 *
	 * @since 1.5.4
	 * @param mixed $served Whether the request has already been served.
	 * @return mixed The unchanged flag.
	 */
	public function add_rest_security_headers( $served ) {
		$this->add_security_headers();
		return $served;
	}

	/**
	 * Send header lines
	 *
	 * @since 1.5.4
	 * @param array<string, string> $headers Header name => value.
	 * @return void
	 */
	protected function send_headers_now( array $headers ): void {
		if ( headers_sent() ) {
			return;
		}

		foreach ( $headers as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}

	/**
	 * Remove WordPress version
	 *
	 * @since 1.1.1
	 * @return string
	 */
	public function remove_version(): string {
		return '';
	}

	/**
	 * Remove unnecessary headers
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function remove_unnecessary_headers(): void {
		\remove_action( 'wp_head', 'rsd_link' );
		\remove_action( 'wp_head', 'wlwmanifest_link' );
		\remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		\remove_action( 'wp_head', 'wp_generator' );
		/**
		 * Filters whether the RSS feed autodiscovery tags are removed from wp_head.
		 *
		 * The feeds themselves keep working at their URLs; only the
		 * `<link rel="alternate" type="application/rss+xml">` tags go. Return
		 * false to keep them for sites whose readers or aggregators rely on
		 * autodiscovery.
		 *
		 * @since 1.5.4
		 * @param bool $remove Whether to remove the feed links. Default true.
		 */
		if ( \apply_filters( 'silver_assist_security_remove_feed_links', true ) ) {
			\remove_action( 'wp_head', 'feed_links_extra', 3 );
			\remove_action( 'wp_head', 'feed_links', 2 );
		}
		\remove_action( 'wp_head', 'index_rel_link' );
		\remove_action( 'wp_head', 'parent_post_rel_link', 10 );
		\remove_action( 'wp_head', 'start_post_rel_link', 10 );
		\remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
		\remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
		\remove_action( 'wp_head', 'wp_oembed_add_host_js' );
		// Keep wp_oembed_register_route: it also registers /oembed/1.0/proxy, which the
		// block editor Embed block needs. Hide only the public provider route.
		\add_filter(
			'rest_endpoints',
			function ( $endpoints ) {
				if ( ! ( \is_user_logged_in() && \current_user_can( 'edit_posts' ) ) ) {
					unset( $endpoints['/oembed/1.0/embed'] );
				}
				return $endpoints;
			}
		);
		// Do not remove wp_filter_oembed_result from oembed_dataparse: it restricts provider HTML
		// to safe markup (iframes, blockquotes), so a hostile provider cannot inject scripts (#129).
	}

	/**
	 * Remove version query string from static resources
	 *
	 * Removes all "ver" query parameters from URLs, including multiple instances
	 * like "/file.css?ver=123?ver=456" to prevent version disclosure.
	 *
	 * The cache-buster is kept wherever it is needed for correctness: wp-admin,
	 * admin-ajax, and WordPress core bundles (wp-includes / wp-admin), whose
	 * packages (e.g. data.min.js and editor.min.js) must be served as a matching
	 * set after a core update. Sites can override per asset with the
	 * `silver_assist_security_strip_asset_version` filter.
	 *
	 * @since 1.1.1
	 * @since 1.5.3 Skips admin, AJAX and core assets; adds the strip filter.
	 * @param string $src    Source URL.
	 * @param string $handle Optional asset handle.
	 * @return string URL with all version parameters removed
	 */
	public function remove_version_query_string( string $src, string $handle = '' ): string {
		if ( ! $this->should_strip_asset_version( $src, $handle ) ) {
			return $src;
		}

		// Check if URL contains any version parameters.
		if ( strpos( $src, 'ver=' ) !== false ) {
			// Remove all occurrences of ver parameter using regex
			// This handles both ?ver= and &ver= patterns.
			$cleaned = preg_replace( '/[\?&]ver=[^&]*/', '', $src );

			// If preg_replace succeeded, use the cleaned version.
			if ( null !== $cleaned ) {
				$src = rtrim( $cleaned, '?&' );

				// If we have parameters but no ?, add it back.
				if ( strpos( $src, '&' ) !== false && strpos( $src, '?' ) === false ) {
					$src = str_replace( '&', '?', $src );
				}
			}
		}

		return $src;
	}

	/**
	 * Decide whether the ver= parameter may be removed from an asset URL
	 *
	 * @since 1.5.3
	 * @param string $src    Source URL.
	 * @param string $handle Asset handle.
	 * @return bool True when the version may be stripped.
	 */
	private function should_strip_asset_version( string $src, string $handle ): bool {
		$strip = ! \is_admin()
			&& ! \wp_doing_ajax()
			&& false === strpos( $src, '/wp-includes/' )
			&& false === strpos( $src, '/wp-admin/' );

		/**
		 * Filters whether the ver= query parameter is removed from an asset URL.
		 *
		 * @since 1.5.3
		 * @param bool   $strip  Whether to strip the version.
		 * @param string $src    Asset URL.
		 * @param string $handle Asset handle.
		 */
		return (bool) \apply_filters( 'silver_assist_security_strip_asset_version', $strip, $src, $handle );
	}

	/**
	 * Whether XML-RPC is disabled
	 *
	 * @since 1.5.4
	 * @return bool
	 */
	private function is_xmlrpc_disabled(): bool {
		/**
		 * Filters whether XML-RPC is disabled.
		 *
		 * Return false for sites that need it (Jetpack, the WordPress mobile
		 * apps, inbound pingbacks). Nothing in this plugin uses XML-RPC.
		 *
		 * @since 1.5.4
		 * @param bool $disabled Whether to disable XML-RPC. Default true.
		 */
		return (bool) \apply_filters( 'silver_assist_security_disable_xmlrpc', true );
	}

	/**
	 * Filter the xmlrpc_enabled flag
	 *
	 * @since 1.5.4
	 * @param bool $enabled Whether XML-RPC is enabled.
	 * @return bool
	 */
	public function filter_xmlrpc_enabled( bool $enabled ): bool {
		return $this->is_xmlrpc_disabled() ? false : $enabled;
	}

	/**
	 * Remove XML-RPC methods
	 *
	 * @since 1.1.1
	 * @param array $methods XML-RPC methods.
	 * @return array
	 */
	public function remove_xmlrpc_methods( array $methods ): array {
		return $this->is_xmlrpc_disabled() ? array() : $methods;
	}

	/**
	 * Configure secure cookies
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function configure_secure_cookies(): void {
		// Only configure session cookies if no session has started yet
		// This prevents disrupting existing sessions during plugin activation.
		if ( ! headers_sent() && session_status() === PHP_SESSION_NONE ) {
			$secure = \is_ssl();

			session_set_cookie_params(
				array(
					'lifetime' => 0,
					'path'     => '/',
					'domain'   => '',
					'secure'   => $secure,
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Required by WordPress filter signature.
	/**
	 * Force secure cookies
	 *
	 * @since 1.1.1
	 * @param bool $secure Current secure flag.
	 * @return bool
	 */
	public function force_secure_cookies( bool $secure ): bool {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.Found
		return \is_ssl();
	}

	/**
	 * Mark the logged-in cookie Secure the way core decides, but never over plain HTTP
	 *
	 * Core marks it Secure only when the home URL is https, so a site whose
	 * wp-admin is https and whose public home is http can still read it on the
	 * public pages. Forcing Secure whenever the request is SSL dropped the cookie
	 * there (admin bar and previews disappeared for logged-in users).
	 *
	 * @since 1.5.4
	 * @param bool $secure Whether the cookie is Secure according to core.
	 * @return bool
	 */
	public function force_secure_logged_in_cookie( bool $secure ): bool {
		return $secure && \is_ssl();
	}

	/**
	 * Disable user enumeration
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function disable_user_enumeration(): void {
		// Disable author enumeration via REST API.
		\add_filter(
			'rest_endpoints',
			function ( $endpoints ) {
				// The block editor needs these routes (author selector, mentions) for
				// users who can edit content; only hide them from everyone else.
				if ( \is_user_logged_in() && \current_user_can( 'edit_posts' ) ) {
					return $endpoints;
				}
				if ( isset( $endpoints['/wp/v2/users'] ) ) {
					unset( $endpoints['/wp/v2/users'] );
				}
				if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
					unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
				}
				return $endpoints;
			}
		);

		// Disable author enumeration via URL.
		\add_action(
			'template_redirect',
			function () {
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public page check, no form submission.
				$author_param = isset( $_GET['author'] ) ? \sanitize_text_field( \wp_unslash( $_GET['author'] ) ) : false;
				if ( \is_author() || $author_param ) {
					\wp_safe_redirect( \home_url() );
					exit;
				}
			}
		);

		// Remove author links from posts.
		\add_filter(
			'author_link',
			function () {
				return \home_url();
			}
		);
	}

	/**
	 * Hide login errors that reveal whether an account exists
	 *
	 * Only the login and lost-password screens are generic, and not while the
	 * visitor is locked out: the lockout message is the only explanation for a
	 * rejected login in that case. Password reset and other screens keep core's
	 * messages ("passwords do not match", "link expired"), which reveal nothing
	 * about accounts and are the only guidance the user gets.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 Leaves the lockout message and non-credential screens alone.
	 * @param string $errors Error markup built by wp-login.php.
	 * @return string
	 */
	public function hide_login_errors( $errors = '' ): string {
		$errors = (string) $errors;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen detection, no form data is used.
		$action = isset( $_REQUEST['action'] ) ? \sanitize_key( \wp_unslash( $_REQUEST['action'] ) ) : 'login';

		if ( ! in_array( $action, array( 'login', 'lostpassword', 'retrievepassword' ), true ) ) {
			return $errors;
		}

		$lockout_key = SecurityHelper::generate_ip_transient_key( 'lockout', SecurityHelper::get_client_ip() );
		if ( \get_transient( $lockout_key ) ) {
			return $errors;
		}

		return \__( 'Invalid login credentials.', 'silver-assist-security' );
	}

	/**
	 * Remove admin bar for non-admins
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function remove_admin_bar_for_non_admins(): void {
		if ( ! \current_user_can( 'manage_options' ) && ! \is_admin() ) {
			\show_admin_bar( false );
		}
	}

	/**
	 * Disable file editing
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function disable_file_editing(): void {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	/**
	 * Remove WordPress logo from admin bar
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function remove_wp_logo(): void {
		global $wp_admin_bar;
		$wp_admin_bar->remove_menu( 'wp-logo' );
	}

	/**
	 * Change admin footer text
	 *
	 * @since 1.1.1
	 * @return string
	 */
	public function change_admin_footer(): string {
		return sprintf(
			/* translators: %s: plugin name with HTML formatting */
			\__( 'Secured by %s', 'silver-assist-security' ),
			'<strong>Silver Assist Security Essentials</strong>'
		);
	}

	/**
	 * Get client IP address
	 *
	 * @since 1.1.1
	 * @return string
	 */
	public function get_client_ip(): string {
		return SecurityHelper::get_client_ip();
	}

	/**
	 * Check if current environment is development
	 *
	 * Detects development environments to avoid applying HSTS which can
	 * cause issues in local development when HTTPS is not properly configured.
	 *
	 * @since 1.1.14
	 * @return bool True if development environment, false otherwise
	 */
	private function is_development_environment(): bool {
		/**
		 * Filters whether the site counts as a development environment.
		 *
		 * HSTS is skipped in development. A true or false value short-circuits
		 * the detection (host name patterns, WP_DEBUG and the environment type);
		 * null runs it. Note that WP_DEBUG on a production site disables HSTS.
		 *
		 * @since 1.5.4
		 * @param bool|null $is_development Override, or null to auto-detect.
		 */
		$override = \apply_filters( 'silver_assist_security_is_development_environment', null );
		if ( is_bool( $override ) ) {
			return $override;
		}

		// Get server name.
		$server_name = isset( $_SERVER['SERVER_NAME'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '';
		if ( empty( $server_name ) && isset( $_SERVER['HTTP_HOST'] ) ) {
			$server_name = \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_HOST'] ) );
		}

		// Check for common development indicators.
		$dev_patterns = array(
			'localhost',
			'127.0.0.1',
			'::1',
			'.local',
			'.test',
			'.dev',
			'.localhost',
			'192.168.',
			'10.0.',
			'172.16.',
		);

		foreach ( $dev_patterns as $pattern ) {
			if ( stripos( $server_name, $pattern ) !== false ) {
				return true;
			}
		}

		// Check for WP_DEBUG or WP_ENVIRONMENT_TYPE.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG === true ) {
			return true;
		}

		if ( function_exists( 'wp_get_environment_type' ) ) {
			$env_type = \wp_get_environment_type();
			if ( in_array( $env_type, array( 'local', 'development' ), true ) ) {
				return true;
			}
		}

		return false;
	}
}
