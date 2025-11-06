<?php
/**
 * Silver Assist Security Essentials - Admin Panel Interface
 *
 * Handles the WordPress admin interface for security configuration including
 * login settings, password policies, GraphQL limits, and security status display.
 * Provides comprehensive settings management and validation.
 *
 * @package SilverAssist\Security\Admin
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.15
 */

namespace SilverAssist\Security\Admin;

use Exception;
use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\SettingsHub\SettingsHub;
use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Ajax\ContactForm7AjaxHandler;
use SilverAssist\Security\Admin\Assets\AssetManager;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Admin\Renderer\AdminPageRenderer;
use SilverAssist\Security\Admin\Settings\SettingsHandler;

/**
 * Admin Panel class
 *
 * Handles the WordPress admin interface for security configuration
 *
 * @since 1.1.1
 */
class AdminPanel {

	/**
	 * GraphQL Configuration Manager instance
	 *
	 * @var GraphQLConfigManager
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Plugin version for cache busting
	 *
	 * @var string
	 */
	private string $plugin_version;

	/**
	 * Security AJAX Handler instance
	 *
	 * @var SecurityAjaxHandler
	 */
	private SecurityAjaxHandler $ajax_handler;

	/**
	 * Security Data Provider instance
	 *
	 * @var SecurityDataProvider
	 */
	private SecurityDataProvider $data_provider;

	/**
	 * Statistics Provider instance
	 *
	 * @var StatisticsProvider
	 */
	private StatisticsProvider $stats_provider;

	/**
	 * Admin Page Renderer instance
	 *
	 * @var AdminPageRenderer
	 */
	private AdminPageRenderer $page_renderer;

	/**
	 * Settings Handler instance
	 *
	 * @var SettingsHandler
	 */
	private SettingsHandler $settings_handler;

	/**
	 * Contact Form 7 AJAX Handler instance
	 *
	 * @var ContactForm7AjaxHandler
	 */
	private ContactForm7AjaxHandler $cf7_ajax_handler;

	/**
	 * Asset Manager instance
	 *
	 * @var AssetManager
	 */
	private AssetManager $asset_manager;

	/**
	 * Constructor
	 *
	 * @since 1.1.1
	 */
	public function __construct() {
		$this->plugin_version = SILVER_ASSIST_SECURITY_VERSION;
		$this->config_manager = GraphQLConfigManager::getInstance();

		// Initialize data providers
		$this->data_provider  = new SecurityDataProvider();
		$this->stats_provider = new StatisticsProvider();

		// Initialize AJAX handler with dependencies
		$this->ajax_handler = new SecurityAjaxHandler( $this->data_provider, $this->stats_provider );

		// Initialize page renderer
		$this->page_renderer = new AdminPageRenderer( $this->config_manager, $this->data_provider );

		// Initialize settings handler
		$this->settings_handler = new SettingsHandler();

		// Initialize CF7 AJAX handler
		$this->cf7_ajax_handler = new ContactForm7AjaxHandler();

		// Initialize asset manager
		$this->asset_manager = new AssetManager( $this->plugin_version );

		$this->init();
	}

	/**
	 * Initialize admin panel
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init(): void {
		// Register with Settings Hub early (priority 4) to ensure hub processes it at priority 5
		\add_action( 'admin_menu', [ $this, 'register_with_hub' ], 4 );
		\add_action( 'admin_init', [ $this, 'register_settings' ] );
		\add_action( 'admin_init', [ $this, 'save_security_settings' ] );

		// Register asset management hook (delegated to AssetManager)
		\add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_scripts' ] );

		// Register only AdminPanel-specific AJAX handlers
		\add_action( 'wp_ajax_silver_assist_check_updates', [ $this, 'ajax_check_updates' ] );

		// Security and CF7 AJAX handlers register themselves via their constructors
	}

	/**
	 * Register plugin with Settings Hub or fallback to standalone menu
	 *
	 * @since 1.1.13
	 * @return void
	 */
	public function register_with_hub(): void {
		// Check if Settings Hub is available
		if ( ! \class_exists( SettingsHub::class ) ) {

			// Fallback to standalone menu when hub is not available
			$this->add_admin_menu();
			return;
		}

		// XDebug: Settings Hub available
		if ( \defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			SecurityHelper::log_security_event(
				'SETTINGS_HUB_REGISTRATION',
				'Settings Hub class found, proceeding with registration',
				[ 'hub_available' => true ]
			);
		}

		try {
			$hub = SettingsHub::get_instance();

			// Get actions array for plugin card
			$actions = $this->get_hub_actions();

			// Register plugin with hub
			$hub->register_plugin(
				'silver-assist-security',
				\__( 'Security', 'silver-assist-security' ),
				[ $this, 'render_admin_page' ],
				[
					'description' => \__( 'Security configuration for WordPress', 'silver-assist-security' ),
					'version'     => $this->plugin_version,
					'tab_title'   => \__( 'Security', 'silver-assist-security' ),
					'capability'  => 'manage_options',
					'actions'     => $actions,
				]
			);

		} catch ( Exception $e ) {

			// Log error and fallback to standalone menu
			SecurityHelper::log_security_event(
				'SETTINGS_HUB_ERROR',
				'Failed to register with Settings Hub: ' . $e->getMessage(),
				[ 'exception' => $e->getMessage() ]
			);
			$this->add_admin_menu();
		}
	}

	/**
	 * Get actions array for Settings Hub plugin card
	 *
	 * @since 1.1.13
	 * @return array Array of action configurations
	 */
	private function get_hub_actions(): array {
		$actions = [];

		// Add "Check Updates" button if updater is available
		$plugin = Plugin::getInstance();
		if ( $plugin->get_updater() ) {
			$actions[] = [
				'label'    => \__( 'Check Updates', 'silver-assist-security' ),
				'callback' => [ $this, 'render_update_check_script' ],
				'class'    => 'button button-primary',
			];
		}

		return $actions;
	}

	/**
	 * Add standalone admin menu (fallback when Settings Hub is not available)
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function add_admin_menu(): void {
		\add_options_page(
			\__( 'Silver Assist Security', 'silver-assist-security' ),
			\__( 'Security Essentials', 'silver-assist-security' ),
			'manage_options',
			'silver-assist-security',
			[ $this, 'render_admin_page' ]
		);
	}

	/**
	 * Register plugin settings
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function register_settings(): void {
		// Login Security Settings
		\register_setting( 'silver_assist_security_login', 'silver_assist_login_attempts' );
		\register_setting( 'silver_assist_security_login', 'silver_assist_lockout_duration' );
		\register_setting( 'silver_assist_security_login', 'silver_assist_session_timeout' );
		\register_setting( 'silver_assist_security_login', 'silver_assist_bot_protection' );

		// Admin Hide Settings
		\register_setting( 'silver_assist_security_admin_hide', 'silver_assist_admin_hide_enabled' );
		\register_setting( 'silver_assist_security_admin_hide', 'silver_assist_admin_hide_path' );

		// Password Settings
		\register_setting( 'silver_assist_security_password', 'silver_assist_password_strength_enforcement' );

		// GraphQL Settings
		\register_setting( 'silver_assist_security_graphql', 'silver_assist_graphql_headless_mode' );
		\register_setting( 'silver_assist_security_graphql', 'silver_assist_graphql_query_timeout' );
	}

	/**
	 * Render admin page
	 *
	 * Includes capability check for security and direct method calls (e.g., in tests).
	 * WordPress also checks via add_options_page() and Settings Hub, providing defense in depth.
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function render_admin_page(): void {
		// Delegate to AdminPageRenderer for cleaner separation of concerns
		$this->page_renderer->render();
	}

	/**
	 * Proxy method for settings save - delegates to SettingsHandler
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function save_security_settings(): void {
		$this->settings_handler->save_security_settings();
	}

	/**
	 * Render update check script for Settings Hub action button
	 *
	 * Loads external JavaScript file and echoes onclick handler that calls
	 * the global update check function. Settings Hub expects echo, not return.
	 *
	 * @since 1.1.13
	 * @param string $plugin_slug Plugin slug passed by Settings Hub
	 * @return void
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Parameter required by Settings Hub callback signature
	public function render_update_check_script( string $plugin_slug = '' ): void {
		$plugin  = Plugin::getInstance();
		$updater = $plugin->get_updater();

		if ( ! $updater ) {
			return;
		}

		// Enqueue update check script
		\wp_enqueue_script(
			'silver-assist-update-check',
			SecurityHelper::get_asset_url( 'assets/js/update-check.js' ),
			[ 'jquery' ],
			$this->plugin_version,
			true
		);

		// Localize script with configuration data
		\wp_localize_script(
			'silver-assist-update-check',
			'silverAssistUpdateCheck',
			[
				'ajaxurl'   => \admin_url( 'admin-ajax.php' ),
				'nonce'     => \wp_create_nonce( 'silver_assist_security_updates_nonce' ),
				'updateUrl' => \admin_url( 'update-core.php' ),
				'strings'   => [
					'updateAvailable' => \__( 'Update available! Redirecting to Updates page...', 'silver-assist-security' ),
					'upToDate'        => \__( "You're up to date!", 'silver-assist-security' ),
					'checkError'      => \__( 'Error checking updates. Please try again.', 'silver-assist-security' ),
					'connectError'    => \__( 'Error connecting to update server.', 'silver-assist-security' ),
				],
			]
		);

		// Echo JavaScript that will be injected by Settings Hub into the event listener
		echo 'silverAssistCheckUpdates(); return false;';
	}

	/**
	 * AJAX handler for checking plugin updates
	 *
	 * Validates nonce, checks for updates using wp-github-updater,
	 * and returns update status information.
	 *
	 * @since 1.1.13
	 * @return void
	 */
	public function ajax_check_updates(): void {
		// Validate nonce
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verification doesn't require sanitization
		if ( ! isset( $_POST['nonce'] ) || ! \wp_verify_nonce( \wp_unslash( $_POST['nonce'] ), 'silver_assist_security_updates_nonce' ) ) {
			\wp_send_json_error( [ 'message' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		// Check user capability
		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( [ 'message' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		$plugin  = Plugin::getInstance();
		$updater = $plugin->get_updater();

		if ( ! $updater ) {
			\wp_send_json_error( [ 'message' => \__( 'Updater not available', 'silver-assist-security' ) ] );
		}

		try {
			// Clear cached version to force fresh check from GitHub
			$transient_key = 'silver-assist-security_version_check';
			\delete_transient( $transient_key );

			// CRITICAL: Clear WordPress update cache to force refresh
			// This is required for WordPress to detect the update on the Updates page
			\delete_site_transient( 'update_plugins' );

			// Force WordPress to check for updates immediately
			\wp_update_plugins();

			$update_available = $updater->isUpdateAvailable();
			$current_version  = $updater->getCurrentVersion();
			$latest_version   = $updater->getLatestVersion();

			\wp_send_json_success(
				[
					'update_available' => $update_available,
					'current_version'  => $current_version,
					'latest_version'   => $latest_version,
					'message'          => $update_available
						? \__( 'Update available!', 'silver-assist-security' )
						: \__( "You're up to date!", 'silver-assist-security' ),
				]
			);
		} catch ( Exception $e ) {
			SecurityHelper::log_security_event(
				'UPDATE_CHECK_ERROR',
				'Failed to check for updates: ' . $e->getMessage(),
				[ 'exception' => $e->getMessage() ]
			);

			\wp_send_json_error(
				[
					'message' => \__( 'Error checking for updates', 'silver-assist-security' ),
				]
			);
		}
	}

	/**
	 * Get list of forbidden admin path keywords
	 *
	 * @since 1.1.4
	 * @return array<string> List of forbidden path keywords
	 */
	public function get_forbidden_admin_paths(): array {
		return PathValidator::get_forbidden_paths();
	}

	/**
	 * Asset management proxy method - delegates to AssetManager
	 *
	 * @since 1.1.15
	 * @param string $hook_suffix Current admin page hook suffix
	 * @return void
	 */
	public function enqueue_admin_scripts( string $hook_suffix ): void {
		$this->asset_manager->enqueue_admin_scripts( $hook_suffix );
	}
}
