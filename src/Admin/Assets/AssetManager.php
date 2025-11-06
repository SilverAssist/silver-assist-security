<?php
/**
 * Silver Assist Security Essentials - Asset Manager
 *
 * Centralized management for admin assets including CSS, JavaScript,
 * and localization. Extracted from AdminPanel.php for better separation
 * of concerns and maintainability.
 *
 * @package SilverAssist\Security\Admin\Assets
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Assets;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Asset Manager Class
 *
 * Handles enqueuing and localization of admin assets for the security plugin.
 *
 * @since 1.1.15
 */
class AssetManager {

	/**
	 * GraphQL Configuration Manager instance
	 *
	 * @var GraphQLConfigManager
	 * @since 1.1.15
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Plugin version for cache busting
	 *
	 * @var string
	 * @since 1.1.15
	 */
	private string $plugin_version;

	/**
	 * Initialize asset manager
	 *
	 * @since 1.1.15
	 * @param string $plugin_version Plugin version for cache busting
	 */
	public function __construct( string $plugin_version ) {
		$this->config_manager = GraphQLConfigManager::getInstance();
		$this->plugin_version = $plugin_version;
	}

	/**
	 * Initialize asset management hooks
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function init(): void {
		\add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );
	}

	/**
	 * Enqueue admin scripts and styles
	 *
	 * @since 1.1.15
	 * @param string $hook_suffix Current admin page hook suffix
	 * @return void
	 */
	public function enqueue_admin_scripts( string $hook_suffix ): void {
		// Allow loading on both standalone menu and Settings Hub submenu
		// Settings Hub uses: "silver-assist_page_silver-assist-security"
		// Standalone menu uses: "settings_page_silver-assist-security"
		$allowed_hooks = array(
			'settings_page_silver-assist-security',        // Standalone fallback menu
			'silver-assist_page_silver-assist-security',   // Settings Hub submenu
			'toplevel_page_silver-assist-security',         // Direct top-level (if ever used)
		);

		if ( ! \in_array( $hook_suffix, $allowed_hooks, true ) ) {
			return;
		}

		$this->enqueue_styles();
		$this->enqueue_scripts();
		$this->localize_scripts();
	}

	/**
	 * Enqueue admin styles
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function enqueue_styles(): void {
		\wp_enqueue_style(
			'silver-assist-variables',
			SecurityHelper::get_asset_url( 'assets/css/variables.css' ),
			array(),
			$this->plugin_version
		);

		\wp_enqueue_style(
			'silver-assist-security-admin',
			SecurityHelper::get_asset_url( 'assets/css/admin.css' ),
			array( 'silver-assist-variables' ),
			$this->plugin_version
		);
	}

	/**
	 * Enqueue admin JavaScript files
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function enqueue_scripts(): void {
		\wp_enqueue_script(
			'silver-assist-security-admin',
			SecurityHelper::get_asset_url( 'assets/js/admin.js' ),
			array( 'jquery' ),
			$this->plugin_version,
			true
		);
	}

	/**
	 * Localize scripts with translations and configuration data
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function localize_scripts(): void {
		\wp_localize_script(
			'silver-assist-security-admin',
			'silverAssistSecurity',
			array(
				'ajaxurl'             => \admin_url( 'admin-ajax.php' ),
				'admin_url'           => \admin_url( '' ),
				'nonce'               => \wp_create_nonce( 'silver_assist_security_ajax' ),
				'logout_nonce'        => \wp_create_nonce( 'log-out' ),
				'refreshInterval'     => 30000, // 30 seconds
				'phpExecutionTimeout' => $this->config_manager->get_php_execution_timeout(),
				'strings'             => $this->get_localized_strings(),
			)
		);
	}

	/**
	 * Get all localized strings for JavaScript
	 *
	 * @since 1.1.15
	 * @return array Localized strings array
	 */
	private function get_localized_strings(): array {
		return array(
			'loading'                => \__( 'Loading...', 'silver-assist-security' ),
			'error'                  => \__( 'Error loading data', 'silver-assist-security' ),
			'lastUpdated'            => \__( 'Last updated:', 'silver-assist-security' ),
			'noThreats'              => \__( 'No active threats detected', 'silver-assist-security' ),
			'refreshing'             => \__( 'Refreshing...', 'silver-assist-security' ),
			'updateUrl'              => \admin_url( 'update-core.php' ),
			// Version check strings
			'newVersionAvailable'    =>
				/* translators: %s: new version number */
				\__( 'New version %s available.', 'silver-assist-security' ),
			'updateNow'              => \__( 'Update now', 'silver-assist-security' ),
			'checking'               => \__( 'Checking...', 'silver-assist-security' ),
			'newVersionFound'        =>
				/* translators: %1$s: new version number, %2$s: current version number */
				\__( "New version available: %1\$s\\nCurrent version: %2\$s", 'silver-assist-security' ),
			'upToDate'               =>
				/* translators: %s: current version number */
				\__( 'The plugin is up to date with the latest version (%s)', 'silver-assist-security' ),
			'checkError'             => \__( 'Error checking for updates:', 'silver-assist-security' ),
			'unknownError'           => \__( 'Unknown error', 'silver-assist-security' ),
			'connectivityError'      => \__( 'Connectivity error while checking for updates', 'silver-assist-security' ),
			// Form validation error strings
			'loginAttemptsError'     => \__( 'Login attempts must be between 1 and 20', 'silver-assist-security' ),
			'lockoutDurationError'   => \__( 'Lockout duration must be between 60 and 3600 seconds', 'silver-assist-security' ),
			'sessionTimeoutError'    => \__( 'Session timeout must be between 5 and 120 minutes', 'silver-assist-security' ),
			'graphqlDepthError'      => \__( 'GraphQL query depth must be between 1 and 20', 'silver-assist-security' ),
			'graphqlComplexityError' => \__( 'GraphQL query complexity must be between 10 and 1000', 'silver-assist-security' ),
			'graphqlTimeoutError'    => \sprintf(
				/* translators: %d: maximum timeout in seconds based on PHP limit */
				\__( 'GraphQL query timeout must be between 1 and %d seconds (PHP limit)', 'silver-assist-security' ),
				$this->config_manager->get_php_execution_timeout()
			),
			'customUrlPatternError'  => \__( 'Custom admin URL must contain only lowercase letters, numbers, and hyphens (3-30 characters)', 'silver-assist-security' ),
			'urlPatternError'        => \__( 'Use only lowercase letters, numbers, and hyphens (3-30 characters)', 'silver-assist-security' ),
			// Admin path validation strings
			'pathValidating'         => \__( 'Validating...', 'silver-assist-security' ),
			'pathValid'              => \__( '✓ Path is valid', 'silver-assist-security' ),
			'pathTooShort'           => \__( 'Path must be at least 3 characters long', 'silver-assist-security' ),
			'pathTooLong'            => \__( 'Path must be 50 characters or less', 'silver-assist-security' ),
			'pathForbidden'          => \__( 'This path contains forbidden keywords', 'silver-assist-security' ),
			'pathInvalidChars'       => \__( 'Path can only contain letters, numbers, hyphens, and underscores', 'silver-assist-security' ),
			'pathEmpty'              => \__( 'Path cannot be empty', 'silver-assist-security' ),
			// Auto-save strings
			'saving'                 => \__( 'Saving...', 'silver-assist-security' ),
			'saved'                  => \__( 'Saved!', 'silver-assist-security' ),
			'saveFailed'             => \__( 'Save failed', 'silver-assist-security' ),
			// AJAX error strings
			'updateCheckFailed'      => \__( 'Failed to check for Silver Assist updates', 'silver-assist-security' ),
			'securityStatusFailed'   => \__( 'Failed to load security essentials', 'silver-assist-security' ),
			'loginStatsFailed'       => \__( 'Failed to load login stats', 'silver-assist-security' ),
			// Table headers
			'ipHash'                 => \__( 'IP Hash', 'silver-assist-security' ),
			'blockedTime'            => \__( 'Blocked Time', 'silver-assist-security' ),
			'remaining'              => \__( 'Remaining', 'silver-assist-security' ),
			'minutes'                => \__( 'min', 'silver-assist-security' ),
			// Dashboard dynamic values
			'enabled'                => \__( 'Enabled', 'silver-assist-security' ),
			'disabled'               => \__( 'Disabled', 'silver-assist-security' ),
			'headlessCms'            => \__( 'Headless CMS', 'silver-assist-security' ),
			'standard'               => \__( 'Standard', 'silver-assist-security' ),
		);
	}
}
