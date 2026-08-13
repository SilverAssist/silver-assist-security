<?php
/**
 * Silver Assist Security Suite - Core Plugin Controller
 *
 * Root plugin bootstrap, loaded on "init". Two earlier-loading sibling
 * loaders — SecurityLoader (plugins_loaded priority 1) and
 * GraphQLLoader (plugins_loaded priority 5) — cover the components that
 * need to register their hooks before "init"; see those classes for why.
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.5.1
 */

namespace SilverAssist\Security\Core;

use SilverAssist\PluginKernel\AbstractPlugin;
use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Security\LoginBranding;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\RestAPISecurity;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

/**
 * Main Plugin class
 *
 * Singleton access (instance()) and the priority-ordered component loading
 * loop are inherited from AbstractPlugin (silverassist/wp-plugin-kernel) —
 * this class only declares which "init"-tier components to load
 * (get_components()) and the plugin-specific setup that runs alongside
 * them (init_hooks()).
 *
 * @since 1.1.1
 */
class Plugin extends AbstractPlugin {

	/**
	 * Updater instance
	 *
	 * @var Updater|null
	 */
	private ?Updater $updater = null;

	// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- Deprecated camelCase alias kept for backward compatibility; see instance().
	/**
	 * Deprecated alias for instance()
	 *
	 * Kept for backward compatibility: this is a public accessor on a project
	 * that follows Semantic Versioning, so renaming it without a compatibility
	 * shim would break external code calling Plugin::get_instance()/getInstance()
	 * directly.
	 *
	 * @deprecated 1.5.1 Use instance() instead.
	 * @since 1.1.1
	 * @return self
	 */
	public static function get_instance(): self {
		return self::instance();
	}

	// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- Deprecated camelCase alias kept for backward compatibility; see instance().
	/**
	 * Deprecated alias for instance()
	 *
	 * @deprecated 1.5.1 Use instance() instead.
	 * @since 1.1.1
	 * @return self
	 */
	public static function getInstance(): self {
		return self::instance();
	}

	/**
	 * List the "init"-tier component classes this plugin loads
	 *
	 * LoginSecurity, GeneralSecurity, RestAPISecurity, LoginBranding, and
	 * AdminHideSecurity load earlier, via SecurityLoader (plugins_loaded
	 * priority 1). GraphQLSecurity loads via GraphQLLoader (plugins_loaded
	 * priority 5). See those classes for why.
	 *
	 * @since 1.5.1
	 * @return array<class-string>
	 */
	protected function get_components(): array {
		return array(
			AdminPanel::class,
			ContactForm7Integration::class,
		);
	}

	/**
	 * Plugin-level setup that isn't itself a LoadableInterface component
	 *
	 * Runs after this tier's components have loaded.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	protected function init_hooks(): void {
		$this->load_textdomain();
		$this->init_updater();

		// Initialize the IP cleanup cron system.
		IPBlacklist::init_cron_cleanup();

		// Add plugin action links.
		\add_filter( 'plugin_action_links_' . SILVER_ASSIST_SECURITY_BASENAME, array( $this, 'add_action_links' ) );
	}

	/**
	 * Load plugin textdomain for translations
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function load_textdomain(): void {
		// Default languages directory for silver-assist-security.
		$lang_dir = SILVER_ASSIST_SECURITY_PATH . '/languages/';

		/**
		 * Filters the languages directory path for Silver Assist Security
		 *
		 * @param string $lang_dir The languages directory path
		 * @since 1.1.1
		 */
		$lang_dir = \apply_filters( 'silver_assist_security_languages_directory', $lang_dir );

		// Get user locale (WordPress 6.5+ always has get_user_locale).
		$get_locale = \get_user_locale();

		/**
		 * Language locale filter for Silver Assist Security
		 *
		 * @param string $get_locale The locale to use with get_user_locale()
		 * @param string $domain     The text domain
		 * @since 1.1.1
		 */
		$locale = \apply_filters( 'plugin_locale', $get_locale, 'silver-assist-security' );
		$mofile = sprintf( '%1$s-%2$s.mo', 'silver-assist-security', $locale );

		// Setup paths to current locale file.
		$mofile_local  = "{$lang_dir}{$mofile}";
		$mofile_global = WP_LANG_DIR . '/silver-assist-security/' . $mofile;

		if ( file_exists( $mofile_global ) ) {
			// Look in global /wp-content/languages/silver-assist-security/ folder first.
			\load_textdomain( 'silver-assist-security', $mofile_global );
		} elseif ( file_exists( $mofile_local ) ) {
			// Look in local /wp-content/plugins/silver-assist-security/languages/ folder.
			\load_textdomain( 'silver-assist-security', $mofile_local );
		} else {
			// Load the default language files as fallback.
			\load_plugin_textdomain( 'silver-assist-security', false, dirname( plugin_basename( SILVER_ASSIST_SECURITY_PATH . '/silver-assist-security.php' ) ) . '/languages' );
		}
	}

	/**
	 * Initialize updater
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init_updater(): void {
		$this->updater = new Updater(
			SILVER_ASSIST_SECURITY_PATH . 'silver-assist-security.php',
			'SilverAssist/silver-assist-security'
		);
	}

	/**
	 * Add plugin action links
	 *
	 * @since 1.1.1
	 * @param array $links Existing action links.
	 * @return array Modified action links
	 */
	public function add_action_links( array $links ): array {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			\admin_url( 'admin.php?page=silver-assist-security' ),
			\__( 'Settings', 'silver-assist-security' )
		);

		array_unshift( $links, $settings_link );

		return $links;
	}

	/**
	 * Get admin panel instance
	 *
	 * Preserves the pre-kernel null-outside-admin contract: AdminPanel only
	 * ever loaded (and its hooks registered) on admin requests.
	 *
	 * @since 1.1.1
	 * @return AdminPanel|null
	 */
	public function get_admin_panel(): ?AdminPanel {
		return AdminPanel::instance()->should_load() ? AdminPanel::instance() : null;
	}

	/**
	 * Get login security instance
	 *
	 * @since 1.1.1
	 * @return LoginSecurity|null
	 */
	public function get_login_security(): ?LoginSecurity {
		return LoginSecurity::instance();
	}

	/**
	 * Get login branding instance
	 *
	 * @since 1.4.0
	 * @return LoginBranding|null
	 */
	public function get_login_branding(): ?LoginBranding {
		return LoginBranding::instance()->should_load() ? LoginBranding::instance() : null;
	}

	/**
	 * Get general security instance
	 *
	 * @since 1.1.1
	 * @return GeneralSecurity|null
	 */
	public function get_general_security(): ?GeneralSecurity {
		return GeneralSecurity::instance();
	}

	/**
	 * Get REST API security instance
	 *
	 * @since 1.5.0
	 * @return RestAPISecurity|null
	 */
	public function get_rest_api_security(): ?RestAPISecurity {
		return RestAPISecurity::instance()->should_load() ? RestAPISecurity::instance() : null;
	}

	/**
	 * Get GraphQL security instance
	 *
	 * @since 1.1.1
	 * @return GraphQLSecurity|null
	 */
	public function get_graphql_security(): ?GraphQLSecurity {
		return GraphQLSecurity::instance()->should_load() ? GraphQLSecurity::instance() : null;
	}

	/**
	 * Get updater instance
	 *
	 * @since 1.1.1
	 * @return Updater|null
	 */
	public function get_updater(): ?Updater {
		return $this->updater;
	}

	/**
	 * Get Contact Form 7 integration instance
	 *
	 * @since 1.1.15
	 * @return ContactForm7Integration|null
	 */
	public function get_cf7_integration(): ?ContactForm7Integration {
		return ContactForm7Integration::instance()->should_load() ? ContactForm7Integration::instance() : null;
	}

	/**
	 * Check if Contact Form 7 integration is active
	 *
	 * @since 1.1.15
	 * @return bool True if CF7 integration is active
	 */
	public function is_cf7_integration_active(): bool {
		return ContactForm7Integration::instance()->should_load();
	}
}
