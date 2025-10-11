<?php
/**
 * Silver Assist Security Suite - Core Plugin Controller
 *
 * Main plugin controller that orchestrates all security components including
 * login security, GraphQL prot    ral security features, and admin panel.
 * Implements singleton pattern for centralized management.
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.13
 */

namespace SilverAssist\Security\Core;

use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Core\Updater;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Security\AdminHideSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\LoginSecurity;

/**
 * Main Plugin class
 *
 * Handles plugin initialization and coordination between components
 *
 * @since 1.1.1
 */
class Plugin {


	/**
	 * Plugin instance
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Admin panel instance
	 *
	 * @var AdminPanel|null
	 */
	private ?AdminPanel $admin_panel = null;

	/**
	 * Login security instance
	 *
	 * @var LoginSecurity|null
	 */
	private ?LoginSecurity $login_security = null;

	/**
	 * General security instance
	 *
	 * @var GeneralSecurity|null
	 */
	private ?GeneralSecurity $general_security = null;

	/**
	 * Admin hide security instance
	 *
	 * @var AdminHideSecurity|null
	 */
	private ?AdminHideSecurity $admin_hide_security = null;

	/**
	 * GraphQL security instance
	 *
	 * @var GraphQLSecurity|null
	 */
	private ?GraphQLSecurity $graphql_security = null;

	/**
	 * Updater instance
	 *
	 * @var Updater|null
	 */
	private ?Updater $updater = null;

	/**
	 * Get plugin instance (Singleton pattern)
	 *
	 * @since 1.1.1
	 * @return Plugin
	 */
	public static function getInstance(): Plugin {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Private constructor to enforce singleton pattern
	 *
	 * @since 1.1.1
	 */
	private function __construct() {
		// Initialize SecurityHelper first
		SecurityHelper::init();

		// Initialize security components early (before setup_theme)
		\add_action( 'plugins_loaded', array( $this, 'init_security_components' ), 1 );

		// Load text domain for translations (safe to call here since we're in init hook)
		\add_action( 'init', array( $this, 'load_textdomain' ) );

		// Initialize components
		\add_action( 'init', array( $this, 'init_admin_panel' ) );
		\add_action( 'init', array( $this, 'init_graphql_security' ) );
		\add_action( 'init', array( $this, 'init_updater' ) );

		// Add plugin action links
		\add_filter( 'plugin_action_links_' . SILVER_ASSIST_SECURITY_BASENAME, array( $this, 'add_action_links' ) );
	}

	/**
	 * Load plugin textdomain for translations
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function load_textdomain(): void {
		// Default languages directory for silver-assist-security
		$lang_dir = SILVER_ASSIST_SECURITY_PATH . '/languages/';

		/**
		 * Filters the languages directory path for Silver Assist Security
		 *
		 * @param string $lang_dir The languages directory path
		 * @since 1.1.1
		 */
		$lang_dir = \apply_filters( 'silver_assist_security_languages_directory', $lang_dir );

		// Get user locale (WordPress 6.5+ always has get_user_locale)
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

		// Setup paths to current locale file
		$mofile_local  = "{$lang_dir}{$mofile}";
		$mofile_global = WP_LANG_DIR . '/silver-assist-security/' . $mofile;

		if ( file_exists( $mofile_global ) ) {
			// Look in global /wp-content/languages/silver-assist-security/ folder first
			\load_textdomain( 'silver-assist-security', $mofile_global );
		} elseif ( file_exists( $mofile_local ) ) {
			// Look in local /wp-content/plugins/silver-assist-security/languages/ folder
			\load_textdomain( 'silver-assist-security', $mofile_local );
		} else {
			// Load the default language files as fallback
			\load_plugin_textdomain( 'silver-assist-security', false, dirname( plugin_basename( SILVER_ASSIST_SECURITY_PATH . '/silver-assist-security.php' ) ) . '/languages/' );
		}
	}

	/**
	 * Initialize admin panel
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function init_admin_panel(): void {
		if ( \is_admin() ) {
			$this->admin_panel = new AdminPanel();
		}
	}

	/**
	 * Initialize security components
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function init_security_components(): void {
		$this->login_security   = new LoginSecurity();
		$this->general_security = new GeneralSecurity();

		// Only initialize AdminHideSecurity if it's enabled
		$admin_hide_enabled = (bool) DefaultConfig::get_option( 'silver_assist_admin_hide_enabled' );
		if ( $admin_hide_enabled ) {
			$this->admin_hide_security = new AdminHideSecurity();
		}
	}

	/**
	 * Initialize GraphQL security
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function init_graphql_security(): void {
		// Only initialize if WPGraphQL is active
		if ( \class_exists( 'WPGraphQL' ) ) {
			$this->graphql_security = new GraphQLSecurity();
		}
	}

	/**
	 * Initialize updater
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function init_updater(): void {
		$this->updater = new Updater(
			SILVER_ASSIST_SECURITY_PATH . 'silver-assist-security.php',
			'SilverAssist/silver-assist-security'
		);
	}

	/**
	 * Add plugin action links
	 *
	 * @since 1.1.1
	 * @param array $links Existing action links
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
	 * @since 1.1.1
	 * @return AdminPanel|null
	 */
	public function get_admin_panel(): ?AdminPanel {
		return $this->admin_panel;
	}

	/**
	 * Get login security instance
	 *
	 * @since 1.1.1
	 * @return LoginSecurity|null
	 */
	public function get_login_security(): ?LoginSecurity {
		return $this->login_security;
	}

	/**
	 * Get general security instance
	 *
	 * @since 1.1.1
	 * @return GeneralSecurity|null
	 */
	public function get_general_security(): ?GeneralSecurity {
		return $this->general_security;
	}

	/**
	 * Get GraphQL security instance
	 *
	 * @since 1.1.1
	 * @return GraphQLSecurity|null
	 */
	public function get_graphql_security(): ?GraphQLSecurity {
		return $this->graphql_security;
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
}
