<?php
/**
 * Silver Assist Security Suite - Core Plugin Controller
 *
 * Main plugin controller that orchestrates all security components including
 * login security, GraphQL protection, general security features, and admin panel.
 * Implements singleton pattern for centralized management.
 *
 * @package SilverAssist\Security\Core
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.1.0
 */

namespace SilverAssist\Security\Core;

use SilverAssist\Security\Admin\AdminPanel;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Core\Updater;

/**
 * Main Plugin class
 * 
 * Handles plugin initialization and coordination between components
 * 
 * @since 1.0.0
 */
class Plugin
{

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
     * @since 1.0.0
     * @return Plugin
     */
    public static function getInstance(): Plugin
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Private constructor to enforce singleton pattern
     * 
     * @since 1.0.0
     */
    private function __construct()
    {
        $this->init();
    }

    /**
     * Initialize plugin components
     * 
     * @since 1.0.0
     * @return void
     */
    private function init(): void
    {
        // Load text domain for translations
        \add_action("init", [$this, "load_textdomain"]);

        // Initialize components
        $this->init_admin_panel();
        $this->init_security_components();
        $this->init_graphql_security();
        $this->init_updater();

        // Add plugin action links
        \add_filter("plugin_action_links_" . SILVER_ASSIST_SECURITY_BASENAME, [$this, "add_action_links"]);
    }

    /**
     * Load plugin text domain
     * 
     * @since 1.0.0
     * @return void
     */
    public function load_textdomain(): void
    {
        \load_plugin_textdomain(
            "silver-assist-security",
            false,
            dirname(SILVER_ASSIST_SECURITY_BASENAME) . "/languages"
        );
    }

    /**
     * Initialize admin panel
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_admin_panel(): void
    {
        if (\is_admin()) {
            $this->admin_panel = new AdminPanel();
        }
    }

    /**
     * Initialize security components
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_security_components(): void
    {
        $this->login_security = new LoginSecurity();
        $this->general_security = new GeneralSecurity();
    }

    /**
     * Initialize GraphQL security
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_graphql_security(): void
    {
        // Only initialize if WPGraphQL is active
        if (\class_exists("WPGraphQL")) {
            $this->graphql_security = new GraphQLSecurity();
        }
    }

    /**
     * Initialize updater
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_updater(): void
    {
        $this->updater = new Updater(
            SILVER_ASSIST_SECURITY_PATH . "silver-assist-security.php",
            "SilverAssist/silver-assist-security"
        );
    }

    /**
     * Add plugin action links
     * 
     * @since 1.0.0
     * @param array $links Existing action links
     * @return array Modified action links
     */
    public function add_action_links(array $links): array
    {
        $settings_link = sprintf(
            "<a href=\"%s\">%s</a>",
            \admin_url("admin.php?page=silver-assist-security"),
            \__("Settings", "silver-assist-security")
        );

        array_unshift($links, $settings_link);

        return $links;
    }

    /**
     * Get admin panel instance
     * 
     * @since 1.0.0
     * @return AdminPanel|null
     */
    public function get_admin_panel(): ?AdminPanel
    {
        return $this->admin_panel;
    }

    /**
     * Get login security instance
     * 
     * @since 1.0.0
     * @return LoginSecurity|null
     */
    public function get_login_security(): ?LoginSecurity
    {
        return $this->login_security;
    }

    /**
     * Get general security instance
     * 
     * @since 1.0.0
     * @return GeneralSecurity|null
     */
    public function get_general_security(): ?GeneralSecurity
    {
        return $this->general_security;
    }

    /**
     * Get GraphQL security instance
     * 
     * @since 1.0.0
     * @return GraphQLSecurity|null
     */
    public function get_graphql_security(): ?GraphQLSecurity
    {
        return $this->graphql_security;
    }

    /**
     * Get updater instance
     * 
     * @since 1.0.0
     * @return Updater|null
     */
    public function get_updater(): ?Updater
    {
        return $this->updater;
    }
}
