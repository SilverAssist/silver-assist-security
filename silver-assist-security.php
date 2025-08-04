<?php
/**
 * Plugin Name: Silver Assist Security Suite
 * Description: Comprehensive security suite for Silver Assist - includes login security, GraphQL protection, and admin configuration panel
 * Version: 1.0.0
 * Author: Silver Assist
 * Author URI: http://silverassist.com/
 * Text Domain: silver-assist-security
 * Domain Path: /languages
 * Requires PHP: 8.0
 * Requires at least: 6.5
 * Tested up to: 6.4
 * Network: false
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package SilverAssist\Security
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.0
 */

// Prevent direct access
if (!defined("ABSPATH")) {
    exit;
}

// Define plugin constants
define('SILVER_ASSIST_SECURITY_VERSION', '1.0.0');
define('SILVER_ASSIST_SECURITY_PATH', plugin_dir_path(__FILE__));
define('SILVER_ASSIST_SECURITY_URL', plugin_dir_url(__FILE__));
define('SILVER_ASSIST_SECURITY_BASENAME', plugin_basename(__FILE__));

/**
 * PSR-4 Autoloader for Silver Assist Security Suite
 * 
 * @param string $class The fully-qualified class name.
 * @return void
 */
spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = "SilverAssist\\Security\\";

    // Base directory for the namespace prefix
    $base_dir = SILVER_ASSIST_SECURITY_PATH . "src/";

    // Does the class use the namespace prefix?
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        // No, move to the next registered autoloader
        return;
    }

    // Get the relative class name
    $relative_class = substr($class, $len);

    // Replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir . str_replace("\\", "/", $relative_class) . ".php";

    // If the file exists, require it
    if (file_exists($file)) {
        require $file;
    }
});

use SilverAssist\Security\Core\Plugin;

/**
 * Main Plugin Bootstrap Class
 * 
 * Handles plugin initialization, activation, deactivation, and uninstall hooks
 * 
 * @since 1.0.0
 */
class SilverAssistSecurityBootstrap
{

    /**
     * Plugin instance
     * 
     * @var SilverAssistSecurityBootstrap|null
     */
    private static ?SilverAssistSecurityBootstrap $instance = null;

    /**
     * Default plugin options
     * 
     * @var array<string, mixed>
     */
    private array $default_options = [
        "silver_assist_login_attempts" => 5,
        "silver_assist_lockout_duration" => 900, // 15 minutes
        "silver_assist_session_timeout" => 30, // 30 minutes
        "silver_assist_password_reset_enforcement" => 1,
        "silver_assist_password_strength_enforcement" => 1,
        "silver_assist_admin_password_reset" => 0,
        "silver_assist_graphql_query_depth" => 8,
        "silver_assist_graphql_query_complexity" => 100,
        "silver_assist_graphql_query_timeout" => 5
    ];

    /**
     * Plugin options to remove on uninstall
     * 
     * @var array<string>
     */
    private array $plugin_options = [
        "silver_assist_login_attempts",
        "silver_assist_lockout_duration",
        "silver_assist_session_timeout",
        "silver_assist_password_reset_enforcement",
        "silver_assist_password_strength_enforcement",
        "silver_assist_admin_password_reset",
        "silver_assist_graphql_query_depth",
        "silver_assist_graphql_query_complexity",
        "silver_assist_graphql_query_timeout"
    ];

    /**
     * Constructor
     * 
     * @since 1.0.0
     */
    private function __construct()
    {
        $this->init_hooks();
    }

    /**
     * Get singleton instance
     * 
     * @since 1.0.0
     * @return SilverAssistSecurityBootstrap
     */
    public static function getInstance(): SilverAssistSecurityBootstrap
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Initialize WordPress hooks
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_hooks(): void
    {
        // Plugin lifecycle hooks
        register_activation_hook(__FILE__, [$this, "activate"]);
        register_deactivation_hook(__FILE__, [$this, "deactivate"]);
        register_uninstall_hook(__FILE__, [__CLASS__, "uninstall"]);

        // Initialize plugin
        add_action("plugins_loaded", [$this, "init_plugin"]);
    }

    /**
     * Initialize the Silver Assist Security Suite
     * 
     * @since 1.0.0
     * @return void
     */
    public function init_plugin(): void
    {
        try {
            // Initialize the main plugin class
            Plugin::getInstance();
        } catch (Exception $e) {
            // Log the error and show admin notice
            error_log("Silver Assist Security Suite initialization failed: " . $e->getMessage());

            add_action("admin_notices", function () use ($e) {
                echo "<div class=\"notice notice-error\"><p>";
                echo "<strong>Silver Assist Security Suite Error:</strong> " . esc_html($e->getMessage());
                echo "</p></div>";
            });
        }
    }

    /**
     * Plugin activation handler
     * 
     * @since 1.0.0
     * @return void
     */
    public function activate(): void
    {
        // Set default options
        foreach ($this->default_options as $option => $value) {
            if (get_option($option) === false) {
                add_option($option, $value);
            }
        }
    }

    /**
     * Plugin deactivation handler
     * 
     * @since 1.0.0
     * @return void
     */
    public function deactivate(): void
    {
        // Clean up transients and temporary data
        global $wpdb;

        // Clean up rate limiting transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_graphql_rate_limit_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_graphql_rate_limit_%'");
    }

    /**
     * Plugin uninstall handler
     * 
     * @since 1.0.0
     * @return void
     */
    public static function uninstall(): void
    {
        $instance = new self();

        // Remove all plugin options
        foreach ($instance->plugin_options as $option) {
            delete_option($option);
        }

        // Clean up any remaining transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_silver_assist_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_silver_assist_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_graphql_rate_limit_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_graphql_rate_limit_%'");
    }
}

// Initialize the plugin bootstrap
SilverAssistSecurityBootstrap::getInstance();
