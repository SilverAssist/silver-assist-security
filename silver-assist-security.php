<?php
/**
 * Plugin Name: Silver Assist Security Essentials
 * Plugin URI: https://github.com/SilverAssist/silver-assist-security
 * Description: Resolves critical security vulnerabilities: WordPress login protection, HTTPOnly cookie implementation, and comprehensive GraphQL security. Addresses security audit findings automatically.
 * Version: 1.1.12
 * Author: Silver Assist
 * Author URI: http://silverassist.com/
 * Text Domain: silver-assist-security
 * Domain Path: /languages
 * Requires PHP: 8.0
 * Requires at least: 6.5
 * Tested up to: 6.4
 * Network: false
 * License: Polyform Noncommercial License 1.0.0
 * License URI: https://polyformproject.org/licenses/noncommercial/1.0.0/
 *
 * @package SilverAssist\Security
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.12
 */

// Prevent direct access
if (!defined("ABSPATH")) {
    exit;
}

// Define plugin constants
define("SILVER_ASSIST_SECURITY_VERSION", "1.1.12");
define("SILVER_ASSIST_SECURITY_PATH", plugin_dir_path(__FILE__));
define("SILVER_ASSIST_SECURITY_URL", plugin_dir_url(__FILE__));
define("SILVER_ASSIST_SECURITY_BASENAME", plugin_basename(__FILE__));

// Load Composer autoloader for external dependencies
$composer_autoloader = SILVER_ASSIST_SECURITY_PATH . "vendor/autoload.php";
if (file_exists($composer_autoloader)) {
    require_once $composer_autoloader;
}

/**
 * PSR-4 Autoloader for Silver Assist Security Essentials
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
use SilverAssist\Security\Core\DefaultConfig;

/**
 * Main Plugin Bootstrap Class
 * 
 * Handles plugin initialization, activation, deactivation, and uninstall hooks
 * 
 * @since 1.1.1
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
     * Constructor
     * 
     * @since 1.1.1
     */
    private function __construct()
    {
        $this->init_hooks();
        $this->init_plugin();
    }

    /**
     * Get singleton instance
     * 
     * @since 1.1.1
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
     * @since 1.1.1
     * @return void
     */
    private function init_hooks(): void
    {
        // Plugin lifecycle hooks
        register_activation_hook(__FILE__, [$this, "activate"]);
        register_deactivation_hook(__FILE__, [$this, "deactivate"]);
        register_uninstall_hook(__FILE__, [__CLASS__, "uninstall"]);
    }

    /**
     * Initialize the Silver Assist Security Essentials
     * 
     * @since 1.1.1
     * @return void
     */
    public function init_plugin(): void
    {
        try {
            // Initialize the main plugin class
            Plugin::getInstance();
        } catch (Exception $e) {
            // Log the error and show admin notice
            error_log("Silver Assist Security Essentials initialization failed: {$e->getMessage()}");

            \add_action("admin_notices", function () use ($e) {
                echo "<div class=\"notice notice-error\"><p>";
                echo "<strong>Silver Assist Security Essentials Error:</strong> " . esc_html($e->getMessage());
                echo "</p></div>";
            });
        }
    }

    /**
     * Plugin activation handler
     * 
     * @since 1.1.1
     * @return void
     */
    public function activate(): void
    {
        // Set default options using centralized configuration
        foreach (DefaultConfig::get_defaults() as $option => $value) {
            if (\get_option($option) === false) {
                \add_option($option, $value);
            }
        }

        // Initialize last_activity for all currently logged-in users
        // This prevents immediate logout after plugin activation
        $this->initialize_user_last_activity();

        // Flush rewrite rules to ensure custom admin URL routing works properly
        \flush_rewrite_rules();
    }

    /**
     * Initialize last_activity for all currently logged-in users
     * 
     * This prevents immediate logout after plugin activation by setting
     * last_activity timestamp for users who are currently logged in.
     * 
     * @since 1.1.1
     * @return void
     */
    private function initialize_user_last_activity(): void
    {
        // Get all currently logged-in users by checking for active sessions
        $current_time = time();

        // Query for users who have WordPress sessions (simplified check)
        $users = \get_users([
            "meta_query" => [
                [
                    "key" => "session_tokens",
                    "compare" => "EXISTS"
                ]
            ]
        ]);

        // Initialize last_activity for each logged-in user
        foreach ($users as $user) {
            $existing_activity = \get_user_meta($user->ID, "last_activity", true);

            // Only set if not already set to avoid overwriting existing data
            if (empty($existing_activity)) {
                \update_user_meta($user->ID, "last_activity", $current_time);
            }
        }
    }

    /**
     * Plugin deactivation handler
     * 
     * @since 1.1.1
     * @return void
     */
    public function deactivate(): void
    {
        // Clean up transients and temporary data
        global $wpdb;

        // Clean up rate limiting transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_graphql_rate_limit_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_graphql_rate_limit_%'");

        // Flush rewrite rules to clean up custom admin URL routing
        \flush_rewrite_rules();
    }

    /**
     * Plugin uninstall handler
     * 
     * @since 1.1.1
     * @return void
     */
    public static function uninstall(): void
    {
        // Remove all plugin options using centralized configuration
        foreach (array_keys(DefaultConfig::get_defaults()) as $option) {
            \delete_option($option);
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
