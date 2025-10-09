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
 * @version 1.1.12
 */

namespace SilverAssist\Security\Admin;

use Exception;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\SettingsHub\SettingsHub;

/**
 * Admin Panel class
 * 
 * Handles the WordPress admin interface for security configuration
 * 
 * @since 1.1.1
 */
class AdminPanel
{
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
     * Constructor
     * 
     * @since 1.1.1
     */
    public function __construct()
    {
        $this->plugin_version = SILVER_ASSIST_SECURITY_VERSION;
        $this->config_manager = GraphQLConfigManager::getInstance();
        $this->init();
    }

    /**
     * Initialize admin panel
     * 
     * @since 1.1.1
     * @return void
     */
    private function init(): void
    {
        \add_action("admin_menu", [$this, "register_with_hub"]);
        \add_action("admin_init", [$this, "register_settings"]);
        \add_action("admin_init", [$this, "save_security_settings"]);
        \add_action("admin_enqueue_scripts", [$this, "enqueue_admin_scripts"]);

        // AJAX endpoints for real-time status
        \add_action("wp_ajax_silver_assist_get_security_status", [$this, "ajax_get_security_status"]);
        \add_action("wp_ajax_silver_assist_get_login_stats", [$this, "ajax_get_login_stats"]);
        \add_action("wp_ajax_silver_assist_get_blocked_ips", [$this, "ajax_get_blocked_ips"]);
        \add_action("wp_ajax_silver_assist_get_security_logs", [$this, "ajax_get_security_logs"]);
        \add_action("wp_ajax_silver_assist_auto_save", [$this, "ajax_auto_save"]);
        \add_action("wp_ajax_silver_assist_validate_admin_path", [$this, "ajax_validate_admin_path"]);
        \add_action("wp_ajax_silver_assist_check_updates", [$this, "ajax_check_updates"]);
    }

    /**
     * Register plugin with Settings Hub or fallback to standalone menu
     * 
     * @since 1.1.13
     * @return void
     */
    public function register_with_hub(): void
    {
        // Check if Settings Hub is available
        if (!\class_exists(SettingsHub::class)) {
            // Fallback to standalone menu when hub is not available
            $this->add_admin_menu();
            return;
        }

        try {
            $hub = SettingsHub::get_instance();
            
            // Get actions array for plugin card
            $actions = $this->get_hub_actions();
            
            // Register plugin with hub
            $hub->register_plugin(
                "silver-assist-security",
                \__("Security", "silver-assist-security"),
                [$this, "render_admin_page"],
                [
                    "description" => \__("Security configuration for WordPress", "silver-assist-security"),
                    "version" => $this->plugin_version,
                    "tab_title" => \__("Security", "silver-assist-security"),
                    "actions" => $actions,
                ]
            );
        } catch (Exception $e) {
            // Log error and fallback to standalone menu
            SecurityHelper::log_security_event(
                "SETTINGS_HUB_ERROR",
                "Failed to register with Settings Hub: " . $e->getMessage(),
                ["exception" => $e->getMessage()]
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
    private function get_hub_actions(): array
    {
        $actions = [];
        
        // Add "Check Updates" button if updater is available
        $plugin = Plugin::getInstance();
        if ($plugin->get_updater()) {
            $actions[] = [
                "label" => \__("Check Updates", "silver-assist-security"),
                "callback" => [$this, "render_update_check_script"],
                "class" => "button button-primary",
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
    private function add_admin_menu(): void
    {
        \add_options_page(
            \__("Silver Assist Security", "silver-assist-security"),
            \__("Security Essentials", "silver-assist-security"),
            "manage_options",
            "silver-assist-security",
            [$this, "render_admin_page"]
        );
    }

    /**
     * Register plugin settings
     * 
     * @since 1.1.1
     * @return void
     */
    public function register_settings(): void
    {
        // Login Security Settings
        \register_setting("silver_assist_security_login", "silver_assist_login_attempts");
        \register_setting("silver_assist_security_login", "silver_assist_lockout_duration");
        \register_setting("silver_assist_security_login", "silver_assist_session_timeout");
        \register_setting("silver_assist_security_login", "silver_assist_bot_protection");

        // Admin Hide Settings
        \register_setting("silver_assist_security_admin_hide", "silver_assist_admin_hide_enabled");
        \register_setting("silver_assist_security_admin_hide", "silver_assist_admin_hide_path");

        // Password Settings
        \register_setting("silver_assist_security_password", "silver_assist_password_strength_enforcement");

        // GraphQL Settings
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_headless_mode");
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_timeout");
    }

    /**
     * Get asset URL with minification support
     * 
     * Returns minified version when SCRIPT_DEBUG is not true, regular version otherwise.
     * 
     * @since 1.1.10
     * @param string $asset_path The relative path to the asset (e.g., 'assets/css/admin.css')
     * @return string The full URL to the asset
     */
    private function get_asset_url(string $asset_path): string
    {
        return SecurityHelper::get_asset_url($asset_path);
    }

    /**
     * Enqueue admin scripts and styles
     * 
     * @since 1.1.1
     * @param string $hook_suffix Current admin page hook suffix
     * @return void
     */
    public function enqueue_admin_scripts(string $hook_suffix): void
    {
        if ($hook_suffix !== "settings_page_silver-assist-security") {
            return;
        }

        \wp_enqueue_style(
            "silver-assist-variables",
            $this->get_asset_url("assets/css/variables.css"),
            [],
            $this->plugin_version
        );

        \wp_enqueue_style(
            "silver-assist-security-admin",
            $this->get_asset_url("assets/css/admin.css"),
            ["silver-assist-variables"],
            $this->plugin_version
        );

        \wp_enqueue_script(
            "silver-assist-security-admin",
            $this->get_asset_url("assets/js/admin.js"),
            ["jquery"],
            $this->plugin_version,
            true
        );

        // Localize script for AJAX
        \wp_localize_script("silver-assist-security-admin", "silverAssistSecurity", [
            "ajaxurl" => \admin_url("admin-ajax.php"),
            "admin_url" => \admin_url(""),
            "nonce" => \wp_create_nonce("silver_assist_security_ajax"),
            "logout_nonce" => \wp_create_nonce("log-out"),
            "refreshInterval" => 30000, // 30 seconds
            "phpExecutionTimeout" => $this->config_manager->get_php_execution_timeout(),
            "strings" => [
                "loading" => __("Loading...", "silver-assist-security"),
                "error" => __("Error loading data", "silver-assist-security"),
                "lastUpdated" => __("Last updated:", "silver-assist-security"),
                "noThreats" => __("No active threats detected", "silver-assist-security"),
                "refreshing" => __("Refreshing...", "silver-assist-security"),
                "updateUrl" => \admin_url("update-core.php"),
                // Version check strings
                "newVersionAvailable" =>
                    /* translators: %s: new version number */
                    __("New version %s available.", "silver-assist-security"),
                "updateNow" => __("Update now", "silver-assist-security"),
                "checking" => __("Checking...", "silver-assist-security"),
                "newVersionFound" =>
                    /* translators: %1$s: new version number, %2$s: current version number */
                    __("New version available: %1\$s\\nCurrent version: %2\$s", "silver-assist-security"),
                "upToDate" =>
                    /* translators: %s: current version number */
                    __("The plugin is up to date with the latest version (%s)", "silver-assist-security"),
                "checkError" => __("Error checking for updates:", "silver-assist-security"),
                "unknownError" => __("Unknown error", "silver-assist-security"),
                "connectivityError" => __("Connectivity error while checking for updates", "silver-assist-security"),
                // Form validation error strings
                "loginAttemptsError" => __("Login attempts must be between 1 and 20", "silver-assist-security"),
                "lockoutDurationError" => __("Lockout duration must be between 60 and 3600 seconds", "silver-assist-security"),
                "sessionTimeoutError" => __("Session timeout must be between 5 and 120 minutes", "silver-assist-security"),
                "graphqlDepthError" => __("GraphQL query depth must be between 1 and 20", "silver-assist-security"),
                "graphqlComplexityError" => __("GraphQL query complexity must be between 10 and 1000", "silver-assist-security"),
                "graphqlTimeoutError" => sprintf(
                    /* translators: %d: maximum timeout in seconds based on PHP limit */
                    __("GraphQL query timeout must be between 1 and %d seconds (PHP limit)", "silver-assist-security"),
                    $this->config_manager->get_php_execution_timeout()
                ),
                "customUrlPatternError" => __("Custom admin URL must contain only lowercase letters, numbers, and hyphens (3-30 characters)", "silver-assist-security"),
                "urlPatternError" => __("Use only lowercase letters, numbers, and hyphens (3-30 characters)", "silver-assist-security"),
                // Admin path validation strings
                "pathValidating" => __("Validating...", "silver-assist-security"),
                "pathValid" => __("✓ Path is valid", "silver-assist-security"),
                "pathTooShort" => __("Path must be at least 3 characters long", "silver-assist-security"),
                "pathTooLong" => __("Path must be 50 characters or less", "silver-assist-security"),
                "pathForbidden" => __("This path contains forbidden keywords", "silver-assist-security"),
                "pathInvalidChars" => __("Path can only contain letters, numbers, hyphens, and underscores", "silver-assist-security"),
                "pathEmpty" => __("Path cannot be empty", "silver-assist-security"),
                // Auto-save strings
                "saving" => __("Saving...", "silver-assist-security"),
                "saved" => __("Saved!", "silver-assist-security"),
                "saveFailed" => __("Save failed", "silver-assist-security"),
                // AJAX error strings
                "updateCheckFailed" => __("Failed to check for Silver Assist updates", "silver-assist-security"),
                "securityStatusFailed" => __("Failed to load security essentials", "silver-assist-security"),
                "loginStatsFailed" => __("Failed to load login stats", "silver-assist-security"),
                // Table headers
                "ipHash" => __("IP Hash", "silver-assist-security"),
                "blockedTime" => __("Blocked Time", "silver-assist-security"),
                "remaining" => __("Remaining", "silver-assist-security"),
                "minutes" => __("min", "silver-assist-security"),
                // Dashboard dynamic values
                "enabled" => __("Enabled", "silver-assist-security"),
                "disabled" => __("Disabled", "silver-assist-security"),
                "headlessCms" => __("Headless CMS", "silver-assist-security"),
                "standard" => __("Standard", "silver-assist-security"),
            ]
        ]);
    }

    /**
     * AJAX handler for security status
     * 
     * @since 1.1.1
     * @return void
     */
    public function ajax_get_security_status(): void
    {
        try {
            // Use centralized AJAX validation
            if (!SecurityHelper::validate_ajax_request("silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security validation failed"]);
                return;
            }

            $status = $this->get_security_status();
            \wp_send_json_success($status);

        } catch (Exception $e) {
            SecurityHelper::log_security_event(
                "AJAX_ERROR",
                "Security status AJAX error: " . $e->getMessage(),
                ["function" => "ajax_get_security_status"]
            );
            
            \wp_send_json_error([
                "message" => "Error loading security status",
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for login statistics
     * 
     * @since 1.1.1
     * @return void
     */
    public function ajax_get_login_stats(): void
    {
        try {
            // Verify nonce
            if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security check failed"]);
                return;
            }

            // Check user permissions
            if (!\current_user_can("manage_options")) {
                \wp_send_json_error(["message" => "Insufficient permissions"]);
                return;
            }

            $stats = $this->get_login_statistics();
            \wp_send_json_success($stats);

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => "Error loading login statistics",
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for blocked IPs
     * 
     * @since 1.1.1
     * @return void
     */
    public function ajax_get_blocked_ips(): void
    {
        try {
            // Verify nonce
            if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security check failed"]);
                return;
            }

            // Check user permissions
            if (!\current_user_can("manage_options")) {
                \wp_send_json_error(["message" => "Insufficient permissions"]);
                return;
            }

            $blocked_ips = $this->get_blocked_ips();
            \wp_send_json_success($blocked_ips);

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => "Error loading blocked IPs",
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for security logs
     * 
     * @since 1.1.1
     * @return void
     */
    public function ajax_get_security_logs(): void
    {
        try {
            // Verify nonce
            if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security check failed"]);
                return;
            }

            // Check user permissions
            if (!\current_user_can("manage_options")) {
                \wp_send_json_error(["message" => "Insufficient permissions"]);
                return;
            }

            $logs = $this->get_recent_security_logs();
            \wp_send_json_success($logs);

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => "Error loading security logs",
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for auto-save functionality
     * 
     * @since 1.1.1
     * @return void
     */
    public function ajax_auto_save(): void
    {
        try {
            // Verify nonce
            if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security check failed"]);
                return;
            }

            // Check user permissions
            if (!\current_user_can("manage_options")) {
                \wp_send_json_error(["message" => "Insufficient permissions"]);
                return;
            }

            // Process form data - handle checkboxes that may not be present when unchecked
            $settings = [
                // Login Security
                "silver_assist_login_attempts" => (int) ($_POST["silver_assist_login_attempts"] ?? 5),
                "silver_assist_lockout_duration" => (int) ($_POST["silver_assist_lockout_duration"] ?? 900),
                "silver_assist_session_timeout" => (int) ($_POST["silver_assist_session_timeout"] ?? 30),
                "silver_assist_password_strength_enforcement" => (int) ($_POST["silver_assist_password_strength_enforcement"] ?? 0),
                "silver_assist_bot_protection" => (int) ($_POST["silver_assist_bot_protection"] ?? 0),

                // GraphQL Security
                "silver_assist_graphql_headless_mode" => (int) ($_POST["silver_assist_graphql_headless_mode"] ?? 0),
            ];

            // Update all settings
            foreach ($settings as $option_name => $value) {
                \update_option($option_name, $value);
            }

            \wp_send_json_success([
                "message" => \__("Settings saved automatically", "silver-assist-security"),
                "timestamp" => current_time("mysql")
            ]);

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => \__("Error saving settings", "silver-assist-security"),
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for admin path validation
     *
     * @since 1.1.4
     * @return void
     */
    public function ajax_validate_admin_path(): void
    {
        try {
            // Verify nonce
            if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
                \wp_send_json_error(["message" => "Security check failed"]);
                return;
            }

            // Check user permissions
            if (!\current_user_can("manage_options")) {
                \wp_send_json_error(["message" => "Insufficient permissions"]);
                return;
            }

            $path = \sanitize_text_field($_POST["path"] ?? "");

            // Use centralized PathValidator for validation
            $validation_result = PathValidator::validate_admin_path($path);

            if ($validation_result["is_valid"]) {
                \wp_send_json_success([
                    "message" => $validation_result["error_message"], // Contains success message
                    "preview_url" => \home_url("/" . $path),
                    "sanitized_path" => $validation_result["sanitized_path"]
                ]);
            } else {
                \wp_send_json_error([
                    "message" => $validation_result["error_message"],
                    "type" => $validation_result["error_type"]
                ]);
            }

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => \__("Error validating path", "silver-assist-security"),
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * Get overall security status
     * 
     * @since 1.1.1
     * @return array Security status data
     */
    private function get_security_status(): array
    {
        // Use config manager for GraphQL configuration
        $graphql_config = $this->config_manager->get_configuration();

        $status = [
            "login_security" => [
                "enabled" => true,
                "max_attempts" => (int) DefaultConfig::get_option("silver_assist_login_attempts"),
                "lockout_duration" => (int) DefaultConfig::get_option("silver_assist_lockout_duration"),
                "session_timeout" => (int) DefaultConfig::get_option("silver_assist_session_timeout"),
                "status" => "active"
            ],
            "admin_security" => [
                "password_strength_enforcement" => (bool) DefaultConfig::get_option("silver_assist_password_strength_enforcement"),
                "bot_protection" => (bool) DefaultConfig::get_option("silver_assist_bot_protection"),
                "status" => $this->get_admin_security_status()
            ],
            "graphql_security" => [
                "enabled" => class_exists("WPGraphQL"),
                "headless_mode" => (bool) DefaultConfig::get_option("silver_assist_graphql_headless_mode"),
                "query_depth_limit" => $graphql_config["query_depth_limit"],
                "query_complexity_limit" => $graphql_config["query_complexity_limit"],
                "query_timeout" => $graphql_config["query_timeout"],
                "introspection_enabled" => $graphql_config["introspection_enabled"],
                "debug_mode" => $graphql_config["debug_mode"],
                "endpoint_access" => $graphql_config["endpoint_access"],
                "status" => class_exists("WPGraphQL") ? "active" : "disabled"
            ],
            "general_security" => [
                "httponly_cookies" => true,
                "xml_rpc_disabled" => true,
                "version_hiding" => true,
                "ssl_enabled" => \is_ssl(),
                "status" => "active"
            ],
            "overall_status" => "secure",
            "last_updated" => current_time("mysql"),
            "active_features" => $this->count_active_features()
        ];

        return $status;
    }

    /**
     * Get login statistics
     * 
     * @since 1.1.1
     * @return array Login statistics
     */
    private function get_login_statistics(): array
    {
        global $wpdb;

        // Get current blocked IPs count
        $blocked_count = $this->get_blocked_ips_count();

        // Get recent failed attempts (last 24 hours)
        $recent_attempts = $this->get_recent_failed_attempts();

        return [
            "blocked_ips_count" => $blocked_count,
            "recent_failed_attempts" => $recent_attempts,
            "lockout_duration_minutes" => round(DefaultConfig::get_option("silver_assist_lockout_duration") / 60),
            "max_attempts" => (int) DefaultConfig::get_option("silver_assist_login_attempts"),
            "last_updated" => current_time("mysql")
        ];
    }

    /**
     * Get blocked IPs list
     * 
     * @since 1.1.1
     * @return array List of blocked IPs with details
     */
    private function get_blocked_ips(): array
    {
        global $wpdb;

        try {
            $blocked_ips = [];

            // Check if wpdb is available
            if (!$wpdb) {
                return $blocked_ips;
            }

            // Query transients for lockout entries
            $lockout_transients = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT option_name, option_value 
                     FROM {$wpdb->options} 
                     WHERE option_name LIKE %s 
                     AND option_value = \"1\"",
                    "_transient_lockout_%"
                )
            );

            if (!$lockout_transients) {
                return $blocked_ips;
            }

            foreach ($lockout_transients as $transient) {
                if (!isset($transient->option_name)) {
                    continue;
                }

                $key = str_replace("_transient_lockout_", "", $transient->option_name);

                // Get timeout info
                $timeout_key = "_transient_timeout_lockout_{$key}";
                $timeout = $wpdb->get_var($wpdb->prepare(
                    "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
                    $timeout_key
                ));

                if ($timeout && is_numeric($timeout) && $timeout > time()) {
                    $remaining = $timeout - time();
                    $lockout_duration = (int) DefaultConfig::get_option("silver_assist_lockout_duration");

                    $blocked_ips[] = [
                        "hash" => $key,
                        "ip" => "Hidden for security",
                        "remaining_time" => $remaining,
                        "remaining_minutes" => max(0, round($remaining / 60)),
                        "blocked_at" => date("Y-m-d H:i:s", time() - ($lockout_duration - $remaining))
                    ];
                }
            }

            return $blocked_ips;

        } catch (Exception $e) {
            // Log error and return empty array
            error_log("Silver Assist Security: Error getting blocked IPs - {$e->getMessage()}");
            return [];
        }
    }

    /**
     * Count active security features
     * 
     * @since 1.1.1
     * @return int Number of active features
     */
    private function count_active_features(): int
    {
        $count = 0;

        // Login security (always active)
        $count++;

        // Password enforcement
        if (DefaultConfig::get_option("silver_assist_password_strength_enforcement"))
            $count++;

        // GraphQL security
        if (class_exists("WPGraphQL"))
            $count++;

        // General security features (always active)
        $count += 4; // HTTPOnly cookies, XML-RPC disabled, version hiding, SSL status

        return $count;
    }

    /**
     * Get admin security status based on feature activation
     * 
     * @since 1.1.1
     * @return string Status (active|disabled)
     */
    private function get_admin_security_status(): string
    {
        $password_enforcement = (bool) DefaultConfig::get_option("silver_assist_password_strength_enforcement");
        $bot_protection = (bool) DefaultConfig::get_option("silver_assist_bot_protection");

        // Return active if any admin security feature is enabled
        return ($password_enforcement || $bot_protection) ? "active" : "disabled";
    }

    /**
     * Get count of blocked IPs
     * 
     * @since 1.1.1
     * @return int Number of currently blocked IPs
     */
    private function get_blocked_ips_count(): int
    {
        global $wpdb;

        $count = $wpdb->get_var(
            "SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_lockout_%\" 
             AND option_value = \"1\""
        );

        return (int) $count;
    }

    /**
     * Get recent failed login attempts count
     * 
     * @since 1.1.1
     * @return int Number of failed attempts in last 24 hours
     */
    private function get_recent_failed_attempts(): int
    {
        global $wpdb;

        // Count active login attempt transients
        $count = $wpdb->get_var(
            "SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_login_attempts_%\""
        );

        return (int) $count;
    }

    /**
     * Get recent security logs
     * 
     * @since 1.1.1
     * @return array Recent security events
     */
    private function get_recent_security_logs(): array
    {
        global $wpdb;

        $logs = [];

        // Get recent login attempts (transients)
        $attempt_transients = $wpdb->get_results(
            "SELECT option_name, option_value 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_login_attempts_%\" 
             ORDER BY option_id DESC 
             LIMIT 10"
        );

        foreach ($attempt_transients as $transient) {
            $ip_hash = str_replace("_transient_login_attempts_", "", $transient->option_name);
            $attempts = (int) $transient->option_value;

            $logs[] = [
                "type" => "failed_login",
                "ip_hash" => substr($ip_hash, 0, 8) . "...",
                "attempts" => $attempts,
                "timestamp" => current_time("mysql"),
                "status" => $attempts >= DefaultConfig::get_option("silver_assist_login_attempts") ? "blocked" : "monitoring"
            ];
        }

        // Get recent lockouts
        $lockout_transients = $wpdb->get_results(
            "SELECT option_name, option_value 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_lockout_%\" 
             AND option_value = \"1\"
             ORDER BY option_id DESC 
             LIMIT 5"
        );

        foreach ($lockout_transients as $lockout) {
            $ip_hash = str_replace("_transient_lockout_", "", $lockout->option_name);

            $logs[] = [
                "type" => "ip_blocked",
                "ip_hash" => substr($ip_hash, 0, 8) . "...",
                "timestamp" => current_time("mysql"),
                "status" => "active",
                "action" => "IP blocked due to excessive failed login attempts"
            ];
        }

        // Sort by timestamp (most recent first)
        usort($logs, function ($a, $b) {
            return strcmp($b["timestamp"], $a["timestamp"]);
        });

        return array_slice($logs, 0, 15); // Return max 15 recent logs
    }

    /**
     * Save security settings
     * 
     * @since 1.1.1
     * @return void
     */
    public function save_security_settings(): void
    {
        if (!isset($_POST["save_silver_assist_security"]) || !\current_user_can("manage_options")) {
            return;
        }

        // Verify nonce
        if (!\wp_verify_nonce($_POST["_wpnonce"], "silver_assist_security_settings")) {
            \wp_die(\__("Security check failed.", "silver-assist-security"));
        }

        // Save login security settings using null coalescing for cleaner code
        $login_attempts = intval($_POST["silver_assist_login_attempts"] ?? DefaultConfig::get_option("silver_assist_login_attempts"));
        if ($_POST["silver_assist_login_attempts"] ?? null) {
            $login_attempts = max(1, min(20, $login_attempts));
            \update_option("silver_assist_login_attempts", $login_attempts);
        }

        $lockout_duration = intval($_POST["silver_assist_lockout_duration"] ?? DefaultConfig::get_option("silver_assist_lockout_duration"));
        if ($_POST["silver_assist_lockout_duration"] ?? null) {
            $lockout_duration = max(60, min(3600, $lockout_duration));
            \update_option("silver_assist_lockout_duration", $lockout_duration);
        }

        $session_timeout = intval($_POST["silver_assist_session_timeout"] ?? DefaultConfig::get_option("silver_assist_session_timeout"));
        if ($_POST["silver_assist_session_timeout"] ?? null) {
            $session_timeout = max(5, min(120, $session_timeout));
            \update_option("silver_assist_session_timeout", $session_timeout);
        }

        // Save bot protection settings
        \update_option("silver_assist_bot_protection", (int) ($_POST["silver_assist_bot_protection"] ?? 0));

        // Save password settings
        \update_option("silver_assist_password_strength_enforcement", (int) ($_POST["silver_assist_password_strength_enforcement"] ?? 0));

        // Save Admin Hide settings
        $admin_hide_enabled = (int) ($_POST["silver_assist_admin_hide_enabled"] ?? 0);
        \update_option("silver_assist_admin_hide_enabled", $admin_hide_enabled);

        $admin_hide_path = \sanitize_title($_POST["silver_assist_admin_hide_path"] ?? "silver-admin");
        if (!empty($admin_hide_path) && $this->validate_admin_hide_path($admin_hide_path)) {
            \update_option("silver_assist_admin_hide_path", $admin_hide_path);
        } else {
            \update_option("silver_assist_admin_hide_path", "silver-admin");
        }

        // Flush rewrite rules when admin hide settings change
        if ($admin_hide_enabled) {
            \flush_rewrite_rules();
        }

        // Save GraphQL settings  
        // Save headless mode setting
        \update_option("silver_assist_graphql_headless_mode", (int) ($_POST["silver_assist_graphql_headless_mode"] ?? 0));

        // Save GraphQL timeout setting
        $graphql_timeout = intval($_POST["silver_assist_graphql_query_timeout"] ?? \get_option("silver_assist_graphql_query_timeout", $this->config_manager->get_php_execution_timeout()));
        if ($_POST["silver_assist_graphql_query_timeout"] ?? null) {
            $php_timeout = $this->config_manager->get_php_execution_timeout();
            $graphql_timeout = max(1, min($php_timeout, $graphql_timeout));
            \update_option("silver_assist_graphql_query_timeout", $graphql_timeout);
        }

        // Add success message
        \add_action("admin_notices", function () {
            echo "<div class=\"notice notice-success is-dismissible\">";
            echo "<p>" . \__("Security settings have been saved successfully.", "silver-assist-security") . "</p>";
            echo "</div>";
        });
    }

    /**
     * Render admin page
     * 
     * @since 1.1.1
     * @return void
     */
    public function render_admin_page(): void
    {
        // Get current values
        $login_attempts = DefaultConfig::get_option("silver_assist_login_attempts");
        $lockout_duration = DefaultConfig::get_option("silver_assist_lockout_duration");
        $session_timeout = DefaultConfig::get_option("silver_assist_session_timeout");
        $bot_protection = DefaultConfig::get_option("silver_assist_bot_protection");
        $password_strength_enforcement = DefaultConfig::get_option("silver_assist_password_strength_enforcement");
        $graphql_headless_mode = DefaultConfig::get_option("silver_assist_graphql_headless_mode");
        $graphql_query_timeout = \get_option("silver_assist_graphql_query_timeout", $this->config_manager->get_php_execution_timeout());

        // Get initial security status for display
        $security_status = $this->get_security_status();

        ?>
        <div class="wrap">
            <h1><?php echo esc_html(__("Silver Assist Security Essentials", "silver-assist-security")); ?></h1>

            <!-- Real-time Security Status Dashboard -->
            <div class="silver-assist-dashboard">
                <div class="dashboard-header">
                    <h2><?php esc_html_e("Security Status Dashboard", "silver-assist-security"); ?></h2>
                    <div class="dashboard-refresh">
                        <span class="last-updated" id="last-updated">
                            <?php esc_html_e("Last updated:", "silver-assist-security"); ?>
                            <span id="last-updated-time"><?php echo esc_html(current_time("H:i:s")); ?></span>
                        </span>
                        <button type="button" class="button" id="refresh-dashboard">
                            <?php esc_html_e("Refresh Now", "silver-assist-security"); ?>
                        </button>
                    </div>
                </div>

                <!-- Security Status Cards -->
                <div class="silver-stats-grid">
                    <div class="status-card login-security">
                        <div class="card-header">
                            <h3><?php esc_html_e("Login Security", "silver-assist-security"); ?></h3>
                            <span class="status-indicator"
                                id="login-status"><?php echo esc_html($security_status["login_security"]["status"]); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="stat">
                                <span class="stat-value"
                                    id="blocked-ips-count"><?php echo esc_html($security_status["login_security"]["max_attempts"]); ?></span>
                                <span class="stat-label"><?php esc_html_e("Max Attempts", "silver-assist-security"); ?></span>
                            </div>
                            <div class="stat">
                                <span class="stat-value" id="recent-attempts">0</span>
                                <span class="stat-label"><?php esc_html_e("Blocked IPs", "silver-assist-security"); ?></span>
                            </div>
                            <div class="stat">
                                <span
                                    class="stat-value"><?php echo esc_html(round($security_status["login_security"]["lockout_duration"] / 60)); ?></span>
                                <span class="stat-label"><?php esc_html_e("Lockout (min)", "silver-assist-security"); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card admin-security">
                        <div class="card-header">
                            <h3><?php esc_html_e("Admin Security", "silver-assist-security"); ?></h3>
                            <span class="status-indicator"
                                id="admin-status"><?php echo esc_html($security_status["admin_security"]["status"]); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e("Password Strength Enforcement", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value <?php echo $security_status["admin_security"]["password_strength_enforcement"] ? "enabled" : "disabled"; ?>">
                                    <?php echo $security_status["admin_security"]["password_strength_enforcement"] ? esc_html__("Enabled", "silver-assist-security") : esc_html__("Disabled", "silver-assist-security"); ?>
                                </span>
                            </div>
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e("Bot Protection", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value <?php echo $security_status["admin_security"]["bot_protection"] ? "enabled" : "disabled"; ?>">
                                    <?php echo $security_status["admin_security"]["bot_protection"] ? esc_html__("Enabled", "silver-assist-security") : esc_html__("Disabled", "silver-assist-security"); ?>
                                </span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card graphql-security">
                        <div class="card-header">
                            <h3><?php esc_html_e("GraphQL Security", "silver-assist-security"); ?></h3>
                            <span class="status-indicator"
                                id="graphql-status"><?php echo esc_html($security_status["graphql_security"]["status"]); ?></span>
                        </div>
                        <div class="card-content">
                            <?php if ($security_status["graphql_security"]["enabled"]): ?>
                                <div class="headless-mode-indicator">
                                    <span class="mode-label"><?php esc_html_e("Mode:", "silver-assist-security"); ?></span>
                                    <span
                                        class="mode-value <?php echo $security_status["graphql_security"]["headless_mode"] ? "headless" : "standard"; ?>">
                                        <?php echo $security_status["graphql_security"]["headless_mode"] ?
                                            esc_html__("Headless CMS", "silver-assist-security") :
                                            esc_html__("Standard", "silver-assist-security"); ?>
                                    </span>
                                </div>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status["graphql_security"]["query_depth_limit"]); ?></span>
                                    <span class="stat-label"><?php esc_html_e("Max Depth", "silver-assist-security"); ?></span>
                                </div>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status["graphql_security"]["query_complexity_limit"]); ?></span>
                                    <span class="stat-label"><?php esc_html_e("Max Complexity", "silver-assist-security"); ?></span>
                                </div>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status["graphql_security"]["query_timeout"]); ?>s</span>
                                    <span class="stat-label"><?php esc_html_e("Timeout", "silver-assist-security"); ?></span>
                                </div>
                                <div class="feature-status">
                                    <span
                                        class="feature-name"><?php esc_html_e("Introspection", "silver-assist-security"); ?></span>
                                    <span
                                        class="feature-value <?php echo $security_status["graphql_security"]["introspection_enabled"] ? "disabled" : "enabled"; ?>">
                                        <?php echo $security_status["graphql_security"]["introspection_enabled"] ?
                                            esc_html__("Enabled", "silver-assist-security") :
                                            esc_html__("Disabled", "silver-assist-security"); ?>
                                    </span>
                                </div>
                                <div class="feature-status">
                                    <span class="feature-name"><?php esc_html_e("Access", "silver-assist-security"); ?></span>
                                    <span
                                        class="feature-value <?php echo $security_status["graphql_security"]["endpoint_access"] === "public" ? "disabled" : "enabled"; ?>">
                                        <?php echo $security_status["graphql_security"]["endpoint_access"] === "public" ?
                                            esc_html__("Public", "silver-assist-security") :
                                            esc_html__("Restricted", "silver-assist-security"); ?>
                                    </span>
                                </div>
                            <?php else: ?>
                                <p class="graphql-disabled">
                                    <?php esc_html_e("WPGraphQL plugin not detected", "silver-assist-security"); ?>
                                </p>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="status-card general-security">
                        <div class="card-header">
                            <h3><?php esc_html_e("General Security", "silver-assist-security"); ?></h3>
                            <span class="status-indicator"
                                id="general-status"><?php echo esc_html($security_status["general_security"]["status"]); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e("HTTPOnly Cookies", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e("Enabled", "silver-assist-security"); ?></span>
                            </div>
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e("XML-RPC Protection", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e("Enabled", "silver-assist-security"); ?></span>
                            </div>
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e("Version Hiding", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e("Enabled", "silver-assist-security"); ?></span>
                            </div>
                            <div class="feature-status">
                                <span class="feature-name"><?php esc_html_e("SSL/HTTPS", "silver-assist-security"); ?></span>
                                <span
                                    class="feature-value <?php echo $security_status["general_security"]["ssl_enabled"] ? "enabled" : "disabled"; ?>">
                                    <?php echo $security_status["general_security"]["ssl_enabled"] ? esc_html__("Enabled", "silver-assist-security") : esc_html__("Disabled", "silver-assist-security"); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Active Threats and Blocked IPs -->
                <div class="dashboard-threats">
                    <div class="threats-header">
                        <h3><?php esc_html_e("Active Threats & Blocked IPs", "silver-assist-security"); ?></h3>
                        <span class="threat-count" id="threat-count">0</span>
                    </div>
                    <div class="threats-content" id="blocked-ips-list">
                        <p class="loading"><?php esc_html_e("Loading blocked IPs...", "silver-assist-security"); ?></p>
                    </div>
                </div>
            </div>

            <!-- Security Configuration Form -->
            <div class="silver-assist-configuration">
                <h2><?php esc_html_e("Security Configuration", "silver-assist-security"); ?></h2>

                <form method="post" action="">
                    <?php wp_nonce_field("silver_assist_security_settings"); ?>

                    <!-- Login Security Settings -->
                    <div class="card">
                        <h2><?php esc_html_e("Login Security Settings", "silver-assist-security"); ?></h2>
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_login_attempts">
                                        <?php esc_html_e("Maximum Login Attempts", "silver-assist-security"); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_login_attempts" name="silver_assist_login_attempts"
                                        value="<?php echo esc_attr($login_attempts); ?>" min="1" max="20" class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e("Number of failed login attempts before lockout (1-20)", "silver-assist-security"); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_lockout_duration">
                                        <?php esc_html_e("Lockout Duration (seconds)", "silver-assist-security"); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_lockout_duration"
                                        name="silver_assist_lockout_duration" value="<?php echo esc_attr($lockout_duration); ?>"
                                        min="60" max="3600" class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e("How long to lock out users after failed attempts (60-3600 seconds)", "silver-assist-security"); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_session_timeout">
                                        <?php esc_html_e("Session Timeout (minutes)", "silver-assist-security"); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_session_timeout" name="silver_assist_session_timeout"
                                        value="<?php echo esc_attr($session_timeout); ?>" min="5" max="120"
                                        class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e("Session timeout duration in minutes (5-120)", "silver-assist-security"); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <?php esc_html_e("Bot Protection", "silver-assist-security"); ?>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="silver_assist_bot_protection" value="1" <?php checked($bot_protection, 1); ?> />
                                        <?php esc_html_e("Block automated bots and security scanners with 404 responses", "silver-assist-security"); ?>
                                    </label>
                                    <p class="description">
                                        <?php esc_html_e("Detects and blocks common bots, crawlers, and security scanning tools.", "silver-assist-security"); ?>
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <!-- Admin URL Security Settings -->
                    <!-- Password Security Settings -->
                    <div class="card">
                        <h2><?php esc_html_e("Password Security Settings", "silver-assist-security"); ?></h2>
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <?php esc_html_e("Password Strength Enforcement", "silver-assist-security"); ?>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="silver_assist_password_strength_enforcement" value="1"
                                            <?php checked($password_strength_enforcement, 1); ?> />
                                        <?php esc_html_e("Enforce strong password requirements", "silver-assist-security"); ?>
                                    </label>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <!-- Admin Hide Security Settings -->
                    <div class="card">
                        <h2><?php esc_html_e("Admin Hide Security", "silver-assist-security"); ?></h2>
                        <p class="description">
                            <?php esc_html_e("Hide WordPress admin and login pages from unauthorized users by redirecting to custom URLs.", "silver-assist-security"); ?>
                        </p>

                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <?php esc_html_e("Enable Admin Hiding", "silver-assist-security"); ?>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="silver_assist_admin_hide_enabled" value="1" <?php checked(DefaultConfig::get_option("silver_assist_admin_hide_enabled"), 1); ?> />
                                        <?php esc_html_e("Hide /wp-admin and /wp-login.php from unauthorized users", "silver-assist-security"); ?>
                                    </label>
                                    <p class="description">
                                        <?php esc_html_e("When enabled, direct access to WordPress admin URLs will return 404 errors. Use the custom path below to access the admin area.", "silver-assist-security"); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_admin_hide_path">
                                        <?php esc_html_e("Custom Admin Path", "silver-assist-security"); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="text" id="silver_assist_admin_hide_path" name="silver_assist_admin_hide_path"
                                        value="<?php echo esc_attr(DefaultConfig::get_option("silver_assist_admin_hide_path")); ?>"
                                        placeholder="silver-admin" maxlength="50" />
                                    <p class="description">
                                        <?php esc_html_e("Custom path to access the admin area (e.g., 'my-secret-admin'). Avoid common words like 'admin', 'login', etc.", "silver-assist-security"); ?>
                                        <br>
                                        <?php if (DefaultConfig::get_option("silver_assist_admin_hide_enabled")): ?>
                                            <strong><?php esc_html_e("Current admin URL:", "silver-assist-security"); ?></strong>
                                            <code><?php echo esc_url(home_url("/" . DefaultConfig::get_option("silver_assist_admin_hide_path"))); ?></code>
                                        <?php endif; ?>
                                    </p>
                                </td>
                            </tr>
                        </table>

                        <div class="admin-hide-warning"
                            style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0;">
                            <h4 style="margin-top: 0; color: #856404;">
                                <span class="dashicons dashicons-warning" style="color: #ffc107;"></span>
                                <?php esc_html_e("Important Security Notice", "silver-assist-security"); ?>
                            </h4>
                            <ul style="color: #856404; margin-bottom: 0;">
                                <li><?php esc_html_e("Save your custom admin URL in a secure location before enabling this feature.", "silver-assist-security"); ?>
                                </li>
                                <li><?php esc_html_e("If you forget the custom path, you can disable this feature via FTP by adding this line to wp-config.php:", "silver-assist-security"); ?>
                                    <br><code style="background: #f8f9fa; padding: 3px 6px; border-radius: 3px; font-family: monospace;">define('SILVER_ASSIST_HIDE_ADMIN', false);</code>
                                </li>
                                <li><?php esc_html_e("This feature adds an extra layer of security but should be used alongside strong passwords and other security measures.", "silver-assist-security"); ?>
                                </li>
                            </ul>
                        </div>
                    </div>

                    <!-- GraphQL Security Settings -->
                    <?php if (class_exists("WPGraphQL")): ?>
                        <div class="card">
                            <h2><?php esc_html_e("GraphQL Security Enhancements", "silver-assist-security"); ?></h2>

                            <div class="graphql-native-notice">
                                <p><strong><?php esc_html_e("WPGraphQL Detected", "silver-assist-security"); ?></strong></p>
                                <p><?php esc_html_e("WPGraphQL has its own security settings. These enhancements work alongside WPGraphQL's native configuration.", "silver-assist-security"); ?>
                                </p>
                                <p><a href="<?php echo admin_url("admin.php?page=graphql-settings"); ?>"
                                        class="button button-secondary" target="_blank">
                                        <?php esc_html_e("Open WPGraphQL Settings", "silver-assist-security"); ?>
                                    </a></p>
                            </div>

                            <table class="form-table">
                                <tr>
                                    <th scope="row">
                                        <?php esc_html_e("Headless CMS Mode", "silver-assist-security"); ?>
                                    </th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="silver_assist_graphql_headless_mode" value="1" <?php checked($graphql_headless_mode, 1); ?> />
                                            <?php esc_html_e("Enable optimized rate limiting for headless CMS usage", "silver-assist-security"); ?>
                                        </label>
                                        <p class="description">
                                            <?php esc_html_e("Increases rate limits and timeout handling for better headless CMS performance. Use WPGraphQL's native settings for query depth and complexity.", "silver-assist-security"); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">
                                        <?php esc_html_e("GraphQL Query Timeout", "silver-assist-security"); ?>
                                    </th>
                                    <td>
                                        <input type="range" name="silver_assist_graphql_query_timeout"
                                            id="silver_assist_graphql_query_timeout" min="1"
                                            max="<?php echo esc_attr($this->config_manager->get_php_execution_timeout()); ?>"
                                            value="<?php echo esc_attr($graphql_query_timeout); ?>" step="1" />
                                        <span id="graphql-timeout-value"><?php echo esc_html($graphql_query_timeout); ?></span>
                                        <?php esc_html_e("seconds", "silver-assist-security"); ?>
                                        <p class="description">
                                            <strong><?php esc_html_e("PHP Limit:", "silver-assist-security"); ?></strong>
                                            <?php echo esc_html($this->config_manager->get_php_execution_timeout()); ?>
                                            <?php esc_html_e("seconds", "silver-assist-security"); ?>
                                            <br>
                                            <?php esc_html_e("Maximum time allowed for GraphQL query execution. Cannot exceed PHP execution time limit.", "silver-assist-security"); ?>
                                            <br>
                                            <em><?php echo esc_html($this->config_manager->get_timeout_config()["description"]); ?></em>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">
                                        <?php esc_html_e("Enhanced Rate Limiting", "silver-assist-security"); ?>
                                    </th>
                                    <td>
                                        <p class="description">
                                            <strong><?php esc_html_e("Current Rate Limits:", "silver-assist-security"); ?></strong><br>
                                            <?php if ($graphql_headless_mode): ?>
                                                • <?php esc_html_e("Standard requests: 300/minute", "silver-assist-security"); ?><br>
                                                •
                                                <?php esc_html_e("Build processes: 600/minute (auto-detected)", "silver-assist-security"); ?><br>
                                                •
                                                <?php esc_html_e("Query timeout: Extended for complex operations", "silver-assist-security"); ?>
                                            <?php else: ?>
                                                • <?php esc_html_e("Standard requests: 100/minute", "silver-assist-security"); ?><br>
                                                •
                                                <?php esc_html_e("Build processes: 300/minute (auto-detected)", "silver-assist-security"); ?><br>
                                                • <?php esc_html_e("Query timeout: Standard limits", "silver-assist-security"); ?>
                                            <?php endif; ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">
                                        <?php esc_html_e("WPGraphQL Recommendations", "silver-assist-security"); ?>
                                    </th>
                                    <td>
                                        <div class="wpgraphql-recommendations">
                                            <p><strong><?php esc_html_e("For Headless CMS Usage:", "silver-assist-security"); ?></strong>
                                            </p>
                                            <ul>
                                                <li><?php esc_html_e("✓ Enable Query Depth Limiting with Max Depth: 15-20", "silver-assist-security"); ?>
                                                </li>
                                                <li><?php esc_html_e("✓ Keep Batch Queries enabled with limit: 10-20", "silver-assist-security"); ?>
                                                </li>
                                                <li><?php esc_html_e("✓ Disable Public Introspection in production", "silver-assist-security"); ?>
                                                </li>
                                                <li><?php esc_html_e("✓ Disable GraphQL Debug Mode in production", "silver-assist-security"); ?>
                                                </li>
                                            </ul>

                                            <p><strong><?php esc_html_e("Current WPGraphQL Settings:", "silver-assist-security"); ?></strong>
                                            </p>
                                            <div id="wpgraphql-current-settings" class="wpgraphql-settings-display">
                                                <?php echo $this->get_wpgraphql_current_settings(); ?>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            </table>

                            <?php if ($graphql_headless_mode): ?>
                                <div class="headless-mode-notice">
                                    <p><strong><?php esc_html_e("Headless CMS Mode Active", "silver-assist-security"); ?></strong></p>
                                    <ul>
                                        <li><?php esc_html_e("✓ Enhanced rate limiting for high-frequency requests", "silver-assist-security"); ?>
                                        </li>
                                        <li><?php esc_html_e("✓ Build process detection (Next.js, Gatsby, etc.)", "silver-assist-security"); ?>
                                        </li>
                                        <li><?php esc_html_e("✓ Extended timeouts for complex queries", "silver-assist-security"); ?>
                                        </li>
                                        <li><?php esc_html_e("✓ Optimized for static site generation (SSG/ISR)", "silver-assist-security"); ?>
                                        </li>
                                    </ul>
                                    <p class="description">
                                        <?php esc_html_e("Configure query depth and complexity limits in WPGraphQL settings for optimal performance.", "silver-assist-security"); ?>
                                    </p>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <?php submit_button(__("Save Security Settings", "silver-assist-security"), "primary", "save_silver_assist_security"); ?>
                </form>
            </div>
            <?php
    }

    /**
     * Render update check script for Settings Hub action button
     * 
     * Outputs inline JavaScript that triggers an AJAX update check when called
     * by the Settings Hub action button. Integrates with wp-github-updater.
     * 
     * @since 1.1.13
     * @return void
     */
    public function render_update_check_script(): void
    {
        $plugin = Plugin::getInstance();
        $updater = $plugin->get_updater();

        if (!$updater) {
            return;
        }

        $nonce = \wp_create_nonce("silver_assist_security_updates_nonce");
        ?>
        <script type="text/javascript">
        (($) => {
            "use strict";
            
            // Trigger update check immediately when action button is clicked
            $.ajax({
                url: ajaxurl,
                type: "POST",
                data: {
                    action: "silver_assist_check_updates",
                    nonce: "<?php echo \esc_js($nonce); ?>"
                },
                success: (response) => {
                    if (response.success) {
                        if (response.data.update_available) {
                            alert("<?php echo \esc_js(\__("Update available! Redirecting to Updates page...", "silver-assist-security")); ?>");
                            window.location.href = "<?php echo \esc_url(\admin_url("update-core.php")); ?>";
                        } else {
                            alert("<?php echo \esc_js(\__("You're up to date!", "silver-assist-security")); ?>");
                        }
                    } else {
                        alert("<?php echo \esc_js(\__("Error checking updates. Please try again.", "silver-assist-security")); ?>");
                    }
                },
                error: () => {
                    alert("<?php echo \esc_js(\__("Error connecting to update server.", "silver-assist-security")); ?>");
                }
            });
        })(jQuery);
        </script>
        <?php
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
    public function ajax_check_updates(): void
    {
        // Validate nonce
        if (!isset($_POST["nonce"]) || !\wp_verify_nonce($_POST["nonce"], "silver_assist_security_updates_nonce")) {
            \wp_send_json_error(["message" => \__("Security validation failed", "silver-assist-security")]);
            return;
        }

        // Check user capability
        if (!\current_user_can("manage_options")) {
            \wp_send_json_error(["message" => \__("Insufficient permissions", "silver-assist-security")]);
            return;
        }

        $plugin = Plugin::getInstance();
        $updater = $plugin->get_updater();

        if (!$updater) {
            \wp_send_json_error(["message" => \__("Updater not available", "silver-assist-security")]);
            return;
        }

        try {
            // Clear cached version to force fresh check
            $transient_key = "silver-assist-security_version_check";
            \delete_transient($transient_key);
            
            $update_available = $updater->isUpdateAvailable();
            $current_version = $updater->getCurrentVersion();
            $latest_version = $updater->getLatestVersion();

            \wp_send_json_success([
                "update_available" => $update_available,
                "current_version" => $current_version,
                "latest_version" => $latest_version,
                "message" => $update_available 
                    ? \__("Update available!", "silver-assist-security")
                    : \__("You're up to date!", "silver-assist-security")
            ]);
        } catch (Exception $e) {
            SecurityHelper::log_security_event(
                "UPDATE_CHECK_ERROR",
                "Failed to check for updates: " . $e->getMessage(),
                ["exception" => $e->getMessage()]
            );

            \wp_send_json_error([
                "message" => \__("Error checking for updates", "silver-assist-security")
            ]);
        }
    }

    /**
     * Get current WPGraphQL settings for display using ConfigManager
     * 
     * @since 1.1.1
     * @return string HTML display of current settings
     */
    private function get_wpgraphql_current_settings(): string
    {
        return $this->config_manager->get_settings_display();
    }

    /**
     * Validate admin hide path using centralized PathValidator
     *
     * @since 1.1.4
     * @param string $path The path to validate
     * @return bool True if path is valid
     */
    private function validate_admin_hide_path(string $path): bool
    {
        $result = PathValidator::validate_admin_path($path);
        return $result["is_valid"];
    }

    /**
     * Get list of forbidden admin path keywords
     *
     * @since 1.1.4
     * @return array<string> List of forbidden path keywords
     */
    public function get_forbidden_admin_paths(): array
    {
        return PathValidator::get_forbidden_paths();
    }
}
