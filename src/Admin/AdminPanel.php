<?php
/**
 * Silver Assist Security Essentials - Admin Panel Interface
 *
 * Handles the WordPress admin interface for security configuration including
 * login settings, password policies, GraphQL limits, and security status display.
 * Provides comprehensive settings management and validation.
 *
 * @package SilverAssist\Security\Admin
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.2
 */

namespace SilverAssist\Security\Admin;

use Exception;

/**
 * Admin Panel class
 * 
 * Handles the WordPress admin interface for security configuration
 * 
 * @since 1.0.0
 */
class AdminPanel
{

    /**
     * Constructor
     * 
     * @since 1.0.0
     */
    public function __construct()
    {
        $this->init();
    }

    /**
     * Initialize admin panel
     * 
     * @since 1.0.0
     * @return void
     */
    private function init(): void
    {
        \add_action("admin_menu", [$this, "add_admin_menu"]);
        \add_action("admin_init", [$this, "register_settings"]);
        \add_action("admin_init", [$this, "save_security_settings"]);
        \add_action("admin_enqueue_scripts", [$this, "enqueue_admin_scripts"]);

        // AJAX endpoints for real-time status
        \add_action("wp_ajax_silver_assist_get_security_status", [$this, "ajax_get_security_status"]);
        \add_action("wp_ajax_silver_assist_get_login_stats", [$this, "ajax_get_login_stats"]);
        \add_action("wp_ajax_silver_assist_get_blocked_ips", [$this, "ajax_get_blocked_ips"]);
        \add_action("wp_ajax_silver_assist_get_security_logs", [$this, "ajax_get_security_logs"]);
        \add_action("wp_ajax_silver_assist_auto_save", [$this, "ajax_auto_save"]);
    }

    /**
     * Add admin menu item
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_admin_menu(): void
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
     * @since 1.0.0
     * @return void
     */
    public function register_settings(): void
    {
        // Login Security Settings
        \register_setting("silver_assist_security_login", "silver_assist_login_attempts");
        \register_setting("silver_assist_security_login", "silver_assist_lockout_duration");
        \register_setting("silver_assist_security_login", "silver_assist_session_timeout");
        \register_setting("silver_assist_security_login", "silver_assist_bot_protection");

        // Password Settings
        \register_setting("silver_assist_security_password", "silver_assist_password_strength_enforcement");

        // GraphQL Settings
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_depth");
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_complexity");
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_timeout");
    }

    /**
     * Enqueue admin scripts and styles
     * 
     * @since 1.0.0
     * @param string $hook_suffix Current admin page hook suffix
     * @return void
     */
    public function enqueue_admin_scripts(string $hook_suffix): void
    {
        if ($hook_suffix !== "settings_page_silver-assist-security") {
            return;
        }

        \wp_enqueue_style(
            "silver-assist-security-admin",
            SILVER_ASSIST_SECURITY_URL . "assets/css/admin.css",
            [],
            SILVER_ASSIST_SECURITY_VERSION
        );

        \wp_enqueue_script(
            "silver-assist-security-admin",
            SILVER_ASSIST_SECURITY_URL . "assets/js/admin.js",
            ["jquery"],
            SILVER_ASSIST_SECURITY_VERSION,
            true
        );

        // Localize script for AJAX
        \wp_localize_script("silver-assist-security-admin", "silverAssistSecurity", [
            "ajaxurl" => \admin_url("admin-ajax.php"),
            "admin_url" => \admin_url(""),
            "nonce" => \wp_create_nonce("silver_assist_security_ajax"),
            "logout_nonce" => \wp_create_nonce("log-out"),
            "refreshInterval" => 30000, // 30 seconds
            "strings" => [
                "loading" => \__("Loading...", "silver-assist-security"),
                "error" => \__("Error loading data", "silver-assist-security"),
                "lastUpdated" => \__("Last updated:", "silver-assist-security"),
                "noThreats" => \__("No active threats detected", "silver-assist-security"),
                "refreshing" => \__("Refreshing...", "silver-assist-security"),
                "updateUrl" => \admin_url("update-core.php"),
                // Version check strings
                "newVersionAvailable" => \__("New version %s available.", "silver-assist-security"),
                "updateNow" => \__("Update now", "silver-assist-security"),
                "checking" => \__("Checking...", "silver-assist-security"),
                "newVersionFound" => \__("New version available: %1\$s\\nCurrent version: %2\$s", "silver-assist-security"),
                "upToDate" => \__("The plugin is up to date with the latest version (%s)", "silver-assist-security"),
                "checkError" => \__("Error checking for updates:", "silver-assist-security"),
                "unknownError" => \__("Unknown error", "silver-assist-security"),
                "connectivityError" => \__("Connectivity error while checking for updates", "silver-assist-security"),
                // Form validation error strings
                "loginAttemptsError" => \__("Login attempts must be between 1 and 20", "silver-assist-security"),
                "lockoutDurationError" => \__("Lockout duration must be between 60 and 3600 seconds", "silver-assist-security"),
                "sessionTimeoutError" => \__("Session timeout must be between 5 and 120 minutes", "silver-assist-security"),
                "graphqlDepthError" => \__("GraphQL query depth must be between 1 and 20", "silver-assist-security"),
                "graphqlComplexityError" => \__("GraphQL query complexity must be between 10 and 1000", "silver-assist-security"),
                "graphqlTimeoutError" => \__("GraphQL query timeout must be between 1 and 30 seconds", "silver-assist-security"),
                "customUrlPatternError" => \__("Custom admin URL must contain only lowercase letters, numbers, and hyphens (3-30 characters)", "silver-assist-security"),
                "urlPatternError" => \__("Use only lowercase letters, numbers, and hyphens (3-30 characters)", "silver-assist-security"),
                // Auto-save strings
                "saving" => \__("Saving...", "silver-assist-security"),
                "saved" => \__("Saved!", "silver-assist-security"),
                "saveFailed" => \__("Save failed", "silver-assist-security"),
                // AJAX error strings
                "updateCheckFailed" => \__("Failed to check for Silver Assist updates", "silver-assist-security"),
                "securityStatusFailed" => \__("Failed to load security essentials", "silver-assist-security"),
                "loginStatsFailed" => \__("Failed to load login stats", "silver-assist-security"),
                // Table headers
                "ipHash" => \__("IP Hash", "silver-assist-security"),
                "blockedTime" => \__("Blocked Time", "silver-assist-security"),
                "remaining" => \__("Remaining", "silver-assist-security"),
                "minutes" => \__("min", "silver-assist-security"),
            ]
        ]);
    }

    /**
     * AJAX handler for security status
     * 
     * @since 1.0.0
     * @return void
     */
    public function ajax_get_security_status(): void
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

            $status = $this->get_security_status();
            \wp_send_json_success($status);

        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => "Error loading security status",
                "error" => $e->getMessage()
            ]);
        }
    }

    /**
     * AJAX handler for login statistics
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
                "silver_assist_password_strength_enforcement" => isset($_POST["silver_assist_password_strength_enforcement"]) ? 1 : 0,
                "silver_assist_bot_protection" => isset($_POST["silver_assist_bot_protection"]) ? 1 : 0,

                // GraphQL Security
                "silver_assist_graphql_query_depth" => (int) ($_POST["silver_assist_graphql_query_depth"] ?? 8),
                "silver_assist_graphql_query_complexity" => (int) ($_POST["silver_assist_graphql_query_complexity"] ?? 100),
                "silver_assist_graphql_query_timeout" => (int) ($_POST["silver_assist_graphql_query_timeout"] ?? 5),
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
     * Get overall security status
     * 
     * @since 1.0.0
     * @return array Security status data
     */
    private function get_security_status(): array
    {
        $status = [
            "login_security" => [
                "enabled" => true,
                "max_attempts" => (int) \get_option("silver_assist_login_attempts", 5),
                "lockout_duration" => (int) \get_option("silver_assist_lockout_duration", 900),
                "session_timeout" => (int) \get_option("silver_assist_session_timeout", 30),
                "status" => "active"
            ],
            "admin_security" => [
                "password_strength_enforcement" => (bool) \get_option("silver_assist_password_strength_enforcement", 1),
                "status" => $this->get_admin_security_status()
            ],
            "graphql_security" => [
                "enabled" => class_exists("WPGraphQL"),
                "query_depth_limit" => (int) \get_option("silver_assist_graphql_query_depth", 8),
                "query_complexity_limit" => (int) \get_option("silver_assist_graphql_query_complexity", 100),
                "query_timeout" => (int) \get_option("silver_assist_graphql_query_timeout", 5),
                "status" => class_exists("WPGraphQL") ? "active" : "disabled"
            ],
            "general_security" => [
                "httponly_cookies" => true,
                "xml_rpc_disabled" => true,
                "version_hiding" => true,
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
     * @since 1.0.0
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
            "lockout_duration_minutes" => round(\get_option("silver_assist_lockout_duration", 900) / 60),
            "max_attempts" => (int) \get_option("silver_assist_login_attempts", 5),
            "last_updated" => current_time("mysql")
        ];
    }

    /**
     * Get blocked IPs list
     * 
     * @since 1.0.0
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
                    $lockout_duration = (int) \get_option("silver_assist_lockout_duration", 900);

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
            error_log("Silver Assist Security: Error getting blocked IPs - " . $e->getMessage());
            return [];
        }
    }

    /**
     * Count active security features
     * 
     * @since 1.0.0
     * @return int Number of active features
     */
    private function count_active_features(): int
    {
        $count = 0;

        // Login security (always active)
        $count++;

        // Password enforcement
        if (\get_option("silver_assist_password_strength_enforcement", 1))
            $count++;

        // GraphQL security
        if (class_exists("WPGraphQL"))
            $count++;

        // General security features (always active)
        $count += 3; // HTTPOnly cookies, XML-RPC disabled, version hiding

        return $count;
    }

    /**
     * Get admin security status based on feature activation
     * 
     * @since 1.0.1
     * @return string Status (active|disabled)
     */
    private function get_admin_security_status(): string
    {
        $password_enforcement = (bool) \get_option("silver_assist_password_strength_enforcement", 1);

        // Return active if password enforcement is enabled
        return $password_enforcement ? "active" : "disabled";
    }

    /**
     * Get count of blocked IPs
     * 
     * @since 1.0.0
     * @return int Number of currently blocked IPs
     */
    private function get_blocked_ips_count(): int
    {
        global $wpdb;

        $count = $wpdb->get_var(
            "SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_lockout_%' 
             AND option_value = '1'"
        );

        return (int) $count;
    }

    /**
     * Get recent failed login attempts count
     * 
     * @since 1.0.0
     * @return int Number of failed attempts in last 24 hours
     */
    private function get_recent_failed_attempts(): int
    {
        global $wpdb;

        // Count active login attempt transients
        $count = $wpdb->get_var(
            "SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_login_attempts_%'"
        );

        return (int) $count;
    }

    /**
     * Get recent security logs
     * 
     * @since 1.0.0
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
             WHERE option_name LIKE '_transient_login_attempts_%' 
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
                "status" => $attempts >= \get_option("silver_assist_login_attempts", 5) ? "blocked" : "monitoring"
            ];
        }

        // Get recent lockouts
        $lockout_transients = $wpdb->get_results(
            "SELECT option_name, option_value 
             FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_lockout_%' 
             AND option_value = '1'
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
     * @since 1.0.0
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

        // Save login security settings
        if (isset($_POST["silver_assist_login_attempts"])) {
            $login_attempts = intval($_POST["silver_assist_login_attempts"]);
            $login_attempts = max(1, min(20, $login_attempts));
            \update_option("silver_assist_login_attempts", $login_attempts);
        }

        if (isset($_POST["silver_assist_lockout_duration"])) {
            $lockout_duration = intval($_POST["silver_assist_lockout_duration"]);
            $lockout_duration = max(60, min(3600, $lockout_duration));
            \update_option("silver_assist_lockout_duration", $lockout_duration);
        }

        if (isset($_POST["silver_assist_session_timeout"])) {
            $session_timeout = intval($_POST["silver_assist_session_timeout"]);
            $session_timeout = max(5, min(120, $session_timeout));
            \update_option("silver_assist_session_timeout", $session_timeout);
        }

        // Save bot protection settings
        \update_option("silver_assist_bot_protection", isset($_POST["silver_assist_bot_protection"]) ? 1 : 0);

        // Save password settings
        \update_option("silver_assist_password_strength_enforcement", isset($_POST["silver_assist_password_strength_enforcement"]) ? 1 : 0);

        // Save GraphQL settings
        if (isset($_POST["silver_assist_graphql_query_depth"])) {
            $query_depth = intval($_POST["silver_assist_graphql_query_depth"]);
            $query_depth = max(1, min(20, $query_depth));
            \update_option("silver_assist_graphql_query_depth", $query_depth);
        }

        if (isset($_POST["silver_assist_graphql_query_complexity"])) {
            $query_complexity = intval($_POST["silver_assist_graphql_query_complexity"]);
            $query_complexity = max(10, min(1000, $query_complexity));
            \update_option("silver_assist_graphql_query_complexity", $query_complexity);
        }

        if (isset($_POST["silver_assist_graphql_query_timeout"])) {
            $query_timeout = intval($_POST["silver_assist_graphql_query_timeout"]);
            $query_timeout = max(1, min(30, $query_timeout));
            \update_option("silver_assist_graphql_query_timeout", $query_timeout);
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
     * @since 1.0.0
     * @return void
     */
    public function render_admin_page(): void
    {
        // Get current values
        $login_attempts = \get_option("silver_assist_login_attempts", 5);
        $lockout_duration = \get_option("silver_assist_lockout_duration", 900);
        $session_timeout = \get_option("silver_assist_session_timeout", 30);
        $bot_protection = \get_option("silver_assist_bot_protection", 1);
        $password_strength_enforcement = \get_option("silver_assist_password_strength_enforcement", 1);
        $graphql_query_depth = \get_option("silver_assist_graphql_query_depth", 8);
        $graphql_query_complexity = \get_option("silver_assist_graphql_query_complexity", 100);
        $graphql_query_timeout = \get_option("silver_assist_graphql_query_timeout", 5);

        // Get initial security status for display
        $security_status = $this->get_security_status();

        ?>
        <div class="wrap">
            <h1><?php echo esc_html(__('Silver Assist Security Essentials', 'silver-assist-security')); ?></h1>

            <!-- Real-time Security Status Dashboard -->
            <div class="silver-assist-dashboard">
                <div class="dashboard-header">
                    <h2><?php esc_html_e('Security Status Dashboard', 'silver-assist-security'); ?></h2>
                    <div class="dashboard-refresh">
                        <span class="last-updated" id="last-updated">
                            <?php esc_html_e('Last updated:', 'silver-assist-security'); ?>
                            <span id="last-updated-time"><?php echo esc_html(current_time('H:i:s')); ?></span>
                        </span>
                        <button type="button" class="button" id="refresh-dashboard">
                            <?php esc_html_e('Refresh Now', 'silver-assist-security'); ?>
                        </button>
                    </div>
                </div>

                <!-- Security Status Cards -->
                <div class="dashboard-cards">
                    <div class="status-card login-security">
                        <div class="card-header">
                            <h3><?php esc_html_e('Login Security', 'silver-assist-security'); ?></h3>
                            <span class="status-indicator"
                                id="login-status"><?php echo esc_html($security_status['login_security']['status']); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="stat">
                                <span class="stat-value"
                                    id="blocked-ips-count"><?php echo esc_html($security_status['login_security']['max_attempts']); ?></span>
                                <span class="stat-label"><?php esc_html_e('Max Attempts', 'silver-assist-security'); ?></span>
                            </div>
                            <div class="stat">
                                <span class="stat-value" id="recent-attempts">0</span>
                                <span class="stat-label"><?php esc_html_e('Blocked IPs', 'silver-assist-security'); ?></span>
                            </div>
                            <div class="stat">
                                <span
                                    class="stat-value"><?php echo esc_html(round($security_status['login_security']['lockout_duration'] / 60)); ?></span>
                                <span class="stat-label"><?php esc_html_e('Lockout (min)', 'silver-assist-security'); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card admin-security">
                        <div class="card-header">
                            <h3><?php esc_html_e('Admin Security', 'silver-assist-security'); ?></h3>
                            <span class="status-indicator"
                                id="admin-status"><?php echo esc_html($security_status['admin_security']['status']); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e('Password Strength Enforcement', 'silver-assist-security'); ?></span>
                                <span
                                    class="feature-value <?php echo $security_status['admin_security']['password_strength_enforcement'] ? 'enabled' : 'disabled'; ?>">
                                    <?php echo $security_status['admin_security']['password_strength_enforcement'] ? esc_html__('Enabled', 'silver-assist-security') : esc_html__('Disabled', 'silver-assist-security'); ?>
                                </span>
                            </div>
                        </div>
                    </div>

                    <div class="status-card graphql-security">
                        <div class="card-header">
                            <h3><?php esc_html_e('GraphQL Security', 'silver-assist-security'); ?></h3>
                            <span class="status-indicator"
                                id="graphql-status"><?php echo esc_html($security_status['graphql_security']['status']); ?></span>
                        </div>
                        <div class="card-content">
                            <?php if ($security_status['graphql_security']['enabled']): ?>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status['graphql_security']['query_depth_limit']); ?></span>
                                    <span class="stat-label"><?php esc_html_e('Max Depth', 'silver-assist-security'); ?></span>
                                </div>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status['graphql_security']['query_complexity_limit']); ?></span>
                                    <span class="stat-label"><?php esc_html_e('Max Complexity', 'silver-assist-security'); ?></span>
                                </div>
                                <div class="stat">
                                    <span
                                        class="stat-value"><?php echo esc_html($security_status['graphql_security']['query_timeout']); ?>s</span>
                                    <span class="stat-label"><?php esc_html_e('Timeout', 'silver-assist-security'); ?></span>
                                </div>
                            <?php else: ?>
                                <p class="graphql-disabled">
                                    <?php esc_html_e('WPGraphQL plugin not detected', 'silver-assist-security'); ?></p>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="status-card general-security">
                        <div class="card-header">
                            <h3><?php esc_html_e('General Security', 'silver-assist-security'); ?></h3>
                            <span class="status-indicator"
                                id="general-status"><?php echo esc_html($security_status['general_security']['status']); ?></span>
                        </div>
                        <div class="card-content">
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e('HTTPOnly Cookies', 'silver-assist-security'); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e('Enabled', 'silver-assist-security'); ?></span>
                            </div>
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e('XML-RPC Protection', 'silver-assist-security'); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e('Enabled', 'silver-assist-security'); ?></span>
                            </div>
                            <div class="feature-status">
                                <span
                                    class="feature-name"><?php esc_html_e('Version Hiding', 'silver-assist-security'); ?></span>
                                <span
                                    class="feature-value enabled"><?php esc_html_e('Enabled', 'silver-assist-security'); ?></span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Active Threats and Blocked IPs -->
                <div class="dashboard-threats">
                    <div class="threats-header">
                        <h3><?php esc_html_e('Active Threats & Blocked IPs', 'silver-assist-security'); ?></h3>
                        <span class="threat-count" id="threat-count">0</span>
                    </div>
                    <div class="threats-content" id="blocked-ips-list">
                        <p class="loading"><?php esc_html_e('Loading blocked IPs...', 'silver-assist-security'); ?></p>
                    </div>
                </div>
            </div>

            <!-- Security Configuration Form -->
            <div class="silver-assist-configuration">
                <h2><?php esc_html_e('Security Configuration', 'silver-assist-security'); ?></h2>

                <form method="post" action="">
                    <?php wp_nonce_field('silver_assist_security_settings'); ?>

                    <!-- Login Security Settings -->
                    <div class="card">
                        <h2><?php esc_html_e('Login Security Settings', 'silver-assist-security'); ?></h2>
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_login_attempts">
                                        <?php esc_html_e('Maximum Login Attempts', 'silver-assist-security'); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_login_attempts" name="silver_assist_login_attempts"
                                        value="<?php echo esc_attr($login_attempts); ?>" min="1" max="20" class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e('Number of failed login attempts before lockout (1-20)', 'silver-assist-security'); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_lockout_duration">
                                        <?php esc_html_e('Lockout Duration (seconds)', 'silver-assist-security'); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_lockout_duration"
                                        name="silver_assist_lockout_duration" value="<?php echo esc_attr($lockout_duration); ?>"
                                        min="60" max="3600" class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e('How long to lock out users after failed attempts (60-3600 seconds)', 'silver-assist-security'); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <label for="silver_assist_session_timeout">
                                        <?php esc_html_e('Session Timeout (minutes)', 'silver-assist-security'); ?>
                                    </label>
                                </th>
                                <td>
                                    <input type="number" id="silver_assist_session_timeout" name="silver_assist_session_timeout"
                                        value="<?php echo esc_attr($session_timeout); ?>" min="5" max="120"
                                        class="small-text" />
                                    <p class="description">
                                        <?php esc_html_e('Session timeout duration in minutes (5-120)', 'silver-assist-security'); ?>
                                    </p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">
                                    <?php esc_html_e('Bot Protection', 'silver-assist-security'); ?>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="silver_assist_bot_protection" value="1"
                                            <?php checked($bot_protection, 1); ?> />
                                        <?php esc_html_e('Block automated bots and security scanners with 404 responses', 'silver-assist-security'); ?>
                                    </label>
                                    <p class="description">
                                        <?php esc_html_e('Detects and blocks common bots, crawlers, and security scanning tools.', 'silver-assist-security'); ?>
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <!-- Admin URL Security Settings -->
                    <!-- Password Security Settings -->
                    <div class="card">
                        <h2><?php esc_html_e('Password Security Settings', 'silver-assist-security'); ?></h2>
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <?php esc_html_e('Password Strength Enforcement', 'silver-assist-security'); ?>
                                </th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="silver_assist_password_strength_enforcement" value="1"
                                            <?php checked($password_strength_enforcement, 1); ?> />
                                        <?php esc_html_e('Enforce strong password requirements', 'silver-assist-security'); ?>
                                    </label>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <!-- GraphQL Security Settings -->
                    <?php if (class_exists('WPGraphQL')): ?>
                        <div class="card">
                            <h2><?php esc_html_e('GraphQL Security Settings', 'silver-assist-security'); ?></h2>
                            <table class="form-table">
                                <tr>
                                    <th scope="row">
                                        <label for="silver_assist_graphql_query_depth">
                                            <?php esc_html_e('Maximum Query Depth', 'silver-assist-security'); ?>
                                        </label>
                                    </th>
                                    <td>
                                        <input type="number" id="silver_assist_graphql_query_depth"
                                            name="silver_assist_graphql_query_depth"
                                            value="<?php echo esc_attr($graphql_query_depth); ?>" min="1" max="20"
                                            class="small-text" />
                                        <p class="description">
                                            <?php esc_html_e('Maximum allowed GraphQL query depth (1-20)', 'silver-assist-security'); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">
                                        <label for="silver_assist_graphql_query_complexity">
                                            <?php esc_html_e('Maximum Query Complexity', 'silver-assist-security'); ?>
                                        </label>
                                    </th>
                                    <td>
                                        <input type="number" id="silver_assist_graphql_query_complexity"
                                            name="silver_assist_graphql_query_complexity"
                                            value="<?php echo esc_attr($graphql_query_complexity); ?>" min="10" max="1000"
                                            class="small-text" />
                                        <p class="description">
                                            <?php esc_html_e('Maximum allowed GraphQL query complexity (10-1000)', 'silver-assist-security'); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row">
                                        <label for="silver_assist_graphql_query_timeout">
                                            <?php esc_html_e('Query Timeout (seconds)', 'silver-assist-security'); ?>
                                        </label>
                                    </th>
                                    <td>
                                        <input type="number" id="silver_assist_graphql_query_timeout"
                                            name="silver_assist_graphql_query_timeout"
                                            value="<?php echo esc_attr($graphql_query_timeout); ?>" min="1" max="30"
                                            class="small-text" />
                                        <p class="description">
                                            <?php esc_html_e('Maximum GraphQL query execution time (1-30 seconds)', 'silver-assist-security'); ?>
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    <?php endif; ?>

                    <?php submit_button(__('Save Security Settings', 'silver-assist-security'), 'primary', 'save_silver_assist_security'); ?>
                </form>

                <!-- Updates Information Section -->
                <?php $this->render_updates_section(); ?>
            </div>
            <?php
    }

    /**
     * Render updates information section
     * 
     * @since 1.0.0
     * @return void
     */
    private function render_updates_section(): void
    {
        // Get updater instance from Plugin
        $plugin = \SilverAssist\Security\Core\Plugin::getInstance();
        $updater = $plugin->get_updater();

        if (!$updater) {
            return;
        }

        $current_version = $updater->get_current_version();
        $latest_version = $updater->get_latest_version();
        $update_available = $updater->is_update_available();
        $github_repo = $updater->get_github_repo();

        ?>
            <div class="card">
                <h2><?php echo \esc_html(\__("Plugin Updates", "silver-assist-security")); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php echo \esc_html(\__("Current Version", "silver-assist-security")); ?></th>
                        <td><?php echo \esc_html($current_version); ?></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo \esc_html(\__("Latest Version", "silver-assist-security")); ?></th>
                        <td>
                            <?php echo \esc_html($latest_version ?: "Unknown"); ?>
                            <?php if ($update_available): ?>
                                <span class="dashicons dashicons-update" style="color: #d63638;"></span>
                                <strong
                                    style="color: #d63638;"><?php echo \esc_html(\__("Update Available!", "silver-assist-security")); ?></strong>
                            <?php else: ?>
                                <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                                <span
                                    style="color: #00a32a;"><?php echo \esc_html(\__("Up to date", "silver-assist-security")); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo \esc_html(\__("Repository", "silver-assist-security")); ?></th>
                        <td>
                            <a href="https://github.com/<?php echo \esc_attr($github_repo); ?>" target="_blank">
                                <?php echo \esc_html($github_repo); ?>
                            </a>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <button type="button" class="button button-secondary" id="check-silver-assist-version">
                        <?php echo \esc_html(\__("Check for Updates", "silver-assist-security")); ?>
                    </button>
                    <?php if ($update_available): ?>
                        <a href="<?php echo \esc_url(\admin_url("update-core.php")); ?>" class="button button-primary">
                            <?php echo \esc_html(\__("Go to Updates", "silver-assist-security")); ?>
                        </a>
                    <?php endif; ?>
                </p>
            </div>
            <?php
    }
}
