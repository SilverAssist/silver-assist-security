<?php
/**
 * Silver Assist Security Essentials - Login Security Protection
 *
 * Implements comprehensive login security including failed attempt tracking,
 * IP-based lockouts, session timeout management, and password strength enforcement.
 * Provides protection against brute force attacks and unauthorized access.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.5
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;

/**
 * Login Security class
 * 
 * Handles login attempt limiting, lockouts, and login form security
 * 
 * @since 1.1.1
 */
class LoginSecurity
{

    /**
     * Maximum login attempts
     * 
     * @var int
     */
    private int $max_attempts;

    /**
     * Lockout duration in seconds
     * 
     * @var int
     */
    private int $lockout_duration;

    /**
     * Session timeout in minutes
     * 
     * @var int
     */
    private int $session_timeout;

    /**
     * Constructor
     * 
     * @since 1.1.1
     */
    public function __construct()
    {
        $this->init_configuration();
        $this->init();
    }

    /**
     * Initialize configuration
     * 
     * @since 1.1.1
     * @return void
     */
    private function init_configuration(): void
    {
        $this->max_attempts = (int) DefaultConfig::get_option("silver_assist_login_attempts");
        $this->lockout_duration = (int) DefaultConfig::get_option("silver_assist_lockout_duration");
        $this->session_timeout = (int) DefaultConfig::get_option("silver_assist_session_timeout");
    }

    /**
     * Initialize login security
     * 
     * @since 1.1.1
     * @return void
     */
    private function init(): void
    {
        // Login form hooks
        \add_action("login_form", [$this, "add_login_form_security"]);
        \add_action("login_init", [$this, "setup_login_protection"]);

        // Bot and crawler protection
        \add_action("login_init", [$this, "block_suspicious_bots"], 5);
        \add_action("wp_login_failed", [$this, "track_bot_behavior"]);

        // Login attempt tracking
        \add_action("wp_login_failed", [$this, "handle_failed_login"]);
        \add_filter("authenticate", [$this, "check_login_lockout"], 30, 3);
        \add_action("wp_login", [$this, "handle_successful_login"], 10, 2);

        // Session management
        \add_action("init", [$this, "setup_session_timeout"]);
        \add_action("wp_logout", [$this, "clear_login_attempts"]);

        // Password reset security
        $this->init_password_security();
    }

    /**
     * Initialize password security features
     * 
     * @since 1.1.1
     * @return void
     */
    private function init_password_security(): void
    {
        $password_strength_enforcement = DefaultConfig::get_option("silver_assist_password_strength_enforcement");

        if ($password_strength_enforcement) {
            \add_action("user_profile_update_errors", [$this, "validate_password_strength"], 10, 3);
            \add_action("validate_password_reset", [$this, "validate_password_strength_reset"], 10, 2);
        }
    }

    /**
     * Add security fields to login form
     * 
     * @since 1.1.1
     * @return void
     */
    public function add_login_form_security(): void
    {
        // Add nonce field
        \wp_nonce_field("secure_login_action", "secure_login_nonce");

        // Add honeypot field (hidden from users)
        echo "<p style=\"position: absolute; left: -9999px;\">";
        echo "<label for=\"website_url\">" . \__("Website URL (leave blank):", "silver-assist-security") . "</label>";
        echo "<input type=\"text\" name=\"website_url\" id=\"website_url\" value=\"\" tabindex=\"-1\" autocomplete=\"off\" />";
        echo "</p>";
    }

    /**
     * Setup login protection
     * 
     * @since 1.1.1
     * @return void
     */
    public function setup_login_protection(): void
    {
        if ($_SERVER["REQUEST_METHOD"] !== "POST") {
            return;
        }

        // Check honeypot
        if (isset($_POST["website_url"]) && !empty($_POST["website_url"])) {
            \wp_die(\__("Security check failed.", "silver-assist-security"));
        }

        // Verify nonce
        if (isset($_POST["log"]) && function_exists("wp_verify_nonce")) {
            if (!\wp_verify_nonce($_POST["secure_login_nonce"] ?? "", "secure_login_action")) {
                error_log("Nonce verification failed for login attempt");
            }
        }
    }

    /**
     * Handle failed login attempt
     * 
     * @since 1.1.1
     * @param string $username Username that failed login
     * @return void
     */
    public function handle_failed_login(string $username): void
    {
        $ip = $this->get_client_ip();
        $key = "login_attempts_{md5($ip)}";

        $attempts = \get_transient($key) ?: 0;
        $attempts++;

        \set_transient($key, $attempts, $this->lockout_duration);

        if ($attempts >= $this->max_attempts) {
            // Log the lockout
            error_log(sprintf(
                "User locked out after %d failed attempts. IP: %s, Username: %s",
                $attempts,
                $ip,
                $username
            ));

            // Set lockout flag
            \set_transient("lockout_{md5($ip)}", true, $this->lockout_duration);
        }
    }

    /**
     * Check if user is locked out
     * 
     * @since 1.1.1
     * @param \WP_User|\WP_Error|null $user User object or error
     * @param string $username Username
     * @param string $password Password
     * @return \WP_User|\WP_Error
     */
    public function check_login_lockout($user, string $username, string $password)
    {
        // Skip if no username/password provided
        if (empty($username) || empty($password)) {
            return $user;
        }

        $ip = $this->get_client_ip();
        $lockout_key = "lockout_{md5($ip)}";
        $attempts_key = "login_attempts_{md5($ip)}";

        // Check if IP is locked out
        if (\get_transient($lockout_key)) {
            $attempts = \get_transient($attempts_key) ?: 0;
            $remaining_time = $this->get_remaining_lockout_time($lockout_key);

            return new \WP_Error(
                "login_locked",
                sprintf(
                    /* translators: %d: number of minutes remaining until unlock */
                    \__("Too many failed login attempts. Try again in %d minutes.", "silver-assist-security"),
                    ceil($remaining_time / 60)
                )
            );
        }

        return $user;
    }

    /**
     * Handle successful login
     * 
     * @since 1.1.1
     * @param string $user_login Username
     * @param \WP_User $user User object
     * @return void
     */
    public function handle_successful_login(string $user_login, \WP_User $user): void
    {
        // Clear login attempts on successful login
        $this->clear_login_attempts();

        // Set session timeout
        $this->set_session_timeout();
    }

    /**
     * Setup session timeout
     * 
     * @since 1.1.1
     * @return void
     */
    public function setup_session_timeout(): void
    {
        if (\is_user_logged_in()) {
            $user_id = \get_current_user_id();
            $last_activity = \get_user_meta($user_id, "last_activity", true);
            $timeout = $this->session_timeout * 60; // Convert to seconds

            // Only check timeout if last_activity exists and is not empty
            // This prevents logout during plugin activation when last_activity hasn't been set yet
            if ($last_activity && is_numeric($last_activity) && (int) $last_activity > 0) {
                $time_since_last_activity = time() - (int) $last_activity;

                // Only logout if timeout exceeded and not in admin area during plugin management
                if (
                    $time_since_last_activity > $timeout &&
                    (!\is_admin() ||
                        (!\current_user_can("activate_plugins") && !isset($_GET["page"]) && !isset($_POST["action"])))
                ) {
                    \wp_logout();
                    \wp_redirect(\wp_login_url() . "?session_expired=1");
                    exit;
                }
            }

            // Always update last activity for logged-in users (but only if not empty)
            // This ensures we initialize last_activity for new users
            \update_user_meta($user_id, "last_activity", time());
        }
    }

    /**
     * Set session timeout
     * 
     * @since 1.1.1
     * @return void
     */
    private function set_session_timeout(): void
    {
        if (\is_user_logged_in()) {
            \update_user_meta(\get_current_user_id(), "last_activity", time());
        }
    }

    /**
     * Clear login attempts for current IP
     * 
     * @since 1.1.1
     * @return void
     */
    public function clear_login_attempts(): void
    {
        $ip = $this->get_client_ip();
        \delete_transient("login_attempts_{md5($ip)}");
        \delete_transient("lockout_{md5($ip)}");
    }

    /**
     * Validate password strength
     * 
     * @since 1.1.1
     * @param \WP_Error $errors Errors object
     * @param bool $update Whether this is a user update
     * @param \WP_User $user User object
     * @return void
     */
    public function validate_password_strength(\WP_Error $errors, bool $update, \WP_User $user): void
    {
        if (isset($_POST["pass1"]) && !empty($_POST["pass1"])) {
            $password = $_POST["pass1"];

            if (!$this->is_strong_password($password)) {
                $errors->add(
                    "weak_password",
                    \__("Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.", "silver-assist-security")
                );
            }
        }
    }

    /**
     * Validate password strength on reset
     * 
     * @since 1.1.1
     * @param \WP_Error $errors Errors object
     * @param \WP_User $user User object
     * @return void
     */
    public function validate_password_strength_reset(\WP_Error $errors, \WP_User $user): void
    {
        if (isset($_POST["pass1"]) && !empty($_POST["pass1"])) {
            $password = $_POST["pass1"];

            if (!$this->is_strong_password($password)) {
                $errors->add(
                    "weak_password",
                    \__("Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.", "silver-assist-security")
                );
            }
        }
    }

    /**
     * Check if password is strong
     * 
     * @since 1.1.1
     * @param string $password Password to check
     * @return bool
     */
    private function is_strong_password(string $password): bool
    {
        // At least 8 characters
        if (strlen($password) < 8) {
            return false;
        }

        // Must contain uppercase letter
        if (!preg_match("/[A-Z]/", $password)) {
            return false;
        }

        // Must contain lowercase letter
        if (!preg_match("/[a-z]/", $password)) {
            return false;
        }

        // Must contain number
        if (!preg_match("/[0-9]/", $password)) {
            return false;
        }

        // Must contain special character
        if (!preg_match("/[^A-Za-z0-9]/", $password)) {
            return false;
        }

        return true;
    }

    /**
     * Get client IP address
     * 
     * @since 1.1.1
     * @return string
     */
    private function get_client_ip(): string
    {
        $ip_keys = [
            "HTTP_CF_CONNECTING_IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "REMOTE_ADDR"
        ];

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(",", $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";
    }

    /**
     * Get remaining lockout time
     * 
     * @since 1.1.1
     * @param string $lockout_key Lockout transient key
     * @return int Remaining time in seconds
     */
    private function get_remaining_lockout_time(string $lockout_key): int
    {
        global $wpdb;

        $transient_timeout = $wpdb->get_var($wpdb->prepare(
            "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
            "_transient_timeout_{$lockout_key}"
        ));

        if ($transient_timeout) {
            return max(0, $transient_timeout - time());
        }

        return 0;
    }

    /**
     * Block suspicious bots and crawlers from accessing login page
     * 
     * @since 1.1.1
     * @return void
     */
    public function block_suspicious_bots(): void
    {
        // Check if bot protection is enabled
        $bot_protection_enabled = DefaultConfig::get_option("silver_assist_bot_protection");
        if (!$bot_protection_enabled) {
            return;
        }

        $user_agent = $_SERVER["HTTP_USER_AGENT"] ?? "";
        $ip = $this->get_client_ip();

        // List of known bot/crawler patterns
        $bot_patterns = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "scan",
            "probe",
            "wget",
            "curl",
            "python",
            "php",
            "perl",
            "java",
            "masscan",
            "nmap",
            "nikto",
            "sqlmap",
            "gobuster",
            "dirb",
            "dirbuster",
            "wpscan",
            "nuclei",
            "httpx"
        ];

        // Check if user agent matches bot patterns
        $is_bot = false;
        foreach ($bot_patterns as $pattern) {
            if (stripos($user_agent, $pattern) !== false) {
                $is_bot = true;
                break;
            }
        }

        // Additional checks for suspicious behavior
        if (!$is_bot) {
            // Check for empty or very short user agents (common in bots)
            if (empty($user_agent) || strlen($user_agent) < 10) {
                $is_bot = true;
            }

            // Check for missing common browser headers
            if (!isset($_SERVER["HTTP_ACCEPT"]) || !isset($_SERVER["HTTP_ACCEPT_LANGUAGE"])) {
                $is_bot = true;
            }

            // Check for rapid access patterns
            $access_key = "login_access_{md5($ip)}";
            $recent_access = \get_transient($access_key) ?: 0;
            if ($recent_access > 5) { // More than 5 requests in last minute
                $is_bot = true;
            }
            \set_transient($access_key, $recent_access + 1, 60);
        }

        if ($is_bot) {
            $this->send_404_response();
        }
    }

    /**
     * Track bot behavior for additional security measures
     * 
     * @since 1.1.1
     * @return void
     */
    public function track_bot_behavior(): void
    {
        $ip = $this->get_client_ip();
        $user_agent = $_SERVER["HTTP_USER_AGENT"] ?? "Unknown";

        // Log bot activity for security monitoring
        $bot_log_key = "bot_activity_{md5($ip)}";
        $bot_activity = \get_transient($bot_log_key) ?: [];

        $bot_activity[] = [
            "timestamp" => time(),
            "user_agent" => $user_agent,
            "method" => $_SERVER["REQUEST_METHOD"] ?? "GET",
            "uri" => $_SERVER["REQUEST_URI"] ?? ""
        ];

        // Keep only last 10 activities
        if (count($bot_activity) > 10) {
            $bot_activity = array_slice($bot_activity, -10);
        }

        \set_transient($bot_log_key, $bot_activity, 3600); // Store for 1 hour

        // If too many bot activities, extend blocking
        if (count($bot_activity) > 3) {
            $extended_block_key = "extended_bot_block_{md5($ip)}";
            \set_transient($extended_block_key, true, 7200); // Block for 2 hours
        }
    }

    /**
     * Send 404 Not Found response to bots
     * 
     * @since 1.1.1
     * @return void
     */
    private function send_404_response(): void
    {
        // Log the blocked access attempt
        error_log(sprintf(
            "SECURITY_ALERT: Bot blocked from login page - IP: %s, User-Agent: %s, Timestamp: %s",
            $this->get_client_ip(),
            $_SERVER["HTTP_USER_AGENT"] ?? "Unknown",
            \current_time("mysql")
        ));

        // Send proper 404 headers
        \status_header(404);
        \nocache_headers();

        // Send minimal 404 page content
        echo "<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <meta name=\"robots\" content=\"noindex,nofollow,noarchive,nosnippet,noimageindex\">
</head>
<body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>";

        exit;
    }

    /**
     * Check if IP is in extended bot block list
     * 
     * @since 1.1.1
     * @param string $ip IP address to check
     * @return bool True if blocked
     */
    private function is_bot_blocked(string $ip): bool
    {
        $extended_block_key = "extended_bot_block_{md5($ip)}";
        return \get_transient($extended_block_key) !== false;
    }
}
