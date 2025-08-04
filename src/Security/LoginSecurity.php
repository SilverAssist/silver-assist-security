<?php
/**
 * Silver Assist Security Suite - Login Security Protection
 *
 * Implements comprehensive login security including failed attempt tracking,
 * IP-based lockouts, session timeout management, and password strength enforcement.
 * Provides protection against brute force attacks and unauthorized access.
 *
 * @package SilverAssist\Security\Security
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.0
 */

namespace SilverAssist\Security\Security;

/**
 * Login Security class
 * 
 * Handles login attempt limiting, lockouts, and login form security
 * 
 * @since 1.0.0
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
     * @since 1.0.0
     */
    public function __construct()
    {
        $this->init_configuration();
        $this->init();
    }

    /**
     * Initialize configuration
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_configuration(): void
    {
        $this->max_attempts = (int) \get_option("silver_assist_login_attempts", 5);
        $this->lockout_duration = (int) \get_option("silver_assist_lockout_duration", 900);
        $this->session_timeout = (int) \get_option("silver_assist_session_timeout", 30);
    }

    /**
     * Initialize login security
     * 
     * @since 1.0.0
     * @return void
     */
    private function init(): void
    {
        // Login form hooks
        \add_action("login_form", [$this, "add_login_form_security"]);
        \add_action("login_init", [$this, "setup_login_protection"]);

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
     * @since 1.0.0
     * @return void
     */
    private function init_password_security(): void
    {
        $password_reset_enforcement = \get_option("silver_assist_password_reset_enforcement", 1);
        $password_strength_enforcement = \get_option("silver_assist_password_strength_enforcement", 1);
        $admin_password_reset = \get_option("silver_assist_admin_password_reset", 0);

        if ($password_reset_enforcement) {
            \add_action("wp_login", [$this, "check_password_reset_requirement"], 10, 2);
        }

        if ($password_strength_enforcement) {
            \add_action("user_profile_update_errors", [$this, "validate_password_strength"], 10, 3);
            \add_action("validate_password_reset", [$this, "validate_password_strength_reset"], 10, 2);
        }

        if (!$admin_password_reset) {
            \add_filter("allow_password_reset", [$this, "disable_admin_password_reset"], 10, 2);
        }
    }

    /**
     * Add security fields to login form
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
     * @return void
     */
    public function setup_session_timeout(): void
    {
        if (\is_user_logged_in()) {
            $last_activity = \get_user_meta(\get_current_user_id(), "last_activity", true);
            $timeout = $this->session_timeout * 60; // Convert to seconds

            if ($last_activity && (time() - $last_activity) > $timeout) {
                \wp_logout();
                \wp_redirect(\wp_login_url() . "?session_expired=1");
                exit;
            }

            // Update last activity
            \update_user_meta(\get_current_user_id(), "last_activity", time());
        }
    }

    /**
     * Set session timeout
     * 
     * @since 1.0.0
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
     * @since 1.0.0
     * @return void
     */
    public function clear_login_attempts(): void
    {
        $ip = $this->get_client_ip();
        \delete_transient("login_attempts_{md5($ip)}");
        \delete_transient("lockout_{md5($ip)}");
    }

    /**
     * Check password reset requirement
     * 
     * @since 1.0.0
     * @param string $user_login Username
     * @param \WP_User $user User object
     * @return void
     */
    public function check_password_reset_requirement(string $user_login, \WP_User $user): void
    {
        $needs_reset = \get_user_meta($user->ID, "force_password_reset", true);

        if ($needs_reset) {
            \wp_logout();
            \wp_redirect(\wp_login_url() . "?force_reset=1&user_id=" . $user->ID);
            exit;
        }
    }

    /**
     * Validate password strength
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * Disable admin password reset
     * 
     * @since 1.0.0
     * @param bool $allow Whether to allow password reset
     * @param int $user_id User ID
     * @return bool
     */
    public function disable_admin_password_reset(bool $allow, int $user_id): bool
    {
        $user = \get_user_by("id", $user_id);

        if ($user && in_array("administrator", $user->roles)) {
            return false;
        }

        return $allow;
    }

    /**
     * Check if password is strong
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
}
