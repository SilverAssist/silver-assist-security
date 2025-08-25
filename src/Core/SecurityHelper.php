<?php
/**
 * Silver Assist Security Essentials - Security Helper Utilities
 *
 * Centralized helper functions for common security operations including
 * asset management, IP detection, password validation, and security logging.
 * Eliminates code duplication across security components.
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.10
 * @author Silver Assist
 * @version 1.1.10
 */

namespace SilverAssist\Security\Core;

/**
 * Security Helper class
 * 
 * Provides centralized utility functions for common security operations
 * 
 * @since 1.1.10
 */
class SecurityHelper
{
  /**
   * Plugin URL for assets
   * 
   * @var string
   */
  private static string $plugin_url;

  /**
   * Plugin version for cache busting
   * 
   * @var string
   */
  private static string $plugin_version;

  /**
   * Initialize SecurityHelper with plugin constants
   * 
   * @since 1.1.10
   * @return void
   */
  public static function init(): void
  {
    self::$plugin_url = SILVER_ASSIST_SECURITY_URL;
    self::$plugin_version = SILVER_ASSIST_SECURITY_VERSION;
  }
  /**
   * Get asset URL with minification support
   * 
   * Returns minified version when SCRIPT_DEBUG is not true, regular version otherwise.
   * This centralizes asset loading logic across all components.
   * 
   * @since 1.1.10
   * @param string $asset_path The relative path to the asset (e.g., 'assets/css/admin.css')
   * @return string The full URL to the asset
   */
  public static function get_asset_url(string $asset_path): string
  {
    // Initialize if not already done
    if (!isset(self::$plugin_url)) {
      self::init();
    }

    $min_suffix = (defined("SCRIPT_DEBUG") && SCRIPT_DEBUG) ? "" : ".min";
    $file_info = pathinfo($asset_path);

    // Construct minified path: assets/css/admin.css -> assets/css/admin.min.css
    $minified_path = $file_info["dirname"] . "/" . $file_info["filename"] . $min_suffix . "." . $file_info["extension"];

    return self::$plugin_url . $minified_path;
  }

  /**
   * Get client IP address with proper header detection
   * 
   * Checks various headers for real IP address detection, especially
   * useful behind proxies, CDNs (CloudFlare), and load balancers.
   * 
   * @since 1.1.10
   * @return string Client IP address
   */
  public static function get_client_ip(): string
  {
    $ip_keys = [
      "HTTP_CF_CONNECTING_IP",     // CloudFlare
      "HTTP_CLIENT_IP",            // Proxy
      "HTTP_X_FORWARDED_FOR",      // Load balancer/proxy
      "HTTP_X_FORWARDED",          // Proxy
      "HTTP_FORWARDED_FOR",        // Proxy
      "HTTP_FORWARDED",            // Proxy
      "REMOTE_ADDR"                // Standard
    ];

    foreach ($ip_keys as $key) {
      if (array_key_exists($key, $_SERVER) === true) {
        foreach (explode(",", $_SERVER[$key]) as $ip) {
          $ip = trim($ip);
          // Validate IP and exclude private/reserved ranges
          if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            return $ip;
          }
        }
      }
    }

    return $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";
  }

  /**
   * Send 404 Not Found response with security-focused headers
   * 
   * Sends a proper 404 response to hide sensitive endpoints from bots,
   * crawlers, and security scanners. Includes anti-indexing headers.
   * 
   * @since 1.1.10
   * @param bool $use_wordpress_template Whether to try loading WordPress 404 template
   * @return void
   */
  public static function send_404_response(bool $use_wordpress_template = true): void
  {
    // Send proper 404 headers
    \status_header(404);
    \nocache_headers();

    // Additional security headers
    header("X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex", true);

    if ($use_wordpress_template) {
      // Try to load WordPress 404 template for better integration
      $template_404 = \get_404_template();
      if ($template_404) {
        include $template_404;
        exit;
      }
    }

    // Fallback minimal 404 response
    echo "<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <meta name=\"robots\" content=\"noindex,nofollow,noarchive,nosnippet,noimageindex\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
</head>
<body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>";

    exit;
  }

  /**
   * Check if password meets strong password requirements
   * 
   * Validates password strength according to security best practices:
   * - Minimum 8 characters
   * - Contains uppercase letter
   * - Contains lowercase letter  
   * - Contains number
   * - Contains special character
   * 
   * @since 1.1.10
   * @param string $password Password to validate
   * @return bool True if password is strong
   */
  public static function is_strong_password(string $password): bool
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
   * Log security event with structured format
   * 
   * Creates standardized security log entries with timestamp, IP, 
   * user agent, and context information for security monitoring.
   * 
   * @since 1.1.10
   * @param string $event_type Type of security event (e.g., 'LOGIN_FAILED', 'BOT_BLOCKED')
   * @param string $message Human-readable event description
   * @param array $context Additional context data (optional)
   * @return void
   */
  public static function log_security_event(string $event_type, string $message, array $context = []): void
  {
    $log_data = [
      "event_type" => $event_type,
      "message" => $message,
      "timestamp" => \current_time("mysql"),
      "ip" => self::get_client_ip(),
      "user_agent" => $_SERVER["HTTP_USER_AGENT"] ?? "Unknown",
      "request_uri" => $_SERVER["REQUEST_URI"] ?? "",
      "context" => $context
    ];

    // Log as structured JSON for better parsing
    error_log(sprintf(
      "SILVER_ASSIST_SECURITY: %s - %s",
      $event_type,
      wp_json_encode($log_data, JSON_UNESCAPED_SLASHES)
    ));
  }

  /**
   * Format time duration in human-readable format
   * 
   * Converts seconds to human-readable time format (e.g., "5 minutes", "1 hour").
   * Useful for displaying lockout durations and timeouts.
   * 
   * @since 1.1.10
   * @param int $seconds Duration in seconds
   * @return string Human-readable time format
   */
  public static function format_time_duration(int $seconds): string
  {
    if ($seconds < 60) {
      return sprintf(
        /* translators: %d: number of seconds */
        \__("%d seconds", "silver-assist-security"),
        $seconds
      );
    }

    $minutes = round($seconds / 60);
    if ($minutes < 60) {
      return sprintf(
        /* translators: %d: number of minutes */
        \__("%d minutes", "silver-assist-security"),
        $minutes
      );
    }

    $hours = round($minutes / 60);
    return sprintf(
      /* translators: %d: number of hours */
      \__("%d hours", "silver-assist-security"),
      $hours
    );
  }

  /**
   * Validate WordPress nonce with enhanced error handling
   * 
   * Centralized nonce validation with proper error responses
   * and security logging for failed attempts.
   * 
   * @since 1.1.10
   * @param string $nonce Nonce value to verify
   * @param string $action Nonce action name
   * @param bool $die_on_failure Whether to wp_die() on failure
   * @return bool True if nonce is valid
   */
  public static function verify_nonce(string $nonce, string $action, bool $die_on_failure = true): bool
  {
    if (!\wp_verify_nonce($nonce, $action)) {
      self::log_security_event(
        "NONCE_VALIDATION_FAILED",
        "Invalid nonce for action: {$action}",
        ["action" => $action, "nonce" => $nonce]
      );

      if ($die_on_failure) {
        \wp_die(\__("Security check failed.", "silver-assist-security"));
      }

      return false;
    }

    return true;
  }

  /**
   * Check if user has required capability with security logging
   * 
   * Centralized capability checking with security event logging
   * for unauthorized access attempts.
   * 
   * @since 1.1.10
   * @param string $capability Required capability
   * @param bool $die_on_failure Whether to wp_die() on failure
   * @return bool True if user has capability
   */
  public static function check_user_capability(string $capability, bool $die_on_failure = true): bool
  {
    if (!\current_user_can($capability)) {
      $user_id = \get_current_user_id();
      $user = $user_id ? \get_userdata($user_id) : null;

      self::log_security_event(
        "CAPABILITY_CHECK_FAILED",
        "User lacks required capability: {$capability}",
        [
          "required_capability" => $capability,
          "user_id" => $user_id,
          "user_login" => $user ? $user->user_login : "anonymous"
        ]
      );

      if ($die_on_failure) {
        \wp_die(\__("You do not have sufficient permissions to access this page.", "silver-assist-security"));
      }

      return false;
    }

    return true;
  }

  /**
   * Generate secure transient key for IP-based tracking
   * 
   * Creates consistent, secure keys for IP-based transient storage
   * used in rate limiting, lockouts, and tracking.
   * 
   * @since 1.1.10
   * @param string $prefix Key prefix (e.g., 'login_attempts', 'lockout')
   * @param string|null $ip IP address (uses current IP if null)
   * @return string Secure transient key
   */
  public static function generate_ip_transient_key(string $prefix, ?string $ip = null): string
  {
    if ($ip === null) {
      $ip = self::get_client_ip();
    }

    return "{$prefix}_" . md5($ip);
  }

  /**
   * Sanitize and validate admin path input
   * 
   * Centralized path sanitization for admin hide functionality
   * with proper validation and security checks.
   * 
   * @since 1.1.10
   * @param string $path Path to sanitize
   * @return string Sanitized path
   */
  public static function sanitize_admin_path(string $path): string
  {
    // Remove any potentially dangerous characters
    $path = \sanitize_title($path);

    // Ensure minimum length
    if (strlen($path) < 3) {
      $path = "silver-admin";
    }

    // Ensure maximum length
    if (strlen($path) > 50) {
      $path = substr($path, 0, 50);
    }

    return $path;
  }

  /**
   * Check if current request is from a known bot or crawler
   * 
   * Analyzes user agent and request patterns to identify automated
   * tools, security scanners, and malicious bots.
   * 
   * @since 1.1.10
   * @param string|null $user_agent User agent string (uses current if null)
   * @return bool True if request appears to be from a bot
   */
  public static function is_bot_request(?string $user_agent = null): bool
  {
    if ($user_agent === null) {
      $user_agent = $_SERVER["HTTP_USER_AGENT"] ?? "";
    }

    // Known bot/crawler patterns
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

    foreach ($bot_patterns as $pattern) {
      if (stripos($user_agent, $pattern) !== false) {
        return true;
      }
    }

    // Additional bot detection patterns
    if (empty($user_agent) || strlen($user_agent) < 10) {
      return true;
    }

    // Check for missing common browser headers
    if (
      !isset($_SERVER["HTTP_ACCEPT"]) &&
      !isset($_SERVER["HTTP_ACCEPT_LANGUAGE"]) &&
      !isset($_SERVER["HTTP_ACCEPT_ENCODING"])
    ) {
      return true;
    }

    return false;
  }

  /**
   * Validate AJAX request with comprehensive security checks
   * 
   * Performs complete AJAX request validation including nonce verification,
   * capability checks, and request method validation.
   * 
   * @since 1.1.10
   * @param string $nonce_action Nonce action name
   * @param string $required_capability Required user capability
   * @param string $allowed_method Allowed HTTP method (default: POST)
   * @return bool True if request is valid
   */
  public static function validate_ajax_request(
    string $nonce_action,
    string $required_capability = "manage_options",
    string $allowed_method = "POST"
  ): bool {
    // Check HTTP method
    if ($_SERVER["REQUEST_METHOD"] !== $allowed_method) {
      self::log_security_event(
        "AJAX_INVALID_METHOD",
        "Invalid HTTP method for AJAX request",
        ["expected" => $allowed_method, "actual" => $_SERVER["REQUEST_METHOD"]]
      );
      return false;
    }

    // Verify nonce
    $nonce = $_POST["nonce"] ?? $_GET["nonce"] ?? "";
    if (!self::verify_nonce($nonce, $nonce_action, false)) {
      return false;
    }

    // Check user capability
    if (!self::check_user_capability($required_capability, false)) {
      return false;
    }

    return true;
  }
}
