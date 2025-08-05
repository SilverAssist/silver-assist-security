<?php
/**
 * Silver Assist Security Essentials - Admin URL Security Protection
 *
 * Implements custom admin URLs to hide default WordPress admin paths.
 * Provides protection by obscuring wp-login.php and wp-admin paths
 * behind a configurable custom URL.
 *
 * @package SilverAssist\Security\Security
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.1
 */

namespace SilverAssist\Security\Security;

/**
 * Admin URL Security class
 * 
 * Handles custom admin URL routing and hides default admin paths
 * 
 * @since 1.0.0
 */
class AdminUrlSecurity
{

  /**
   * Custom admin URL slug
   * 
   * @var string
   */
  private string $custom_admin_url;

  /**
   * Whether to hide admin URLs
   * 
   * @var bool
   */
  private bool $hide_admin_urls;

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
    $this->custom_admin_url = \get_option("silver_assist_custom_admin_url", "silver-admin");
    $this->hide_admin_urls = (bool) \get_option("silver_assist_hide_admin_urls", 1);

    // Ensure custom URL is not a forbidden value
    $forbidden_urls = ["admin", "wp-admin", "login", "wp-login", "administrator"];
    if (in_array($this->custom_admin_url, $forbidden_urls)) {
      $this->custom_admin_url = "silver-admin";
      \update_option("silver_assist_custom_admin_url", $this->custom_admin_url);
    }
  }

  /**
   * Initialize admin URL security
   * 
   * @since 1.0.0
   * @return void
   */
  private function init(): void
  {
    if (!$this->hide_admin_urls) {
      return;
    }

    // Hook early to catch requests
    \add_action("init", [$this, "handle_custom_admin_url"], 1);
    \add_action("template_redirect", [$this, "block_default_admin_urls"], 1);

    // Modify login URL and admin URL functions
    \add_filter("wp_login_url", [$this, "custom_login_url"], 10, 2);
    \add_filter("admin_url", [$this, "custom_admin_url"], 10, 2);
    \add_filter("site_url", [$this, "custom_site_url"], 10, 4);

    // Handle redirects
    \add_action("wp_loaded", [$this, "handle_admin_redirects"]);

    // Add rewrite rules
    \add_action("init", [$this, "add_rewrite_rules"]);
    \add_filter("query_vars", [$this, "add_query_vars"]);
  }

  /**
   * Handle custom admin URL routing
   * 
   * @since 1.0.0
   * @return void
   */
  public function handle_custom_admin_url(): void
  {
    $request_uri = $_SERVER["REQUEST_URI"] ?? "";
    $parsed_url = parse_url($request_uri);
    $path = $parsed_url["path"] ?? "";

    // Check if this is our custom admin URL
    if (strpos($path, "/{$this->custom_admin_url}") === 0) {
      // Set up proper WordPress environment before routing
      $this->setup_admin_environment();
      $this->route_to_admin($path);
    }
  }

  /**
   * Setup proper WordPress environment for admin pages
   * 
   * @since 1.0.0
   * @return void
   */
  private function setup_admin_environment(): void
  {
    // Don't force any hooks - let WordPress handle its own initialization
    // This prevents conflicts with other plugins that may not be ready

    // Simply set the global to indicate we're in admin context
    global $pagenow;
    if (empty($pagenow)) {
      $pagenow = "wp-login.php";
    }
  }

  /**
   * Route custom admin URL to actual admin
   * 
   * @since 1.0.0
   * @param string $path Request path
   * @return void
   */
  private function route_to_admin(string $path): void
  {
    // Remove custom admin URL from path
    $admin_path = str_replace("/{$this->custom_admin_url}", "", $path);

    // Default to wp-login.php if no specific path
    if (empty($admin_path) || $admin_path === "/") {
      $admin_path = "/wp-login.php";
    }

    // Handle different admin paths
    if ($admin_path === "/wp-login.php" || strpos($admin_path, "/wp-login.php") === 0) {
      $this->serve_login_page();
    } elseif (strpos($admin_path, "/wp-admin") === 0) {
      $this->serve_admin_page($admin_path);
    } else {
      // Try to serve as wp-admin path
      $this->serve_admin_page("/wp-admin{$admin_path}");
    }
  }

  /**
   * Serve login page
   * 
   * @since 1.0.0
   * @return void
   */
  private function serve_login_page(): void
  {
    // Set up proper environment for wp-login.php
    $_SERVER["SCRIPT_NAME"] = "/wp-login.php";
    $_SERVER["PHP_SELF"] = "/wp-login.php";

    // Set login page globals for proper asset loading
    global $pagenow;
    $pagenow = "wp-login.php";

    // Ensure admin assets can load properly, but don't force it
    if (!defined("WP_ADMIN")) {
      define("WP_ADMIN", false);
    }

    // Only fire login_init if it hasn't been fired and it's safe to do so
    if (!\did_action("login_init") && function_exists("do_action")) {
      \do_action("login_init");
    }

    // Include WordPress login page
    if (file_exists(ABSPATH . "wp-login.php")) {
      require_once ABSPATH . "wp-login.php";
      exit;
    }
  }

  /**
   * Serve admin page
   * 
   * @since 1.0.0
   * @param string $admin_path Admin path to serve
   * @return void
   */
  private function serve_admin_page(string $admin_path): void
  {
    // Check if user is logged in for admin pages
    if (strpos($admin_path, "/wp-admin") === 0 && !$this->is_user_logged_in_check()) {
      // Redirect to custom login URL
      \wp_redirect($this->get_custom_login_url());
      exit;
    }

    // Set up environment for admin
    $_SERVER["SCRIPT_NAME"] = $admin_path;
    $_SERVER["PHP_SELF"] = $admin_path;

    // Handle admin-ajax.php
    if (strpos($admin_path, "admin-ajax.php") !== false) {
      if (file_exists(ABSPATH . "wp-admin/admin-ajax.php")) {
        require_once ABSPATH . "wp-admin/admin-ajax.php";
        exit;
      }
    }

    // Handle regular admin pages
    if (file_exists(ABSPATH . "wp-admin/index.php")) {
      require_once ABSPATH . "wp-admin/index.php";
      exit;
    }
  }

  /**
   * Block access to default admin URLs
   * 
   * @since 1.0.0
   * @return void
   */
  public function block_default_admin_urls(): void
  {
    $request_uri = $_SERVER["REQUEST_URI"] ?? "";
    $parsed_url = parse_url($request_uri);
    $path = $parsed_url["path"] ?? "";

    // List of paths to block
    $blocked_paths = [
      "/wp-login.php",
      "/wp-admin/",
      "/wp-admin",
      "/admin/",
      "/admin",
      "/administrator/",
      "/administrator"
    ];

    foreach ($blocked_paths as $blocked_path) {
      if (strpos($path, $blocked_path) === 0) {
        $this->send_404_response();
      }
    }
  }

  /**
   * Custom login URL filter
   * 
   * @since 1.0.0
   * @param string $login_url Login URL
   * @param string $redirect Redirect URL
   * @return string Modified login URL
   */
  public function custom_login_url(string $login_url, string $redirect = ""): string
  {
    $custom_url = \home_url("/{$this->custom_admin_url}/");

    if (!empty($redirect)) {
      $custom_url = \add_query_arg("redirect_to", urlencode($redirect), $custom_url);
    }

    return $custom_url;
  }

  /**
   * Custom admin URL filter
   * 
   * @since 1.0.0
   * @param string $url Admin URL
   * @param string $path Admin path
   * @return string Modified admin URL
   */
  public function custom_admin_url(string $url, string $path = ""): string
  {
    // Don't modify AJAX URLs
    if (strpos($path, "admin-ajax.php") !== false) {
      return $url;
    }

    // If we're already in the admin area, don't modify URLs
    if (\is_admin() && strpos($_SERVER["REQUEST_URI"] ?? "", $this->custom_admin_url) !== false) {
      return $url;
    }

    // For frontend admin bar links or direct admin access, redirect to custom login
    if (empty($path) || $path === "/" || $path === "index.php") {
      // This is the main admin URL - redirect to custom login
      return $this->get_custom_login_url();
    }

    // For specific admin pages, construct custom admin URL
    $home_url = \home_url();
    $admin_path = str_replace($home_url . "/wp-admin/", "", $url);

    return \home_url("/{$this->custom_admin_url}/wp-admin/{$admin_path}");
  }

  /**
   * Custom site URL filter
   * 
   * @since 1.0.0
   * @param string $url Site URL
   * @param string $path Path
   * @param string|null $scheme Scheme (can be null)
   * @param int|null $blog_id Blog ID (can be null)
   * @return string Modified site URL
   */
  public function custom_site_url(string $url, string $path, ?string $scheme, ?int $blog_id): string
  {
    if (strpos($path, "wp-login.php") !== false) {
      return $this->get_custom_login_url();
    }

    return $url;
  }

  /**
   * Handle admin redirects
   * 
   * @since 1.0.0
   * @return void
   */
  public function handle_admin_redirects(): void
  {
    // Handle redirects after login
    if (isset($_GET["redirect_to"])) {
      $redirect_to = $_GET["redirect_to"];
      if (strpos($redirect_to, "/wp-admin") !== false) {
        $new_redirect = str_replace("/wp-admin", "/{$this->custom_admin_url}/wp-admin", $redirect_to);
        \wp_redirect($new_redirect);
        exit;
      }
    }
  }

  /**
   * Add rewrite rules for custom admin URL
   * 
   * @since 1.0.0
   * @return void
   */
  public function add_rewrite_rules(): void
  {
    \add_rewrite_rule(
      "^{$this->custom_admin_url}/?$",
      "index.php?custom_admin=login",
      "top"
    );

    \add_rewrite_rule(
      "^{$this->custom_admin_url}/(.+)/?$",
      "index.php?custom_admin=admin&admin_path=\$matches[1]",
      "top"
    );
  }

  /**
   * Add query vars
   * 
   * @since 1.0.0
   * @param array $vars Query vars
   * @return array Modified query vars
   */
  public function add_query_vars(array $vars): array
  {
    $vars[] = "custom_admin";
    $vars[] = "admin_path";
    return $vars;
  }

  /**
   * Get custom login URL
   * 
   * @since 1.0.0
   * @return string Custom login URL
   */
  private function get_custom_login_url(): string
  {
    return \home_url("/{$this->custom_admin_url}/");
  }

  /**
   * Check if user is logged in (without triggering WordPress functions early)
   * 
   * @since 1.0.0
   * @return bool
   */
  private function is_user_logged_in_check(): bool
  {
    return function_exists("is_user_logged_in") && \is_user_logged_in();
  }

  /**
   * Send 404 Not Found response
   * 
   * @since 1.0.0
   * @return void
   */
  private function send_404_response(): void
  {
    // Log the blocked access attempt
    error_log(sprintf(
      "SECURITY_ALERT: Default admin URL blocked - IP: %s, User-Agent: %s, URI: %s, Timestamp: %s",
      $_SERVER["REMOTE_ADDR"] ?? "Unknown",
      $_SERVER["HTTP_USER_AGENT"] ?? "Unknown",
      $_SERVER["REQUEST_URI"] ?? "Unknown",
      date("Y-m-d H:i:s")
    ));

    // Send proper 404 headers
    if (function_exists("status_header")) {
      \status_header(404);
    } else {
      header("HTTP/1.1 404 Not Found");
    }

    if (function_exists("nocache_headers")) {
      \nocache_headers();
    } else {
      header("Cache-Control: no-cache, must-revalidate");
      header("Expires: Wed, 11 Jan 1984 05:00:00 GMT");
    }

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
   * Get current custom admin URL
   * 
   * @since 1.0.0
   * @return string Current custom admin URL slug
   */
  public function get_custom_admin_url(): string
  {
    return $this->custom_admin_url;
  }

  /**
   * Validate and set custom admin URL
   * 
   * @since 1.0.0
   * @param string $url New custom admin URL
   * @return bool True if valid and set, false otherwise
   */
  public function set_custom_admin_url(string $url): bool
  {
    // Sanitize URL
    $url = sanitize_key($url);

    // Check for forbidden values
    $forbidden_urls = ["admin", "wp-admin", "login", "wp-login", "administrator", "wp", "wordpress"];
    if (in_array($url, $forbidden_urls) || empty($url)) {
      return false;
    }

    // Update option
    \update_option("silver_assist_custom_admin_url", $url);
    $this->custom_admin_url = $url;

    // Flush rewrite rules
    \flush_rewrite_rules();

    return true;
  }
}
