<?php
/**
 * Silver Assist Security Essentials - General WordPress Security
 *
 * Implements general WordPress security hardening including security headers,
 * version hiding, user enumeration protection, and cookie security configuration.
 * Provides foundational security measures for WordPress installations.
 *
 * @package SilverAssist\Security\Security
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.1.0
 */

namespace SilverAssist\Security\Security;

/**
 * General Security class
 * 
 * Handles general WordPress security features like headers, version hiding, etc.
 * 
 * @since 1.0.0
 */
class GeneralSecurity
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
     * Initialize general security features
     * 
     * @since 1.0.0
     * @return void
     */
    private function init(): void
    {
        // Security headers
        \add_action("send_headers", [$this, "add_security_headers"]);

        // Hide WordPress version
        \add_filter("the_generator", [$this, "remove_version"]);

        // Remove unnecessary headers
        \add_action("init", [$this, "remove_unnecessary_headers"]);

        // Remove version from scripts and styles
        \add_filter("script_loader_src", [$this, "remove_version_query_string"]);
        \add_filter("style_loader_src", [$this, "remove_version_query_string"]);

        // Disable XML-RPC
        \add_filter("xmlrpc_methods", [$this, "remove_xmlrpc_methods"]);
        \add_filter("xmlrpc_enabled", "__return_false");

        // Configure secure cookies
        \add_action("init", [$this, "configure_secure_cookies"]);
        \add_filter("secure_auth_cookie", [$this, "force_secure_cookies"]);
        \add_filter("secure_logged_in_cookie", [$this, "force_secure_cookies"]);

        // Disable user enumeration
        \add_action("init", [$this, "disable_user_enumeration"]);

        // Hide login errors
        \add_filter("login_errors", [$this, "hide_login_errors"]);

        // Remove admin bar for non-admins
        \add_action("after_setup_theme", [$this, "remove_admin_bar_for_non_admins"]);

        // Disable file editing
        $this->disable_file_editing();

        // Remove WordPress branding
        \add_action("wp_before_admin_bar_render", [$this, "remove_wp_logo"]);
        \add_filter("admin_footer_text", [$this, "change_admin_footer"]);
    }

    /**
     * Add security headers
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_security_headers(): void
    {
        if (!headers_sent()) {
            // Content Security Policy
            header("X-Content-Type-Options: nosniff");
            header("X-Frame-Options: SAMEORIGIN");
            header("X-XSS-Protection: 1; mode=block");
            header("Referrer-Policy: strict-origin-when-cross-origin");
            header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

            // HSTS for HTTPS sites
            if (\is_ssl()) {
                header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
            }
        }
    }

    /**
     * Remove WordPress version
     * 
     * @since 1.0.0
     * @return string
     */
    public function remove_version(): string
    {
        return "";
    }

    /**
     * Remove unnecessary headers
     * 
     * @since 1.0.0
     * @return void
     */
    public function remove_unnecessary_headers(): void
    {
        \remove_action("wp_head", "rsd_link");
        \remove_action("wp_head", "wlwmanifest_link");
        \remove_action("wp_head", "wp_shortlink_wp_head");
        \remove_action("wp_head", "wp_generator");
        \remove_action("wp_head", "feed_links_extra", 3);
        \remove_action("wp_head", "feed_links", 2);
        \remove_action("wp_head", "index_rel_link");
        \remove_action("wp_head", "parent_post_rel_link", 10);
        \remove_action("wp_head", "start_post_rel_link", 10);
        \remove_action("wp_head", "adjacent_posts_rel_link_wp_head", 10);
        \remove_action("wp_head", "wp_oembed_add_discovery_links");
        \remove_action("wp_head", "wp_oembed_add_host_js");
        \remove_action("rest_api_init", "wp_oembed_register_route");
        \remove_filter("oembed_dataparse", "wp_filter_oembed_result", 10);
    }

    /**
     * Remove version query string from static resources
     * 
     * @since 1.0.0
     * @param string $src Source URL
     * @return string
     */
    public function remove_version_query_string(string $src): string
    {
        if (strpos($src, "ver=")) {
            $src = \remove_query_arg("ver", $src);
        }
        return $src;
    }

    /**
     * Remove XML-RPC methods
     * 
     * @since 1.0.0
     * @param array $methods XML-RPC methods
     * @return array
     */
    public function remove_xmlrpc_methods(array $methods): array
    {
        return [];
    }

    /**
     * Configure secure cookies
     * 
     * @since 1.0.0
     * @return void
     */
    public function configure_secure_cookies(): void
    {
        // Only configure session cookies if no session has started yet
        // This prevents disrupting existing sessions during plugin activation
        if (!headers_sent() && session_status() === PHP_SESSION_NONE) {
            $secure = \is_ssl();

            session_set_cookie_params([
                "lifetime" => 0,
                "path" => "/",
                "domain" => "",
                "secure" => $secure,
                "httponly" => true,
                "samesite" => "Lax"
            ]);
        }
    }

    /**
     * Force secure cookies
     * 
     * @since 1.0.0
     * @param bool $secure Current secure flag
     * @return bool
     */
    public function force_secure_cookies(bool $secure): bool
    {
        return \is_ssl();
    }

    /**
     * Disable user enumeration
     * 
     * @since 1.0.0
     * @return void
     */
    public function disable_user_enumeration(): void
    {
        // Disable author enumeration via REST API
        \add_filter("rest_endpoints", function ($endpoints) {
            if (isset($endpoints["/wp/v2/users"])) {
                unset($endpoints["/wp/v2/users"]);
            }
            if (isset($endpoints["/wp/v2/users/(?P<id>[\d]+)"])) {
                unset($endpoints["/wp/v2/users/(?P<id>[\d]+)"]);
            }
            return $endpoints;
        });

        // Disable author enumeration via URL
        \add_action("template_redirect", function () {
            if (\is_author() || ($_GET["author"] ?? false)) {
                \wp_redirect(\home_url());
                exit;
            }
        });

        // Remove author links from posts
        \add_filter("author_link", function () {
            return \home_url();
        });
    }

    /**
     * Hide login errors
     * 
     * @since 1.0.0
     * @return string
     */
    public function hide_login_errors(): string
    {
        return \__("Invalid login credentials.", "silver-assist-security");
    }

    /**
     * Remove admin bar for non-admins
     * 
     * @since 1.0.0
     * @return void
     */
    public function remove_admin_bar_for_non_admins(): void
    {
        if (!\current_user_can("administrator") && !\is_admin()) {
            \show_admin_bar(false);
        }
    }

    /**
     * Disable file editing
     * 
     * @since 1.0.0
     * @return void
     */
    private function disable_file_editing(): void
    {
        if (!defined("DISALLOW_FILE_EDIT")) {
            define("DISALLOW_FILE_EDIT", true);
        }
    }

    /**
     * Remove WordPress logo from admin bar
     * 
     * @since 1.0.0
     * @return void
     */
    public function remove_wp_logo(): void
    {
        global $wp_admin_bar;
        $wp_admin_bar->remove_menu("wp-logo");
    }

    /**
     * Change admin footer text
     * 
     * @since 1.0.0
     * @return string
     */
    public function change_admin_footer(): string
    {
        return sprintf(
            /* translators: %s: plugin name with HTML formatting */
            \__("Secured by %s", "silver-assist-security"),
            "<strong>Silver Assist Security Essentials</strong>"
        );
    }

    /**
     * Get client IP address
     * 
     * @since 1.0.0
     * @return string
     */
    public function get_client_ip(): string
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
}
