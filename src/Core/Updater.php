<?php
/**
 * Silver Assist Security Essentials - Custom GitHub Updates Handler
 *
 * Handles automatic updates from public GitHub releases for the Silver Assist Security Essentials.
 * Provides seamless WordPress admin updates without requiring authentication tokens.
 *
 * @package SilverAssist\Security\Core
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.3
 */

namespace SilverAssist\Security\Core;

// Prevent direct access
defined("ABSPATH") or exit;

/**
 * Class Updater
 *
 * Handles automatic plugin updates from GitHub releases.
 */
class Updater
{
    /**
     * Plugin file path
     * @var string
     */
    private string $plugin_file;

    /**
     * Plugin slug (folder/file.php)
     * @var string
     */
    private string $plugin_slug;

    /**
     * Plugin basename (folder name only)
     * @var string
     */
    private string $plugin_basename;

    /**
     * GitHub repository (owner/repo)
     * @var string
     */
    private string $github_repo;

    /**
     * Current plugin version
     * @var string
     */
    private string $current_version;

    /**
     * Plugin data from header
     * @var array
     */
    private array $plugin_data;

    /**
     * Transient name for version cache
     * @var string
     */
    private string $version_transient;

    /**
     * Initialize the updater
     *
     * @param string $plugin_file Full path to main plugin file
     * @param string $github_repo GitHub repository in format "owner/repo"
     */
    public function __construct(string $plugin_file, string $github_repo)
    {
        $this->plugin_file = $plugin_file;
        $this->plugin_slug = \plugin_basename($plugin_file);
        $this->plugin_basename = dirname($this->plugin_slug);
        $this->github_repo = $github_repo;
        $this->version_transient = "{$this->plugin_basename}_version_check";

        // Get plugin data
        if (!function_exists("get_plugin_data")) {
            require_once ABSPATH . "wp-admin/includes/plugin.php";
        }
        $this->plugin_data = \get_plugin_data($plugin_file);
        $this->current_version = $this->plugin_data["Version"];

        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks(): void
    {
        \add_filter("pre_set_site_transient_update_plugins", [$this, "check_for_update"]);
        \add_filter("plugins_api", [$this, "plugin_info"], 20, 3);
        \add_action("upgrader_process_complete", [$this, "clear_version_cache"], 10, 2);

        // Add custom action for manual version check
        \add_action("wp_ajax_silver_assist_security_check_version", [$this, "manual_version_check"]);
    }

    /**
     * Check for plugin updates
     *
     * @param mixed $transient The update_plugins transient
     * @return mixed
     */
    public function check_for_update($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        // Get latest version from GitHub
        $latest_version = $this->get_latest_version();

        if ($latest_version && version_compare($this->current_version, $latest_version, "<")) {
            $transient->response[$this->plugin_slug] = (object) [
                "slug" => $this->plugin_basename,
                "plugin" => $this->plugin_slug,
                "new_version" => $latest_version,
                "url" => "https://github.com/{$this->github_repo}",
                "package" => $this->get_download_url($latest_version),
                "tested" => \get_bloginfo("version"),
                "requires_php" => "8.0",
                "compatibility" => new \stdClass(),
            ];
        }

        return $transient;
    }

    /**
     * Get plugin information for the update API
     *
     * @param false|object|array $result The result object or array
     * @param string $action The type of information being requested
     * @param object $args Plugin API arguments
     * @return false|object|array
     */
    public function plugin_info($result, string $action, object $args)
    {
        if ($action !== "plugin_information" || $args->slug !== $this->plugin_basename) {
            return $result;
        }

        $latest_version = $this->get_latest_version();
        $changelog = $this->get_changelog();

        return (object) [
            "slug" => $this->plugin_basename,
            "plugin" => $this->plugin_slug,
            "version" => $latest_version ?: $this->current_version,
            "author" => $this->plugin_data["Author"],
            "author_profile" => "https://github.com/SilverAssist",
            "requires" => "6.5",
            "tested" => \get_bloginfo("version"),
            "requires_php" => "8.0",
            "name" => $this->plugin_data["Name"],
            "homepage" => "https://github.com/{$this->github_repo}",
            "sections" => [
                "description" => $this->plugin_data["Description"],
                "changelog" => $changelog,
                "installation" => $this->get_installation_instructions(),
            ],
            "download_link" => $this->get_download_url($latest_version),
            "last_updated" => $this->get_last_updated(),
        ];
    }

    /**
     * Get the latest version from GitHub releases
     *
     * @return string|false
     */
    public function get_latest_version()
    {
        // Check cache first
        $cached_version = \get_transient($this->version_transient);
        if ($cached_version !== false) {
            return $cached_version;
        }

        $api_url = "https://api.github.com/repos/{$this->github_repo}/releases/latest";
        $response = \wp_remote_get($api_url, [
            "timeout" => 15,
            "headers" => [
                "Accept" => "application/vnd.github.v3+json",
                "User-Agent" => "WordPress/" . \get_bloginfo("version"),
            ],
        ]);

        if (\is_wp_error($response) || 200 !== \wp_remote_retrieve_response_code($response)) {
            error_log("Silver Assist Security Essentials Updater: Failed to fetch latest version");
            return false;
        }

        $body = \wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data["tag_name"])) {
            return false;
        }

        $version = ltrim($data["tag_name"], "v");

        // Cache for 12 hours
        \set_transient($this->version_transient, $version, 12 * HOUR_IN_SECONDS);

        return $version;
    }

    /**
     * Get download URL for a specific version
     *
     * @param string $version The version to download
     * @return string
     */
    private function get_download_url(string $version): string
    {
        return "https://github.com/{$this->github_repo}/releases/download/v{$version}/silver-assist-security-v{$version}.zip";
    }

    /**
     * Get changelog from GitHub releases
     *
     * @return string
     */
    private function get_changelog(): string
    {
        $api_url = "https://api.github.com/repos/{$this->github_repo}/releases";
        $response = \wp_remote_get($api_url, [
            "timeout" => 15,
            "headers" => [
                "Accept" => "application/vnd.github.v3+json",
                "User-Agent" => "WordPress/" . \get_bloginfo("version"),
            ],
        ]);

        if (\is_wp_error($response) || 200 !== \wp_remote_retrieve_response_code($response)) {
            return "Unable to fetch changelog. Visit the <a href=\"https://github.com/{$this->github_repo}/releases\">GitHub releases page</a> for updates.";
        }

        $body = \wp_remote_retrieve_body($response);
        $releases = json_decode($body, true);

        if (!is_array($releases)) {
            return "Unable to parse changelog.";
        }

        $changelog = "";
        foreach (array_slice($releases, 0, 5) as $release) { // Show last 5 releases
            $version = ltrim($release["tag_name"], "v");
            $date = date("Y-m-d", strtotime($release["published_at"]));
            $body = $release["body"] ?: "No release notes provided.";

            $changelog .= "<h4>Version {$version} ({$date})</h4>\n";
            $changelog .= "<div>" . \wp_kses_post($body) . "</div>\n\n";
        }

        return $changelog ?: "No changelog available.";
    }

    /**
     * Get installation instructions
     *
     * @return string
     */
    private function get_installation_instructions(): string
    {
        return "
        <h4>Automatic Installation</h4>
        <ol>
            <li>Go to WordPress Admin → Plugins → Add New</li>
            <li>Search for 'Silver Assist Security Essentials'</li>
            <li>Click 'Install Now' and then 'Activate'</li>
        </ol>
        
        <h4>Manual Installation</h4>
        <ol>
            <li>Download the plugin ZIP file</li>
            <li>Go to WordPress Admin → Plugins → Add New → Upload Plugin</li>
            <li>Choose the downloaded ZIP file and click 'Install Now'</li>
            <li>Activate the plugin</li>
        </ol>
        
        <h4>Requirements</h4>
        <ul>
            <li>WordPress 6.5 or higher</li>
            <li>PHP 8.0 or higher</li>
            <li>WPGraphQL plugin (optional, for GraphQL security features)</li>
        </ul>
        ";
    }

    /**
     * Get last updated date
     *
     * @return string
     */
    private function get_last_updated(): string
    {
        $api_url = "https://api.github.com/repos/{$this->github_repo}/releases/latest";
        $response = \wp_remote_get($api_url, [
            "timeout" => 15,
            "headers" => [
                "Accept" => "application/vnd.github.v3+json",
                "User-Agent" => "WordPress/" . \get_bloginfo("version"),
            ],
        ]);

        if (\is_wp_error($response) || 200 !== \wp_remote_retrieve_response_code($response)) {
            return date("Y-m-d");
        }

        $body = \wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data["published_at"])) {
            return date("Y-m-d");
        }

        return date("Y-m-d", strtotime($data["published_at"]));
    }

    /**
     * Clear version cache after update
     *
     * @param \WP_Upgrader $upgrader WP_Upgrader instance
     * @param array $data Array of update data
     */
    public function clear_version_cache(\WP_Upgrader $upgrader, array $data): void
    {
        if ($data["action"] === "update" && $data["type"] === "plugin") {
            if (isset($data["plugins"]) && in_array($this->plugin_slug, $data["plugins"])) {
                \delete_transient($this->version_transient);
            }
        }
    }

    /**
     * Manual version check via AJAX
     */
    public function manual_version_check(): void
    {
        // Verify nonce
        if (!\wp_verify_nonce($_POST["nonce"] ?? "", "silver_assist_security_ajax")) {
            \wp_send_json_error([
                "message" => "Security check failed",
                "code" => "invalid_nonce"
            ]);
        }
        
        if (!\current_user_can("update_plugins")) {
            \wp_send_json_error([
                "message" => "Insufficient permissions",
                "code" => "insufficient_permissions"
            ]);
        }

        try {
            \delete_transient($this->version_transient);
            $latest_version = $this->get_latest_version();

            \wp_send_json_success([
                "current_version" => $this->current_version,
                "latest_version" => $latest_version ?: "Unknown",
                "update_available" => $latest_version && version_compare($this->current_version, $latest_version, "<"),
                "github_repo" => $this->github_repo,
            ]);
        } catch (Exception $e) {
            \wp_send_json_error([
                "message" => "Error checking for updates: {$e->getMessage()}",
                "code" => "version_check_failed"
            ]);
        }
    }

    /**
     * Get current version
     *
     * @return string
     */
    public function get_current_version(): string
    {
        return $this->current_version;
    }

    /**
     * Get GitHub repository
     *
     * @return string
     */
    public function get_github_repo(): string
    {
        return $this->github_repo;
    }

    /**
     * Check if update is available
     *
     * @return bool
     */
    public function is_update_available(): bool
    {
        $latest_version = $this->get_latest_version();
        return $latest_version && version_compare($this->current_version, $latest_version, "<");
    }
}
