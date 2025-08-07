<?php
/**
 * Silver Assist Security Essentials - Custom GitHub Updates Handler
 *
 * Handles automatic updates from public GitHub releases for the Silver Assist Security Essentials.
 * Provides seamless WordPress admin updates without requiring authentication tokens.
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.2
 */

namespace SilverAssist\Security\Core;

// Prevent direct access
defined("ABSPATH") or exit;

// Debug: Verificar si las clases están disponibles
if (!class_exists("SilverAssist\WpGithubUpdater\Updater")) {
    error_log("Silver Assist Security: WpGithubUpdater\Updater class not found");
    // Try to load manually as fallback
    $updater_path = SILVER_ASSIST_SECURITY_PATH . "vendor/silverassist/wp-github-updater/src/Updater.php";
    if (file_exists($updater_path)) {
        require_once $updater_path;
        error_log("Silver Assist Security: Manually loaded Updater class from {$updater_path}");
    }
}

if (!class_exists("SilverAssist\WpGithubUpdater\UpdaterConfig")) {
    error_log("Silver Assist Security: WpGithubUpdater\UpdaterConfig class not found");
    // Try to load manually as fallback
    $config_path = SILVER_ASSIST_SECURITY_PATH . "vendor/silverassist/wp-github-updater/src/UpdaterConfig.php";
    if (file_exists($config_path)) {
        require_once $config_path;
        error_log("Silver Assist Security: Manually loaded UpdaterConfig class from {$config_path}");
    }
}

use SilverAssist\WpGithubUpdater\Updater as GitHubUpdater;
use SilverAssist\WpGithubUpdater\UpdaterConfig;

/**
 * Class Updater
 *
 * Integrates the reusable GitHub updater package.
 * @since 1.1.2
 */
class Updater extends GitHubUpdater
{
    /**
     * Updater for Silver Assist Security Essentials
     *
     * @param string $plugin_file Full path to main plugin file
     * @param string $github_repo GitHub repository in format "owner/repo"
     */
    public function __construct(string $plugin_file, string $github_repo)
    {
        $config = new UpdaterConfig(
            $plugin_file,
            $github_repo,
            [
                "plugin_name" => "Silver Assist Security Essentials",
                "plugin_description" => "WordPress plugin for advanced security: brute force protection, bot blocking, GraphQL security, HTTPOnly cookies, and auto-updates.",
                "plugin_author" => "Silver Assist",
                "plugin_homepage" => "https://github.com/SilverAssist/silver-assist-security",
                "requires_wordpress" => "6.5",
                "requires_php" => "8.0",
                "asset_pattern" => "silver-assist-security-v{version}.zip",
                "cache_duration" => 12 * 3600,
                "ajax_action" => "silver_assist_security_check_version",
                "ajax_nonce" => "silver_assist_security_ajax"
            ]
        );
        parent::__construct($config);
    }
}
