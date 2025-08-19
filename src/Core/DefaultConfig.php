<?php
/**
 * Silver Assist Security Essentials - Default Configuration
 *
 * Centralizes all default configuration values for the plugin
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.6
 */

namespace SilverAssist\Security\Core;

/**
 * Default Configuration class
 * 
 * Provides centralized default values for all plugin settings
 * 
 * @since 1.1.1
 */
class DefaultConfig
{
  /**
   * Get all default plugin options
   * 
   * @since 1.1.1
   * @return array<string, mixed>
   */
  public static function get_defaults(): array
  {
    return [
      "silver_assist_login_attempts" => 5,
      "silver_assist_lockout_duration" => 900, // 15 minutes
      "silver_assist_session_timeout" => 30, // 30 minutes
      "silver_assist_password_strength_enforcement" => 1,
      "silver_assist_bot_protection" => 1,
      "silver_assist_admin_hide_enabled" => 0, // Admin hiding disabled by default for security
      "silver_assist_admin_hide_path" => "silver-admin", // Custom admin path
      "silver_assist_graphql_query_depth" => 8,
      "silver_assist_graphql_query_complexity" => 100,
      "silver_assist_graphql_query_timeout" => 30, // Dynamic: Based on PHP timeout, capped at 30s
      "silver_assist_graphql_headless_mode" => 0
    ];
  }

  /**
   * Get default value for specific option
   * 
   * @since 1.1.1
   * @param string $option_name The option name
   * @return mixed Default value or null if not found
   */
  public static function get_default(string $option_name)
  {
    $defaults = self::get_defaults();
    return $defaults[$option_name] ?? null;
  }

  /**
   * Get option from WordPress with default fallback
   * 
   * @since 1.1.1
   * @param string $option_name The option name
   * @return mixed Option value or default value
   */
  public static function get_option(string $option_name)
  {
    // Handle special case for GraphQL timeout that depends on PHP settings
    if ($option_name === "silver_assist_graphql_query_timeout") {
      return self::get_graphql_timeout_option();
    }

    return \get_option($option_name, self::get_default($option_name));
  }

  /**
   * Get GraphQL timeout option with dynamic PHP timeout calculation
   * 
   * @since 1.1.1
   * @return int GraphQL query timeout in seconds
   */
  private static function get_graphql_timeout_option(): int
  {
    // Check if option is already set in database
    $saved_timeout = \get_option("silver_assist_graphql_query_timeout");
    if ($saved_timeout !== false) {
      return (int) $saved_timeout;
    }

    // Calculate dynamic default based on PHP execution timeout
    $php_timeout = self::get_php_execution_timeout();
    $default_timeout = $php_timeout > 0 ? min($php_timeout, 30) : 30; // Cap at 30 seconds max

    return $default_timeout;
  }

  /**
   * Get PHP execution timeout
   * 
   * @since 1.1.1
   * @return int PHP execution timeout in seconds (0 = unlimited)
   */
  private static function get_php_execution_timeout(): int
  {
    $timeout = ini_get("max_execution_time");
    return $timeout !== false ? (int) $timeout : 30;
  }
}
