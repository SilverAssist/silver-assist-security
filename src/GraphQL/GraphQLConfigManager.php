<?php
/**
 * Silver Assist Security Essentials - GraphQL Configuration Manager
 *
 * Centralizes all GraphQL configuration logic to avoid code duplication
 * between GraphQLSecurity and AdminPanel classes. Provides a single source
 * of truth for GraphQL settings, status checks, and configuration validation.
 *
 * @package SilverAssist\Security\GraphQL
 * @since 1.0.4
 * @author Silver Assist
 * @version 1.1.0
 */

namespace SilverAssist\Security\GraphQL;

/**
 * GraphQL Configuration Manager class
 * 
 * Centralized management of GraphQL configuration and settings
 * to eliminate code duplication and improve maintainability
 * 
 * @since 1.0.4
 */
class GraphQLConfigManager
{
  /**
   * Singleton instance
   * 
   * @var GraphQLConfigManager|null
   */
  private static ?GraphQLConfigManager $instance = null;

  /**
   * Whether headless mode is enabled
   * 
   * @var bool|null
   */
  private ?bool $headless_mode = null;

  /**
   * Cached configuration array
   * 
   * @var array|null
   */
  private ?array $config_cache = null;

  /**
   * Default configuration values
   * 
   * @var array
   */
  private const DEFAULT_CONFIG = [
    "query_depth_limit" => 8,
    "query_complexity_limit" => 100,
    "query_timeout" => 5,
    "introspection_enabled" => false,
    "debug_mode" => false,
    "endpoint_access" => "public",
    "batch_enabled" => true,
    "batch_limit" => 10
  ];

  /**
   * Private constructor to enforce singleton pattern
   * 
   * @since 1.0.4
   */
  private function __construct()
  {
    // Initialize configuration
    $this->load_configuration();
  }

  /**
   * Get singleton instance
   * 
   * @since 1.0.4
   * @return GraphQLConfigManager
   */
  public static function getInstance(): GraphQLConfigManager
  {
    if (self::$instance === null) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  /**
   * Check if WPGraphQL is available and functional
   * 
   * @since 1.0.4
   * @return bool True if WPGraphQL is active and functional
   */
  public function is_wpgraphql_available(): bool
  {
    return \class_exists("WPGraphQL") && \function_exists("get_graphql_setting");
  }

  /**
   * Check if headless mode is enabled
   * 
   * @since 1.0.4
   * @return bool
   */
  public function is_headless_mode(): bool
  {
    if ($this->headless_mode === null) {
      $this->headless_mode = (bool) \get_option("silver_assist_graphql_headless_mode", false);
    }
    return $this->headless_mode;
  }

  /**
   * Get PHP execution timeout setting
   * 
   * @since 1.1.0
   * @return int PHP max_execution_time or 0 if unlimited
   */
  public function get_php_execution_timeout(): int
  {
    $timeout = ini_get("max_execution_time");
    return $timeout ? (int) $timeout : 0;
  }

  /**
   * Get timeout configuration with PHP awareness
   * 
   * @since 1.1.0
   * @return array Timeout configuration including PHP settings
   */
  public function get_timeout_config(): array
  {
    $php_timeout = $this->get_php_execution_timeout();
    $current_timeout = (int) \get_option("silver_assist_graphql_query_timeout", 
      $php_timeout > 0 ? min($php_timeout, 30) : 30
    );
    
    return [
      "php_timeout" => $php_timeout,
      "current_timeout" => $current_timeout,
      "is_unlimited_php" => $php_timeout === 0,
      "is_using_php_default" => !get_option("silver_assist_graphql_query_timeout"),
      "recommended_min" => 5,
      "recommended_max" => $php_timeout > 0 ? min($php_timeout, 60) : 60
    ];
  }

  /**
   * Get WPGraphQL setting with fallback
   * 
   * @since 1.0.4
   * @param string $setting_key The setting key to retrieve
   * @param mixed $default Default value if setting not found
   * @return mixed Setting value or default
   */
  public function get_wpgraphql_setting(string $setting_key, $default = null)
  {
    if (!$this->is_wpgraphql_available()) {
      return $default;
    }

    return get_graphql_setting($setting_key, $default);
  }

  /**
   * Get complete GraphQL configuration
   * 
   * @since 1.0.4
   * @return array Complete configuration array
   */
  public function get_configuration(): array
  {
    if ($this->config_cache === null) {
      $this->load_configuration();
    }
    return $this->config_cache;
  }

  /**
   * Load and cache configuration
   * 
   * @since 1.0.4
   * @return void
   */
  private function load_configuration(): void
  {
    $is_headless = $this->is_headless_mode();

    // Base configuration
    $config = self::DEFAULT_CONFIG;

    if (!$this->is_wpgraphql_available()) {
      // Apply headless adjustments to defaults
      if ($is_headless) {
        $config["query_depth_limit"] = 15;
        $config["query_complexity_limit"] = 200;
        $config["query_timeout"] = 10;
      }
      $this->config_cache = $config;
      return;
    }

    // Get WPGraphQL native settings
    $config = $this->load_wpgraphql_settings($config, $is_headless);

    // Cache the configuration
    $this->config_cache = $config;
  }

  /**
   * Load WPGraphQL specific settings
   * 
   * @since 1.0.4
   * @param array $config Base configuration
   * @param bool $is_headless Whether headless mode is enabled
   * @return array Updated configuration
   */
  private function load_wpgraphql_settings(array $config, bool $is_headless): array
  {
    // Query Depth
    $depth_enabled = $this->get_wpgraphql_setting("query_depth_enabled", "off");
    if ($depth_enabled === "on") {
      $config["query_depth_limit"] = (int) $this->get_wpgraphql_setting("query_depth_max_depth", 10);
    } else {
      // Use headless-aware defaults
      $config["query_depth_limit"] = $is_headless ? 15 : 10;
    }

    // Query Complexity (enhanced by our plugin)
    $config["query_complexity_limit"] = $is_headless ? 200 : 100;

    // Query Timeout (our enhancement) - Use PHP setting as base
    $php_timeout = $this->get_php_execution_timeout();
    $default_timeout = $php_timeout > 0 ? min($php_timeout, 30) : 30; // Cap at 30 seconds max
    $config["query_timeout"] = (int) \get_option("silver_assist_graphql_query_timeout", $default_timeout);

    // Introspection
    $config["introspection_enabled"] = $this->get_wpgraphql_setting("public_introspection_enabled", "off") === "on";

    // Debug Mode
    $config["debug_mode"] = $this->get_wpgraphql_setting("debug_mode_enabled", "off") === "on";

    // Endpoint Access
    $auth_required = $this->get_wpgraphql_setting("restrict_endpoint_to_authenticated_users", "off");
    $config["endpoint_access"] = $auth_required === "on" ? "restricted" : "public";

    // Batch Queries
    $config["batch_enabled"] = $this->get_wpgraphql_setting("batch_queries_enabled", "on") === "on";
    $config["batch_limit"] = (int) $this->get_wpgraphql_setting("batch_limit", 10);

    return $config;
  }

  /**
   * Get security recommendations based on current configuration
   * 
   * @since 1.0.4
   * @return array Array of security recommendations
   */
  public function get_security_recommendations(): array
  {
    $config = $this->get_configuration();
    $recommendations = [];

    if ($config["introspection_enabled"]) {
      $recommendations[] = [
        "level" => "warning",
        "message" => \__("Public introspection enabled (security risk)", "silver-assist-security")
      ];
    }

    if ($config["debug_mode"]) {
      $recommendations[] = [
        "level" => "warning",
        "message" => \__("Debug mode enabled (not recommended for production)", "silver-assist-security")
      ];
    }

    if ($config["endpoint_access"] === "public") {
      $recommendations[] = [
        "level" => "info",
        "message" => \__("GraphQL endpoint is publicly accessible", "silver-assist-security")
      ];
    }

    return $recommendations;
  }

  /**
   * Get formatted settings display for admin panel
   * 
   * @since 1.0.4
   * @return string HTML formatted settings display
   */
  public function get_settings_display(): string
  {
    if (!$this->is_wpgraphql_available()) {
      return "<em>" . \esc_html__("WPGraphQL not active", "silver-assist-security") . "</em>";
    }

    $config = $this->get_configuration();
    $settings = [];

    // Endpoint Access (most important for security)
    $auth_status = $config["endpoint_access"] === "restricted" ?
      "<span style=\"color: #d63638; font-weight: bold;\">" . \esc_html__("RESTRICTED", "silver-assist-security") . "</span>" :
      "<span style=\"color: #00a32a; font-weight: bold;\">" . \esc_html__("PUBLIC", "silver-assist-security") . "</span>";

    $settings[] = sprintf(
      "<strong>%s:</strong> %s",
      \esc_html__("Endpoint Access", "silver-assist-security"),
      $auth_status
    );

    // Query Depth
    $settings[] = sprintf(
      "<strong>%s:</strong> %s (%s: %d)",
      \esc_html__("Query Depth Limiting", "silver-assist-security"),
      $config["query_depth_limit"] > 0 ? \esc_html__("Enabled", "silver-assist-security") : \esc_html__("Disabled", "silver-assist-security"),
      \esc_html__("Max Depth", "silver-assist-security"),
      $config["query_depth_limit"]
    );

    // Batch Queries
    $settings[] = sprintf(
      "<strong>%s:</strong> %s (%s: %d)",
      \esc_html__("Batch Queries", "silver-assist-security"),
      $config["batch_enabled"] ? \esc_html__("Enabled", "silver-assist-security") : \esc_html__("Disabled", "silver-assist-security"),
      \esc_html__("Limit", "silver-assist-security"),
      $config["batch_limit"]
    );

    // Introspection
    $settings[] = sprintf(
      "<strong>%s:</strong> %s",
      \esc_html__("Public Introspection", "silver-assist-security"),
      $config["introspection_enabled"] ?
      "<span style=\"color: #d63638;\">" . \esc_html__("Enabled", "silver-assist-security") . "</span>" :
      "<span style=\"color: #00a32a;\">" . \esc_html__("Disabled", "silver-assist-security") . "</span>"
    );

    // Debug Mode
    $settings[] = sprintf(
      "<strong>%s:</strong> %s",
      \esc_html__("Debug Mode", "silver-assist-security"),
      $config["debug_mode"] ?
      "<span style=\"color: #d63638;\">" . \esc_html__("Enabled", "silver-assist-security") . "</span>" :
      "<span style=\"color: #00a32a;\">" . \esc_html__("Disabled", "silver-assist-security") . "</span>"
    );

    // Security recommendations
    $recommendations = $this->get_security_recommendations();
    if (!empty($recommendations)) {
      $warning_messages = array_map(function ($rec) {
        return $rec["message"];
      }, array_filter($recommendations, function ($rec) {
        return $rec["level"] === "warning";
      }));

      if (!empty($warning_messages)) {
        $settings[] = "<strong style=\"color: #d63638;\">" .
          \esc_html__("⚠️ Security Concerns:", "silver-assist-security") . "</strong><br>" .
          implode("<br>", array_map("esc_html", $warning_messages));
      }
    }

    return "<ul><li>" . implode("</li><li>", $settings) . "</li></ul>";
  }

  /**
   * Get safe limits for GraphQL security based on mode
   * 
   * @since 1.0.4
   * @param string $limit_type Type of limit to get (depth|complexity|timeout|aliases|directives|field_duplicates)
   * @return int Safe limit value
   */
  public function get_safe_limit(string $limit_type): int
  {
    $config = $this->get_configuration();
    $is_headless = $this->is_headless_mode();

    return match ($limit_type) {
      "depth" => $config["query_depth_limit"],
      "complexity" => $config["query_complexity_limit"],
      "timeout" => $config["query_timeout"],
      "aliases" => $is_headless ? 50 : 20,
      "directives" => $is_headless ? 30 : 15,
      "field_duplicates" => $is_headless ? 20 : 10,
      default => 0
    };
  }

  /**
   * Get rate limiting configuration
   * 
   * @since 1.0.4
   * @return array Rate limiting configuration
   */
  public function get_rate_limiting_config(): array
  {
    $config = $this->get_configuration();
    $is_headless = $this->is_headless_mode();

    // Base rate limits (requests per minute)
    $base_limit = $is_headless ? 120 : 60;

    // Scale based on WPGraphQL batch settings
    if ($config["batch_enabled"] && $config["batch_limit"] > 1) {
      // If batching is enabled, allow more requests but account for batch multiplier
      $batch_multiplier = min($config["batch_limit"], 10); // Cap multiplier at 10
      $adjusted_limit = $base_limit + ($batch_multiplier * 10);
    } else {
      $adjusted_limit = $base_limit;
    }

    return [
      "requests_per_minute" => $adjusted_limit,
      "burst_limit" => (int) ($adjusted_limit * 1.5), // Allow 50% burst
      "timeout_seconds" => $config["query_timeout"]
    ];
  }

  /**
   * Clear configuration cache (for testing or dynamic updates)
   * 
   * @since 1.0.4
   * @return void
   */
  public function clear_cache(): void
  {
    $this->config_cache = null;
    $this->headless_mode = null;
  }

  /**
   * Get WPGraphQL integration status for monitoring
   * 
   * @since 1.0.4
   * @return array Integration status information
   */
  public function get_integration_status(): array
  {
    $config = $this->get_configuration();

    return [
      "wpgraphql_available" => $this->is_wpgraphql_available(),
      "headless_mode" => $this->is_headless_mode(),
      "current_config" => $config,
      "security_level" => $this->calculate_security_level($config),
      "recommendations" => $this->get_security_recommendations()
    ];
  }

  /**
   * Calculate overall security level based on configuration
   * 
   * @since 1.0.4
   * @param array $config Configuration array
   * @return string Security level (high|medium|low)
   */
  private function calculate_security_level(array $config): string
  {
    $score = 0;

    // Positive security points
    if (!$config["introspection_enabled"])
      $score += 2;
    if (!$config["debug_mode"])
      $score += 2;
    if ($config["endpoint_access"] === "restricted")
      $score += 3;
    if ($config["query_depth_limit"] > 0 && $config["query_depth_limit"] <= 15)
      $score += 2;
    if ($config["batch_limit"] <= 20)
      $score += 1;

    // Determine level
    if ($score >= 8)
      return "high";
    if ($score >= 5)
      return "medium";
    return "low";
  }
}
