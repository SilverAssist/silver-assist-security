<?php
/**
 * Silver Assist Security Essentials - GraphQL Security Protection
 *
 * Implements comprehensive GraphQL security including query depth/complexity limits,
 * rate limiting, introspection control, and request validation. Provides protection
 * against GraphQL-specific attacks and resource exhaustion.
 *
 * @package SilverAssist\Security\GraphQL
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.11
 */

namespace SilverAssist\Security\GraphQL;

use GraphQL\Error\Error;
use GraphQL\Error\UserError;
use GraphQL\Executor\ExecutionResult;

/**
 * GraphQL Security class
 * 
 * Handles GraphQL security features including query depth/complexity limits,
 * rate limiting, introspection control, and security validations
 * 
 * @since 1.1.1
 */
class GraphQLSecurity
{
    /**
     * Configuration manager instance
     * 
     * @var GraphQLConfigManager
     */
    private GraphQLConfigManager $config_manager;

    /**
     * Maximum allowed query depth
     * 
     * @var int
     */
    private int $max_query_depth;

    /**
     * Maximum allowed query complexity score
     * 
     * @var int
     */
    private int $max_query_complexity;

    /**
     * Maximum allowed aliases per query
     * 
     * @var int
     */
    private int $max_aliases;

    /**
     * Maximum allowed duplicate directives per query
     * 
     * @var int
     */
    private int $max_directives;

    /**
     * Maximum allowed field duplicates
     * 
     * @var int
     */
    private int $max_field_duplicates;

    /**
     * Query execution timeout in seconds
     * 
     * @var int
     */
    private int $query_timeout;

    /**
     * Constructor
     * 
     * @since 1.1.1
     */
    public function __construct()
    {
        $this->config_manager = GraphQLConfigManager::getInstance();
        $this->init_configuration();
        $this->init();
    }

    /**
     * Initialize configuration values using GraphQLConfigManager
     * 
     * @since 1.1.1
     * @return void
     */
    private function init_configuration(): void
    {
        // Get configuration from centralized manager
        $config = $this->config_manager->get_configuration();

        // Set properties from configuration
        $this->max_query_depth = $config["query_depth_limit"];
        $this->max_query_complexity = $config["query_complexity_limit"];
        $this->query_timeout = $config["query_timeout"];

        // Set adaptive limits based on headless mode
        $this->max_aliases = $this->config_manager->get_safe_limit("aliases");
        $this->max_directives = $this->config_manager->get_safe_limit("directives");
        $this->max_field_duplicates = $this->config_manager->get_safe_limit("field_duplicates");
    }

    /**
     * Initialize GraphQL security features
     * 
     * @since 1.1.1
     * @return void
     */
    private function init(): void
    {
        // Only initialize if WPGraphQL is active
        if (!\class_exists("WPGraphQL")) {
            return;
        }

        \add_action("init", [$this, "init_graphql_security"]);
        \add_filter("graphql_request_results", [$this, "log_graphql_requests"], 10, 5);
        \add_action("graphql_init", [$this, "disable_introspection_in_production"]);
        \add_action("graphql_init", [$this, "add_security_validations"]);
        \add_filter("graphql_request_data", [$this, "validate_query_before_execution"], 1, 5);
        \add_action("graphql_init", [$this, "set_execution_timeout"]);
        \add_action("send_headers", [$this, "add_graphql_security_headers"]);
    }

    /**
     * Initialize GraphQL security features
     * 
     * @since 1.1.1
     * @return void
     */
    public function init_graphql_security(): void
    {
        // Disable introspection in production
        if (defined("WP_ENVIRONMENT_TYPE") && WP_ENVIRONMENT_TYPE === "production") {
            \add_filter("graphql_show_in_graphiql", "__return_false");
        }

        // Add rate limiting for GraphQL endpoint
        $this->setup_graphql_rate_limiting();
    }

    /**
     * Disable introspection in production
     * 
     * @since 1.1.1
     * @return void
     */
    public function disable_introspection_in_production(): void
    {
        // Use config manager to check WPGraphQL settings
        $config = $this->config_manager->get_configuration();

        // If WPGraphQL already has introspection disabled, respect that
        if (!$config["introspection_enabled"]) {
            return;
        }

        // Our additional production checks
        if (defined("WP_ENVIRONMENT_TYPE") && WP_ENVIRONMENT_TYPE === "production") {
            \add_filter("graphql_introspection_enabled", "__return_false");
            \add_filter("graphql_show_in_graphiql", "__return_false");

            \add_action("graphql_register_types", function () {
                \remove_action("graphql_register_types", ["WPGraphQL\\Type\\Introspection", "register_introspection_fields"]);
            }, 1);
        }
    }

    /**
     * Add security validations integrating with WPGraphQL native features
     * 
     * @since 1.1.1
     * @return void
     */
    public function add_security_validations(): void
    {
        // Add our custom validation rules
        \add_filter("graphql_validation_rules", [$this, "add_custom_validation_rules"]);

        // Integrate with WPGraphQL's native depth validation
        $this->integrate_with_wpgraphql_depth_validation();

        // Enhance WPGraphQL's connection limits for complexity estimation
        $this->enhance_wpgraphql_connection_limits();
    }

    /**
     * Integrate with WPGraphQL's native query depth validation
     * 
     * @since 1.1.1
     * @return void
     */
    private function integrate_with_wpgraphql_depth_validation(): void
    {
        // Check if WPGraphQL depth validation is enabled
        if (function_exists("get_graphql_setting")) {
            $wpgraphql_depth_enabled = \get_graphql_setting("query_depth_enabled", "off");
            $wpgraphql_max_depth = \get_graphql_setting("query_depth_max", 10);

            // If WPGraphQL depth validation is enabled, coordinate with it
            if ($wpgraphql_depth_enabled === "on") {
                // Log coordination for debugging
                if (defined("WP_DEBUG") && WP_DEBUG) {
                    error_log(sprintf(
                        "Silver Assist Security: Coordinating with WPGraphQL depth validation (max: %d)",
                        $wpgraphql_max_depth
                    ));
                }

                // Use WPGraphQL's limit if it's more restrictive
                if ($wpgraphql_max_depth < $this->max_query_depth) {
                    $this->max_query_depth = $wpgraphql_max_depth;
                }
            }
        }
    }

    /**
     * Enhance WPGraphQL's connection limits for complexity estimation
     * 
     * @since 1.1.1
     * @return void
     */
    private function enhance_wpgraphql_connection_limits(): void
    {
        // Filter WPGraphQL's max query amount for complexity estimation
        \add_filter("graphql_connection_max_query_amount", [$this, "filter_connection_max_query_amount"], 10, 5);

        // Add complexity hints to connection resolvers
        \add_filter("graphql_connection_query_args", [$this, "add_complexity_hints_to_connections"], 10, 5);
    }

    /**
     * Filter WPGraphQL's connection max query amount based on complexity estimation
     * 
     * @since 1.1.1
     * @param int $max_query_amount The maximum number of nodes to query
     * @param mixed $source The source object (optional)
     * @param array $args The connection arguments (optional)
     * @param mixed $context The GraphQL context (optional)
     * @param mixed $info The ResolveInfo object (optional)
     * @return int
     */
    public function filter_connection_max_query_amount(int $max_query_amount, $source = null, array $args = [], $context = null, $info = null): int
    {
        // Use our complexity configuration to adjust connection limits
        $complexity_ratio = $this->max_query_complexity / 100; // Base ratio

        // More complex queries get lower connection limits
        $adjusted_limit = intval($max_query_amount / $complexity_ratio);

        // Ensure we don't go below 10 or above default WPGraphQL limit (100)
        return max(10, min(100, $adjusted_limit));
    }

    /**
     * Add complexity hints to GraphQL connections
     * 
     * @since 1.1.1
     * @param array $query_args The query arguments
     * @param mixed $source The source object (optional)
     * @param array $args The connection arguments (optional)
     * @param mixed $context The GraphQL context (optional)
     * @param mixed $info The ResolveInfo object (optional)
     * @return array
     */
    public function add_complexity_hints_to_connections(array $query_args, $source = null, array $args = [], $context = null, $info = null): array
    {
        // Add complexity metadata for monitoring
        $query_args["_silver_assist_complexity_hint"] = [
            "max_complexity" => $this->max_query_complexity,
            "connection_type" => $info->fieldName ?? "unknown",
            "estimated_cost" => $this->estimate_connection_complexity($args)
        ];

        return $query_args;
    }

    /**
     * Estimate connection complexity based on arguments
     * 
     * @since 1.1.1
     * @param array $args Connection arguments
     * @return int Estimated complexity points
     */
    private function estimate_connection_complexity(array $args): int
    {
        $base_cost = 1;

        // Factor in the number of items requested
        $first = $args["first"] ?? 10;
        $last = $args["last"] ?? 10;
        $item_count = max($first, $last);

        // Higher item counts increase complexity
        $item_complexity = ceil($item_count / 10);

        // Factor in where arguments (filtering increases complexity)
        $where_complexity = !empty($args["where"]) ? count($args["where"]) : 0;

        return $base_cost + $item_complexity + $where_complexity;
    }

    /**
     * Add custom validation rules with WPGraphQL integration
     * 
     * @since 1.1.1
     * @param array $validation_rules Existing validation rules
     * @return array Modified validation rules
     */
    public function add_custom_validation_rules(array $validation_rules): array
    {
        // Add our enhanced complexity validation
        $validation_rules[] = new class ($this->max_query_complexity, $this->config_manager) {
            private int $max_complexity;
            private GraphQLConfigManager $config_manager;

            public function __construct(int $max_complexity, GraphQLConfigManager $config_manager)
            {
                $this->max_complexity = $max_complexity;
                $this->config_manager = $config_manager;
            }

            /**
             * Get the validation rule name
             * 
             * @return string
             */
            public function getName(): string
            {
                return "SilverAssistComplexityValidation";
            }

            /**
             * Get visitor function for GraphQL validation
             * 
             * @param mixed $context Validation context
             * @return array
             */
            public function getVisitor($context): array
            {
                return [
                    "DocumentNode" => function ($node) use ($context) {
                        // Use our enhanced complexity validation with WPGraphQL integration
                        $estimated_complexity = $this->estimate_query_complexity($node);

                        // Get dynamic complexity limit based on configuration
                        $complexity_limit = $this->config_manager->get_safe_limit("complexity");

                        if ($estimated_complexity > $complexity_limit) {
                            $context->reportError(new Error(
                                sprintf(
                                    /* translators: 1: estimated complexity, 2: maximum allowed complexity */
                                    \__("Query complexity %1\$d exceeds maximum allowed complexity %2\$d", "silver-assist-security"),
                                    $estimated_complexity,
                                    $complexity_limit
                                )
                            ));
                        }
                    }
                ];
            }

            /**
             * Get SDL visitor (not used in this context)
             * 
             * @param mixed $context SDL validation context
             * @return array
             */
            public function getSDLVisitor($context): array
            {
                return [];
            }

            /**
             * Estimate query complexity using enhanced proxy method
             * 
             * @param mixed $node DocumentNode
             * @return int Estimated complexity
             */
            private function estimate_query_complexity($node): int
            {
                // Convert node to string for analysis
                $query_string = $node->__toString();

                // Enhanced complexity estimation
                $base_complexity = 1;

                // Field count estimation (each field adds complexity)
                $field_matches = [];
                preg_match_all("/\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[{\(]/", $query_string, $field_matches);
                $field_complexity = count($field_matches[1] ?? []);

                // Connection complexity (connections with arguments)
                $connection_matches = [];
                preg_match_all("/\(\s*first:\s*(\d+)/", $query_string, $connection_matches);
                $connection_complexity = 0;
                foreach ($connection_matches[1] ?? [] as $first_value) {
                    $connection_complexity += ceil((int) $first_value / 10);
                }

                // Where clause complexity (filtering increases complexity)
                $where_complexity = substr_count(strtolower($query_string), "where:");

                // Fragment complexity (fragments can multiply complexity)
                $fragment_complexity = substr_count($query_string, "fragment") * 2;

                // Nested query complexity (deeper nesting = higher complexity)
                $nesting_level = 0;
                $max_nesting = 0;
                for ($i = 0; $i < strlen($query_string); $i++) {
                    if ($query_string[$i] === "{") {
                        $nesting_level++;
                        $max_nesting = max($max_nesting, $nesting_level);
                    } elseif ($query_string[$i] === "}") {
                        $nesting_level--;
                    }
                }
                $nesting_complexity = $max_nesting * 2;

                return $base_complexity + $field_complexity + $connection_complexity +
                    $where_complexity + $fragment_complexity + $nesting_complexity;
            }
        };

        return $validation_rules;
    }

    /**
     * Add custom validation rules
     * 
     * @since 1.1.1
     * @param array $rules Existing validation rules
     * @return array
     */
    /**
     * Validate query before execution
     * 
     * @since 1.1.1
     * @param array $request_data Request data including query
     * @param mixed $request HTTP request object (optional)
     * @param string|null $operation_name GraphQL operation name (optional)
     * @param array|null $variables Query variables (optional)
     * @param mixed $context Request context (optional)
     * @return array
     * @throws UserError
     */
    public function validate_query_before_execution(array $request_data, $request = null, ?string $operation_name = null, ?array $variables = null, $context = null): array
    {
        if (empty($request_data["query"])) {
            return $request_data;
        }

        $query = $request_data["query"];

        // Check for introspection in production
        if (defined("WP_ENVIRONMENT_TYPE") && WP_ENVIRONMENT_TYPE === "production") {
            if ($this->is_introspection_query($query)) {
                throw new UserError(\__("Introspection is disabled in production.", "silver-assist-security"));
            }
        }

        // Validate query patterns
        $this->validate_query_patterns($query);

        return $request_data;
    }

    /**
     * Check if query is introspection
     * 
     * @since 1.1.1
     * @param string $query GraphQL query string
     * @return bool
     */
    private function is_introspection_query(string $query): bool
    {
        return preg_match("/(__schema|__type|__typename|__directive)/i", $query);
    }

    /**
     * Validate query patterns for security issues
     * 
     * @since 1.1.1
     * @param string $query GraphQL query string
     * @return void
     * @throws UserError
     */
    private function validate_query_patterns(string $query): void
    {
        // Check for excessive aliases
        $alias_count = preg_match_all("/\w+\s*:\s*\w+/", $query);
        if ($alias_count > $this->max_aliases) {
            throw new UserError(
                sprintf(
                    /* translators: 1: number of aliases found, 2: maximum allowed */
                    \__("Query contains too many aliases (%1\$d). Maximum allowed: %2\$d", "silver-assist-security"),
                    $alias_count,
                    $this->max_aliases
                )
            );
        }

        // Check for excessive directive usage
        $directive_count = preg_match_all("/@\w+/", $query);
        if ($directive_count > $this->max_directives * 2) {
            throw new UserError(
                sprintf(
                    /* translators: 1: number of directives found, 2: maximum allowed */
                    \__("Query contains too many directives (%1\$d). Maximum allowed: %2\$d", "silver-assist-security"),
                    $directive_count,
                    $this->max_directives * 2
                )
            );
        }

        // Check for field duplication patterns
        if (preg_match("/(\w+)(\s*\w+\s*)*\{[^}]*\1[^}]*\1/", $query)) {
            throw new UserError(
                sprintf(
                    /* translators: %d: maximum allowed field duplicates */
                    \__("Query contains excessive field duplication. Maximum allowed: %d", "silver-assist-security"),
                    $this->max_field_duplicates
                )
            );
        }

        // Check for potential circular queries using configured depth limit
        $depth_pattern = str_repeat("\{[^}]*", $this->max_query_depth + 1);
        if (preg_match("/$depth_pattern/", $query)) {
            throw new UserError(
                sprintf(
                    /* translators: %d: maximum query depth limit in levels */
                    \__("Query depth exceeds maximum limit of %d levels.", "silver-assist-security"),
                    $this->max_query_depth
                )
            );
        }

        // Check for excessively long queries (potential DoS)
        $max_query_length = $this->max_query_complexity * 100;
        if (strlen($query) > $max_query_length) {
            throw new UserError(
                sprintf(
                    /* translators: 1: current query length in characters, 2: maximum allowed characters */
                    \__("Query is too large (%1\$d characters). Maximum allowed: %2\$d characters.", "silver-assist-security"),
                    strlen($query),
                    $max_query_length
                )
            );
        }
    }

    /**
     * Set execution timeout
     * 
     * @since 1.1.1
     * @return void
     */
    public function set_execution_timeout(): void
    {
        // Add GraphQL-specific timeout filter
        \add_filter("graphql_request_results", [$this, "enforce_query_timeout"], 1, 5);

        // Get timeout configuration with PHP awareness
        $timeout_config = $this->config_manager->get_timeout_config();

        // Only set PHP limit if current GraphQL timeout is lower than PHP limit
        if ($timeout_config["php_timeout"] === 0 || $timeout_config["current_timeout"] < $timeout_config["php_timeout"]) {
            set_time_limit($timeout_config["current_timeout"]);
        }

        // Log timeout configuration for debugging
        if (defined("WP_DEBUG") && WP_DEBUG) {
            error_log(sprintf(
                "GraphQL Security: PHP timeout=%ds, GraphQL timeout=%ds, Applied=%ds",
                $timeout_config["php_timeout"],
                $timeout_config["current_timeout"],
                $timeout_config["php_timeout"] === 0 ? $timeout_config["current_timeout"] :
                min($timeout_config["php_timeout"], $timeout_config["current_timeout"])
            ));
        }
    }

    /**
     * Enforce query timeout using GraphQL execution tracking
     * 
     * @since 1.1.1
     * @param mixed $response GraphQL response (ExecutionResult object or array)
     * @param mixed $schema GraphQL schema
     * @param string|null $operation Operation name
     * @param string|null $query Query string (can be null in some GraphQL contexts)
     * @param array|null $variables Query variables
     * @return mixed
     */
    public function enforce_query_timeout($response, $schema, ?string $operation, ?string $query, ?array $variables)
    {
        $execution_time = microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"];

        // Check if query execution exceeded our timeout
        if ($execution_time > $this->query_timeout) {
            $query_preview = $query ? substr($query, 0, 100) . "..." : "Unknown query";
            error_log(sprintf(
                "GraphQL query timeout exceeded: %.2fs (limit: %ds) - Query: %s",
                $execution_time,
                $this->query_timeout,
                $query_preview
            ));

            // Handle both ExecutionResult object and array response formats
            if (is_object($response) && method_exists($response, "toArray")) {
                // Convert ExecutionResult to array for manipulation
                $response_array = $response->toArray();

                // Add timeout error to response
                if (!isset($response_array["errors"])) {
                    $response_array["errors"] = [];
                }

                $response_array["errors"][] = [
                    "message" => sprintf(
                        /* translators: %d: timeout limit in seconds */
                        \__("Query execution timeout exceeded (%ds limit)", "silver-assist-security"),
                        $this->query_timeout
                    ),
                    "extensions" => [
                        "code" => "QUERY_TIMEOUT",
                        "execution_time" => $execution_time
                    ]
                ];

                // Create new ExecutionResult with timeout error
                return new ExecutionResult(
                    $response_array["data"] ?? null,
                    $response_array["errors"] ?? [],
                    $response_array["extensions"] ?? []
                );
            } elseif (is_array($response)) {
                // Handle array response format
                if (!isset($response["errors"])) {
                    $response["errors"] = [];
                }

                $response["errors"][] = [
                    "message" => sprintf(
                        /* translators: %d: timeout limit in seconds */
                        \__("Query execution timeout exceeded (%ds limit)", "silver-assist-security"),
                        $this->query_timeout
                    ),
                    "extensions" => [
                        "code" => "QUERY_TIMEOUT",
                        "execution_time" => $execution_time
                    ]
                ];
            }
        }

        return $response;
    }

    /**
     * Setup GraphQL rate limiting
     * 
     * @since 1.1.1
     * @return void
     */
    private function setup_graphql_rate_limiting(): void
    {
        \add_action("graphql_request", [$this, "check_rate_limit"]);
    }

    /**
     * Check rate limit for GraphQL requests using ConfigManager
     * 
     * @since 1.1.1
     * @return void
     * @throws UserError
     */
    public function check_rate_limit(): void
    {
        // Get rate limiting configuration from manager
        $rate_config = $this->config_manager->get_rate_limiting_config();

        $ip = $this->get_client_ip();
        $rate_limit_key = "graphql_rate_limit_{md5($ip)}";
        $time_window = 60; // seconds

        // Check if this is likely a build/development request
        $is_likely_build = $this->is_likely_build_process();

        // Use appropriate limits based on context
        if ($this->config_manager->is_headless_mode() || $is_likely_build) {
            $max_requests = $rate_config["burst_limit"];
        } else {
            $max_requests = $rate_config["requests_per_minute"];
        }

        $current_requests = \get_transient($rate_limit_key) ?: 0;

        if ($current_requests >= $max_requests) {
            throw new UserError(\__("Rate limit exceeded. Please try again later.", "silver-assist-security"));
        }

        \set_transient($rate_limit_key, $current_requests + 1, $time_window);
    }

    /**
     * Check if request is likely from a build process
     * 
     * @since 1.1.1
     * @return bool
     */
    private function is_likely_build_process(): bool
    {
        $user_agent = $_SERVER["HTTP_USER_AGENT"] ?? "";
        return preg_match("/(next|gatsby|nuxt|build|node|fetch)/i", $user_agent);
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
     * Log GraphQL requests for monitoring
     * 
     * @since 1.1.1
     * @param mixed $response GraphQL response (ExecutionResult object or array)
     * @param mixed $schema GraphQL schema
     * @param string|null $operation Operation name
     * @param string|null $query Query string (can be null in some GraphQL contexts)
     * @param array|null $variables Query variables
     * @return mixed
     */
    public function log_graphql_requests($response, $schema, ?string $operation, ?string $query, ?array $variables)
    {
        // Convert ExecutionResult to array for analysis if needed
        $response_array = is_object($response) && method_exists($response, "toArray") ?
            $response->toArray() :
            (is_array($response) ? $response : []);

        $log_data = [
            "timestamp" => \current_time("mysql"),
            "ip" => $this->get_client_ip(),
            "operation" => $operation,
            "query_length" => $query ? strlen($query) : 0,
            "has_errors" => !empty($response_array["errors"]),
            "execution_time" => microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"],
            "user_agent" => $_SERVER["HTTP_USER_AGENT"] ?? ""
        ];

        // Log suspicious patterns (only if query is not null)
        if ($query && $this->is_suspicious_query($query)) {
            $log_data["suspicious"] = true;
            $log_data["query_preview"] = substr($query, 0, 200) . "...";
            error_log("SECURITY: Suspicious GraphQL query - " . json_encode($log_data));
        }

        // Log all requests in debug mode
        if (defined("WP_DEBUG") && WP_DEBUG) {
            error_log("GraphQL request: " . json_encode($log_data));
        }

        return $response;
    }

    /**
     * Check if query contains suspicious patterns
     * 
     * @since 1.1.1
     * @param string $query The GraphQL query to analyze
     * @return bool
     */
    private function is_suspicious_query(string $query): bool
    {
        $max_query_length = $this->max_query_complexity * 50;
        $alias_threshold = max(5, intval($this->max_aliases / 2));
        $directive_threshold = max(3, intval($this->max_directives / 2));
        $field_duplicate_threshold = max(10, $this->max_field_duplicates * 5);

        $suspicious_patterns = [
            "/(__schema|__type).*\{.*\{.*\{/", // Deep introspection
            "/(\w+:\s*\w+.*){" . $alias_threshold . ",}/", // Many aliases
            "/(@\w+.*){" . $directive_threshold . ",}/", // Many directives
            "/.{" . $max_query_length . ",}/", // Very long query
            "/\{[^}]*(\w+[^}]*){" . $field_duplicate_threshold . ",}\}/" // Many field duplicates
        ];

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $query)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add GraphQL security headers
     * 
     * @since 1.1.1
     * @return void
     */
    public function add_graphql_security_headers(): void
    {
        if (isset($_SERVER["REQUEST_URI"]) && strpos($_SERVER["REQUEST_URI"], "/graphql") !== false) {
            header("X-Content-Type-Options: nosniff");
            header("X-Frame-Options: DENY");
            header("X-XSS-Protection: 1; mode=block");
            header("Referrer-Policy: strict-origin-when-cross-origin");

            // Disable caching for GraphQL responses
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Pragma: no-cache");
            header("Expires: Thu, 01 Jan 1970 00:00:00 GMT");
        }
    }

    /**
     * Validate query depth (placeholder for GraphQL validation rules)
     * 
     * @since 1.1.1
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_query_depth($context): array
    {
        return [];
    }

    /**
     * Validate query complexity using hybrid approach
     * 
     * Since WPGraphQL doesn't have native complexity analysis, we use a hybrid approach:
     * 1. Delegate depth validation to WPGraphQL's native QueryDepth rule
     * 2. Use enhanced proxy validation for complexity estimation
     * 3. Integrate with WPGraphQL's connection limits and rate limiting
     * 
     * @since 1.1.1
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_query_complexity($context): array
    {
        // WPGraphQL doesn't have native complexity analysis
        // Our complexity validation happens in validate_query_patterns() 
        // using enhanced heuristics combined with WPGraphQL's native features:
        // - Query depth: Handled by WPGraphQL's QueryDepth validation rule
        // - Connection limits: Handled by WPGraphQL's AbstractConnectionResolver
        // - Rate limiting: Our implementation with WPGraphQL integration
        // - Complexity estimation: Our enhanced proxy validation
        return [];
    }

    /**
     * Validate aliases (placeholder for GraphQL validation rules)
     * 
     * @since 1.1.1
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_aliases($context): array
    {
        return [];
    }

    /**
     * Validate directives (placeholder for GraphQL validation rules)
     * 
     * @since 1.1.1
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_directives($context): array
    {
        return [];
    }

    /**
     * Validate field duplicates (placeholder for GraphQL validation rules)
     * 
     * @since 1.1.1
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_field_duplicates($context): array
    {
        return [];
    }

    /**
     * Get current GraphQL query depth limit
     * 
     * @since 1.1.1
     * @return int
     */
    public function get_max_query_depth(): int
    {
        return $this->max_query_depth;
    }

    /**
     * Get current GraphQL query complexity limit
     * 
     * @since 1.1.1
     * @return int
     */
    public function get_max_query_complexity(): int
    {
        return $this->max_query_complexity;
    }

    /**
     * Get current GraphQL query timeout
     * 
     * @since 1.1.1
     * @return int
     */
    public function get_query_timeout(): int
    {
        return $this->query_timeout;
    }

    /**
     * Refresh configuration values
     * 
     * @since 1.1.1
     * @return void
     */
    public function refresh_configuration(): void
    {
        $this->init_configuration();
    }

    /**
     * Enable headless CMS mode with relaxed security settings
     * 
     * @since 1.1.1
     * @return void
     */
    public function enable_headless_mode(): void
    {
        \update_option("silver_assist_graphql_headless_mode", true);
        $this->headless_mode = true;
        $this->init_configuration();
    }

    /**
     * Disable headless CMS mode and use standard security settings
     * 
     * @since 1.1.1
     * @return void
     */
    public function disable_headless_mode(): void
    {
        \update_option("silver_assist_graphql_headless_mode", false);
        $this->headless_mode = false;
        $this->init_configuration();
    }

    /**
     * Check if headless mode is enabled using ConfigManager
     * 
     * @since 1.1.1
     * @return bool
     */
    public function is_headless_mode(): bool
    {
        return $this->config_manager->is_headless_mode();
    }

    /**
     * Get recommended settings for headless CMS usage
     * 
     * @since 1.1.1
     * @return array
     */
    public function get_headless_recommendations(): array
    {
        $recommendations = [
            "max_query_depth" => 20,
            "max_query_complexity" => 1000,
            "query_timeout" => 30,
            "rate_limit_per_minute" => 300,
            "recommended_settings" => [
                "Enable headless mode for relaxed limits",
                "Consider using query whitelisting for production",
                "Monitor query performance with logging",
                "Use query complexity analysis tools"
            ]
        ];

        // Add WPGraphQL-specific recommendations if available
        if (\class_exists("WPGraphQL") && \function_exists("get_graphql_setting")) {
            $recommendations["wpgraphql_integration"] = [
                "current_introspection" => get_graphql_setting("public_introspection_enabled", "off"),
                "current_batch_enabled" => get_graphql_setting("batch_queries_enabled", "on"),
                "current_batch_limit" => get_graphql_setting("batch_limit", 10),
                "current_depth_enabled" => get_graphql_setting("query_depth_enabled", "off"),
                "current_max_depth" => get_graphql_setting("query_depth_max_depth", 10),
                "recommendations" => [
                    "For headless CMS: Enable query depth limiting with max depth 15-20",
                    "For headless CMS: Keep batch queries enabled with limit 10-20",
                    "For production: Disable public introspection",
                    "For production: Disable debug mode",
                    "Consider authentication restriction based on your use case"
                ]
            ];
        }

        return $recommendations;
    }

    /**
     * Get current WPGraphQL configuration status using ConfigManager
     * 
     * @since 1.1.1
     * @return array
     */
    public function get_wpgraphql_status(): array
    {
        if (!$this->config_manager->is_wpgraphql_available()) {
            return [
                "available" => false,
                "message" => "WPGraphQL plugin not detected"
            ];
        }

        $config = $this->config_manager->get_configuration();
        $integration_status = $this->config_manager->get_integration_status();

        return [
            "available" => true,
            "settings" => [
                "introspection_enabled" => $config["introspection_enabled"],
                "debug_mode" => $config["debug_mode"],
                "batch_queries_enabled" => $config["batch_enabled"],
                "batch_limit" => $config["batch_limit"],
                "query_depth_enabled" => $config["query_depth_limit"] > 0,
                "query_depth_limit" => $config["query_depth_limit"],
                "auth_required" => $config["endpoint_access"] === "restricted"
            ],
            "security_status" => $integration_status["security_level"],
            "recommendations" => $integration_status["recommendations"]
        ];
    }
}
