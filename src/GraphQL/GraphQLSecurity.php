<?php
/**
 * Silver Assist Security Essentials - GraphQL Security Protection
 *
 * Implements comprehensive GraphQL security including query depth/complexity limits,
 * rate limiting, introspection control, and request validation. Provides protection
 * against GraphQL-specific attacks and resource exhaustion.
 *
 * @package SilverAssist\Security\GraphQL
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.2
 */

namespace SilverAssist\Security\GraphQL;

/**
 * GraphQL Security class
 * 
 * Handles GraphQL security features including query depth/complexity limits,
 * rate limiting, introspection control, and security validations
 * 
 * @since 1.0.0
 */
class GraphQLSecurity
{

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
    private int $max_aliases = 10;

    /**
     * Maximum allowed duplicate directives per query
     * 
     * @var int
     */
    private int $max_directives = 5;

    /**
     * Maximum allowed field duplicates
     * 
     * @var int
     */
    private int $max_field_duplicates = 3;

    /**
     * Query execution timeout in seconds
     * 
     * @var int
     */
    private int $query_timeout;

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
     * Initialize configuration values from saved settings
     * 
     * @since 1.0.0
     * @return void
     */
    private function init_configuration(): void
    {
        $this->max_query_depth = (int) \get_option("silver_assist_graphql_query_depth", 8);
        $this->max_query_complexity = (int) \get_option("silver_assist_graphql_query_complexity", 100);
        $this->query_timeout = (int) \get_option("silver_assist_graphql_query_timeout", 5);

        // Ensure values are within safe ranges
        $this->max_query_depth = max(1, min(20, $this->max_query_depth));
        $this->max_query_complexity = max(10, min(1000, $this->max_query_complexity));
        $this->query_timeout = max(1, min(30, $this->query_timeout));
    }

    /**
     * Initialize GraphQL security features
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
     * @return void
     */
    public function disable_introspection_in_production(): void
    {
        if (defined("WP_ENVIRONMENT_TYPE") && WP_ENVIRONMENT_TYPE === "production") {
            \add_filter("graphql_introspection_enabled", "__return_false");

            \add_action("graphql_register_types", function () {
                \remove_action("graphql_register_types", ["WPGraphQL\\Type\\Introspection", "register_introspection_fields"]);
            }, 1);
        }
    }

    /**
     * Add security validations
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_security_validations(): void
    {
        add_filter('graphql_validation_rules', [$this, 'add_custom_validation_rules']);
    }

    /**
     * Add custom validation rules
     * 
     * @since 1.0.0
     * @param array $rules Existing validation rules
     * @return array
     */
    public function add_custom_validation_rules(array $rules): array
    {
        $rules[] = [$this, 'validate_query_depth'];
        $rules[] = [$this, 'validate_query_complexity'];
        $rules[] = [$this, 'validate_aliases'];
        $rules[] = [$this, 'validate_directives'];
        $rules[] = [$this, 'validate_field_duplicates'];

        return $rules;
    }

    /**
     * Validate query before execution
     * 
     * @since 1.0.0
     * @param array $request_data Request data including query
     * @param mixed $request HTTP request object
     * @param string|null $operation_name GraphQL operation name
     * @param array|null $variables Query variables
     * @param mixed $context Request context
     * @return array
     * @throws \GraphQL\Error\UserError
     */
    public function validate_query_before_execution(array $request_data, $request, ?string $operation_name, ?array $variables, $context): array
    {
        if (empty($request_data['query'])) {
            return $request_data;
        }

        $query = $request_data['query'];

        // Check for introspection in production
        if (defined('WP_ENVIRONMENT_TYPE') && WP_ENVIRONMENT_TYPE === 'production') {
            if ($this->is_introspection_query($query)) {
                throw new \GraphQL\Error\UserError('Introspection is disabled in production.');
            }
        }

        // Validate query patterns
        $this->validate_query_patterns($query);

        return $request_data;
    }

    /**
     * Check if query is introspection
     * 
     * @since 1.0.0
     * @param string $query GraphQL query string
     * @return bool
     */
    private function is_introspection_query(string $query): bool
    {
        return preg_match('/(__schema|__type|__typename|__directive)/i', $query);
    }

    /**
     * Validate query patterns for security issues
     * 
     * @since 1.0.0
     * @param string $query GraphQL query string
     * @return void
     * @throws \GraphQL\Error\UserError
     */
    private function validate_query_patterns(string $query): void
    {
        // Check for excessive aliases
        $alias_count = preg_match_all('/\w+\s*:\s*\w+/', $query);
        if ($alias_count > $this->max_aliases) {
            throw new \GraphQL\Error\UserError(
                sprintf(
                    'Query contains too many aliases (%d). Maximum allowed: %d',
                    $alias_count,
                    $this->max_aliases
                )
            );
        }

        // Check for excessive directive usage
        $directive_count = preg_match_all('/@\w+/', $query);
        if ($directive_count > $this->max_directives * 2) {
            throw new \GraphQL\Error\UserError(
                sprintf(
                    'Query contains too many directives (%d). Maximum allowed: %d',
                    $directive_count,
                    $this->max_directives * 2
                )
            );
        }

        // Check for field duplication patterns
        if (preg_match('/(\w+)(\s*\w+\s*)*\{[^}]*\1[^}]*\1/', $query)) {
            throw new \GraphQL\Error\UserError(
                sprintf(
                    'Query contains excessive field duplication. Maximum allowed: %d',
                    $this->max_field_duplicates
                )
            );
        }

        // Check for potential circular queries using configured depth limit
        $depth_pattern = str_repeat('\{[^}]*', $this->max_query_depth + 1);
        if (preg_match("/$depth_pattern/", $query)) {
            throw new \GraphQL\Error\UserError(
                sprintf('Query depth exceeds maximum limit of %d levels.', $this->max_query_depth)
            );
        }

        // Check for excessively long queries (potential DoS)
        $max_query_length = $this->max_query_complexity * 100;
        if (strlen($query) > $max_query_length) {
            throw new \GraphQL\Error\UserError(
                sprintf(
                    'Query is too large (%d characters). Maximum allowed: %d characters.',
                    strlen($query),
                    $max_query_length
                )
            );
        }
    }

    /**
     * Set execution timeout
     * 
     * @since 1.0.0
     * @return void
     */
    public function set_execution_timeout(): void
    {
        if (!ini_get('max_execution_time') || ini_get('max_execution_time') > $this->query_timeout) {
            set_time_limit($this->query_timeout);
        }
    }

    /**
     * Setup GraphQL rate limiting
     * 
     * @since 1.0.0
     * @return void
     */
    private function setup_graphql_rate_limiting(): void
    {
        add_action('graphql_request', [$this, 'check_rate_limit']);
    }

    /**
     * Check rate limit for GraphQL requests
     * 
     * @since 1.0.0
     * @return void
     * @throws \GraphQL\Error\UserError
     */
    public function check_rate_limit(): void
    {
        $ip = $this->get_client_ip();
        $rate_limit_key = 'graphql_rate_limit_' . md5($ip);
        $max_requests = 30; // requests per minute
        $time_window = 60; // seconds

        $current_requests = get_transient($rate_limit_key) ?: 0;

        if ($current_requests >= $max_requests) {
            throw new \GraphQL\Error\UserError('Rate limit exceeded. Please try again later.');
        }

        set_transient($rate_limit_key, $current_requests + 1, $time_window);
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
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Log GraphQL requests for monitoring
     * 
     * @since 1.0.0
     * @param array $response GraphQL response
     * @param mixed $schema GraphQL schema
     * @param string|null $operation Operation name
     * @param string $query Query string
     * @param array|null $variables Query variables
     * @return array
     */
    public function log_graphql_requests(array $response, $schema, ?string $operation, string $query, ?array $variables): array
    {
        $log_data = [
            'timestamp' => current_time('mysql'),
            'ip' => $this->get_client_ip(),
            'operation' => $operation,
            'query_length' => strlen($query),
            'has_errors' => !empty($response['errors']),
            'execution_time' => microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ];

        // Log suspicious patterns
        if ($this->is_suspicious_query($query)) {
            $log_data['suspicious'] = true;
            $log_data['query_preview'] = substr($query, 0, 200) . '...';
            error_log('SECURITY: Suspicious GraphQL query - ' . json_encode($log_data));
        }

        // Log all requests in debug mode
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('GraphQL request: ' . json_encode($log_data));
        }

        return $response;
    }

    /**
     * Check if query contains suspicious patterns
     * 
     * @since 1.0.0
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
            '/(__schema|__type).*\{.*\{.*\{/', // Deep introspection
            '/(\w+:\s*\w+.*){' . $alias_threshold . ',}/', // Many aliases
            '/(@\w+.*){' . $directive_threshold . ',}/', // Many directives
            '/.{' . $max_query_length . ',}/', // Very long query
            '/\{[^}]*(\w+[^}]*){' . $field_duplicate_threshold . ',}\}/' // Many field duplicates
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
     * @since 1.0.0
     * @return void
     */
    public function add_graphql_security_headers(): void
    {
        if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/graphql') !== false) {
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
            header('X-XSS-Protection: 1; mode=block');
            header('Referrer-Policy: strict-origin-when-cross-origin');

            // Disable caching for GraphQL responses
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        }
    }

    /**
     * Validate query depth (placeholder for GraphQL validation rules)
     * 
     * @since 1.0.0
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_query_depth($context): array
    {
        return [];
    }

    /**
     * Validate query complexity (placeholder for GraphQL validation rules)
     * 
     * @since 1.0.0
     * @param mixed $context GraphQL context
     * @return array
     */
    public function validate_query_complexity($context): array
    {
        return [];
    }

    /**
     * Validate aliases (placeholder for GraphQL validation rules)
     * 
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
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
     * @since 1.0.0
     * @return int
     */
    public function get_max_query_depth(): int
    {
        return $this->max_query_depth;
    }

    /**
     * Get current GraphQL query complexity limit
     * 
     * @since 1.0.0
     * @return int
     */
    public function get_max_query_complexity(): int
    {
        return $this->max_query_complexity;
    }

    /**
     * Get current GraphQL query timeout
     * 
     * @since 1.0.0
     * @return int
     */
    public function get_query_timeout(): int
    {
        return $this->query_timeout;
    }

    /**
     * Refresh configuration values
     * 
     * @since 1.0.0
     * @return void
     */
    public function refresh_configuration(): void
    {
        $this->init_configuration();
    }
}
