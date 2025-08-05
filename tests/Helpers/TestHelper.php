<?php
/**
 * Test Helper Class
 *
 * Provides utility functions for testing Silver Assist Security Essentials
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Helpers;

/**
 * Test Helper class
 */
class TestHelper
{
    /**
     * Create a mock WordPress user
     *
     * @param array $args User arguments
     * @return int User ID
     */
    public static function create_test_user(array $args = []): int
    {
        $defaults = [
            'user_login' => 'testuser_' . wp_generate_password(8, false),
            'user_email' => 'test@example.com',
            'user_pass' => 'TestPassword123!',
            'role' => 'subscriber'
        ];

        $user_data = wp_parse_args($args, $defaults);
        return wp_insert_user($user_data);
    }

    /**
     * Delete test user
     *
     * @param int $user_id User ID to delete
     * @return bool Success status
     */
    public static function delete_test_user(int $user_id): bool
    {
        return wp_delete_user($user_id);
    }

    /**
     * Set up mock HTTP request
     *
     * @param array $server_vars Server variables to set
     * @return void
     */
    public static function mock_http_request(array $server_vars = []): void
    {
        $defaults = [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Test Browser)',
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_ACCEPT' => 'text/html,application/xhtml+xml',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.5'
        ];

        foreach (wp_parse_args($server_vars, $defaults) as $key => $value) {
            $_SERVER[$key] = $value;
        }
    }

    /**
     * Clean up transients for testing
     *
     * @param string $prefix Transient prefix to clean
     * @return void
     */
    public static function cleanup_transients(string $prefix = 'silver_assist'): void
    {
        global $wpdb;

        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
            $wpdb->esc_like('_transient_' . $prefix) . '%',
            $wpdb->esc_like('_transient_timeout_' . $prefix) . '%'
        ));
    }

    /**
     * Simulate login attempt
     *
     * @param string $username Username
     * @param string $password Password
     * @param string $ip IP address
     * @return \WP_User|\WP_Error
     */
    public static function simulate_login(string $username, string $password, string $ip = '127.0.0.1')
    {
        $_SERVER['REMOTE_ADDR'] = $ip;
        
        return wp_authenticate($username, $password);
    }

    /**
     * Mock bot user agent
     *
     * @param string $bot_type Type of bot to simulate
     * @return void
     */
    public static function mock_bot_user_agent(string $bot_type = 'crawler'): void
    {
        $bot_agents = [
            'crawler' => 'Mozilla/5.0 (compatible; Baiduspider/2.0)',
            'scanner' => 'Nikto/2.1.6',
            'bot' => 'Bot/1.0',
            'empty' => '',
            'short' => 'X'
        ];

        $_SERVER['HTTP_USER_AGENT'] = $bot_agents[$bot_type] ?? $bot_agents['crawler'];
    }

    /**
     * Assert security option value
     *
     * @param string $option_name Option name
     * @param mixed $expected_value Expected value
     * @return void
     */
    public static function assert_security_option(string $option_name, $expected_value): void
    {
        $actual_value = get_option($option_name);
        
        if ($actual_value !== $expected_value) {
            throw new \Exception(
                sprintf(
                    'Security option %s expected %s but got %s',
                    $option_name,
                    var_export($expected_value, true),
                    var_export($actual_value, true)
                )
            );
        }
    }

    /**
     * Create GraphQL query for testing
     *
     * @param int $depth Query depth
     * @param int $complexity Query complexity
     * @return string GraphQL query
     */
    public static function create_graphql_query(int $depth = 5, int $complexity = 50): string
    {
        $query = 'query { ';
        
        for ($i = 0; $i < $depth; $i++) {
            $query .= 'posts { ';
        }
        
        $query .= 'id title content ';
        
        for ($i = 0; $i < $depth; $i++) {
            $query .= '} ';
        }
        
        $query .= '}';
        
        return $query;
    }
}
