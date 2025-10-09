<?php
/**
 * DefaultConfig Unit Tests
 *
 * Tests for the centralized configuration management class.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.12
 * @version 1.1.12
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Core\DefaultConfig;

/**
 * Test DefaultConfig class
 *
 * @since 1.1.12
 */
class DefaultConfigTest extends \WP_UnitTestCase
{
    /**
     * Set up test environment
     *
     * @since 1.1.12
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        // WordPress Test Suite provides real get_option/update_option
        // No mocking needed
    }

    /**
     * Test get_defaults returns array with all expected keys
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_defaults_returns_complete_array(): void
    {
        $defaults = DefaultConfig::get_defaults();

        $this->assertIsArray($defaults);
        $this->assertNotEmpty($defaults);

        // Check for all expected configuration keys
        $expected_keys = [
            "silver_assist_login_attempts",
            "silver_assist_lockout_duration",
            "silver_assist_session_timeout",
            "silver_assist_password_strength_enforcement",
            "silver_assist_bot_protection",
            "silver_assist_graphql_query_depth",
            "silver_assist_graphql_query_complexity",
            "silver_assist_graphql_query_timeout",
            "silver_assist_graphql_headless_mode",
        ];

        foreach ($expected_keys as $key) {
            $this->assertArrayHasKey($key, $defaults, "Missing configuration key: {$key}");
        }
    }

    /**
     * Test get_defaults returns correct default values
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_defaults_returns_correct_values(): void
    {
        $defaults = DefaultConfig::get_defaults();

        // Login security defaults
        $this->assertEquals(5, $defaults["silver_assist_login_attempts"]);
        $this->assertEquals(900, $defaults["silver_assist_lockout_duration"]);
        $this->assertEquals(30, $defaults["silver_assist_session_timeout"]);
        $this->assertEquals(1, $defaults["silver_assist_password_strength_enforcement"]);
        $this->assertEquals(1, $defaults["silver_assist_bot_protection"]);

        // GraphQL defaults
        $this->assertEquals(8, $defaults["silver_assist_graphql_query_depth"]);
        $this->assertEquals(100, $defaults["silver_assist_graphql_query_complexity"]);
        $this->assertEquals(30, $defaults["silver_assist_graphql_query_timeout"]); // Updated: default is 30s based on PHP max_execution_time
        $this->assertEquals(0, $defaults["silver_assist_graphql_headless_mode"]);
    }

    /**
     * Test get_default returns correct value for existing key
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_default_returns_value_for_existing_key(): void
    {
        $value = DefaultConfig::get_default("silver_assist_login_attempts");
        $this->assertEquals(5, $value);

        $value = DefaultConfig::get_default("silver_assist_graphql_query_depth");
        $this->assertEquals(8, $value);
    }

    /**
     * Test get_default returns null for non-existing key
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_default_returns_null_for_non_existing_key(): void
    {
        $value = DefaultConfig::get_default("non_existing_key");
        $this->assertNull($value);
    }

    /**
     * Test get_option returns WordPress option value when exists
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_option_returns_wordpress_option_when_exists(): void
    {
        // Use real WordPress update_option (provided by WordPress Test Suite)
        update_option("silver_assist_login_attempts", 10);

        $value = DefaultConfig::get_option("silver_assist_login_attempts");
        $this->assertEquals(10, $value);
    }

    /**
     * Test get_option returns default when WordPress option doesn't exist
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_option_returns_default_when_option_not_exists(): void
    {
        // Delete option to ensure it doesn't exist
        delete_option("silver_assist_login_attempts");

        // Should return default value (5) when option doesn't exist
        $value = DefaultConfig::get_option("silver_assist_login_attempts");
        $this->assertEquals(5, $value);
    }

    /**
     * Test get_option returns null for non-configured option
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_option_returns_null_for_non_configured_option(): void
    {
        // Delete option to ensure it doesn't exist
        delete_option("non_existing_option");

        // Should return null for non-configured option
        $value = DefaultConfig::get_option("non_existing_option");
        $this->assertNull($value);
    }

    /**
     * Test all login security configuration keys
     *
     * @since 1.1.12
     * @return void
     */
    public function test_all_login_security_config_keys_exist(): void
    {
        $defaults = DefaultConfig::get_defaults();

        $login_keys = [
            "silver_assist_login_attempts",
            "silver_assist_lockout_duration",
            "silver_assist_session_timeout",
            "silver_assist_password_strength_enforcement",
            "silver_assist_bot_protection",
        ];

        foreach ($login_keys as $key) {
            $this->assertArrayHasKey($key, $defaults);
            $this->assertNotNull($defaults[$key]);
        }
    }

    /**
     * Test all GraphQL configuration keys
     *
     * @since 1.1.12
     * @return void
     */
    public function test_all_graphql_config_keys_exist(): void
    {
        $defaults = DefaultConfig::get_defaults();

        $graphql_keys = [
            "silver_assist_graphql_query_depth",
            "silver_assist_graphql_query_complexity",
            "silver_assist_graphql_query_timeout",
            "silver_assist_graphql_headless_mode",
        ];

        foreach ($graphql_keys as $key) {
            $this->assertArrayHasKey($key, $defaults);
            $this->assertNotNull($defaults[$key]);
        }
    }

    /**
     * Test configuration values are within valid ranges
     *
     * @since 1.1.12
     * @return void
     */
    public function test_configuration_values_are_within_valid_ranges(): void
    {
        $defaults = DefaultConfig::get_defaults();

        // Login attempts should be between 1 and 20
        $this->assertGreaterThanOrEqual(1, $defaults["silver_assist_login_attempts"]);
        $this->assertLessThanOrEqual(20, $defaults["silver_assist_login_attempts"]);

        // Lockout duration should be positive
        $this->assertGreaterThan(0, $defaults["silver_assist_lockout_duration"]);

        // Session timeout should be between 5 and 120 minutes
        $this->assertGreaterThanOrEqual(5, $defaults["silver_assist_session_timeout"]);
        $this->assertLessThanOrEqual(120, $defaults["silver_assist_session_timeout"]);

        // GraphQL query depth should be between 1 and 20
        $this->assertGreaterThanOrEqual(1, $defaults["silver_assist_graphql_query_depth"]);
        $this->assertLessThanOrEqual(20, $defaults["silver_assist_graphql_query_depth"]);

        // GraphQL complexity should be between 10 and 1000
        $this->assertGreaterThanOrEqual(10, $defaults["silver_assist_graphql_query_complexity"]);
        $this->assertLessThanOrEqual(1000, $defaults["silver_assist_graphql_query_complexity"]);

        // GraphQL timeout should be between 1 and 30 seconds
        $this->assertGreaterThanOrEqual(1, $defaults["silver_assist_graphql_query_timeout"]);
        $this->assertLessThanOrEqual(30, $defaults["silver_assist_graphql_query_timeout"]);
    }

    /**
     * Test boolean configuration values
     *
     * @since 1.1.12
     * @return void
     */
    public function test_boolean_configuration_values(): void
    {
        $defaults = DefaultConfig::get_defaults();

        // These should be 0 or 1 (boolean flags)
        $boolean_keys = [
            "silver_assist_password_strength_enforcement",
            "silver_assist_bot_protection",
            "silver_assist_graphql_headless_mode",
        ];

        foreach ($boolean_keys as $key) {
            $value = $defaults[$key];
            $this->assertTrue($value === 0 || $value === 1, "Key {$key} should be 0 or 1");
        }
    }
}
