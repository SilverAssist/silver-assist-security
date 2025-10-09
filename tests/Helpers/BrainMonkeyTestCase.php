<?php
/**
 * Brain Monkey Test Case Base Class
 *
 * Provides a base test case class that integrates Brain Monkey for WordPress function mocking.
 * All test classes should extend this class to leverage WordPress function mocking capabilities.
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.1.12
 * @version 1.1.12
 */

namespace SilverAssist\Security\Tests\Helpers;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

/**
 * Base test case with Brain Monkey integration
 *
 * This class provides WordPress function mocking capabilities using Brain Monkey,
 * along with Mockery integration for comprehensive testing.
 *
 * @since 1.1.12
 */
abstract class BrainMonkeyTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Set up test environment before each test
     *
     * Initializes Brain Monkey and sets up common WordPress function mocks.
     *
     * @since 1.1.12
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // Set up common WordPress function stubs
        $this->setupWordPressFunctions();
    }

    /**
     * Clean up after each test
     *
     * Tears down Brain Monkey and cleans up mocks.
     *
     * @since 1.1.12
     * @return void
     */
    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Set up common WordPress function mocks
     *
     * Provides default implementations for frequently used WordPress functions
     * that can be overridden in specific tests as needed.
     *
     * @since 1.1.12
     * @return void
     */
    protected function setupWordPressFunctions(): void
    {
        // Escaping functions
        Functions\when("esc_html")->returnArg();
        Functions\when("esc_attr")->returnArg();
        Functions\when("esc_url")->returnArg();
        Functions\when("esc_html__")->alias(function ($text, $domain = "default") {
            return $text;
        });
        Functions\when("esc_html_e")->alias(function ($text, $domain = "default") {
            echo $text;
        });
        Functions\when("esc_attr__")->alias(function ($text, $domain = "default") {
            return $text;
        });

        // Translation functions
        Functions\when("__")->alias(function ($text, $domain = "default") {
            return $text;
        });
        Functions\when("_e")->alias(function ($text, $domain = "default") {
            echo $text;
        });
        Functions\when("_x")->alias(function ($text, $context, $domain = "default") {
            return $text;
        });
        Functions\when("_n")->alias(function ($single, $plural, $number, $domain = "default") {
            return $number === 1 ? $single : $plural;
        });

        // Sanitization functions
        Functions\when("sanitize_text_field")->returnArg();
        Functions\when("sanitize_email")->returnArg();
        Functions\when("sanitize_key")->returnArg();
        Functions\when("sanitize_title")->returnArg();

        // WordPress utility functions
        Functions\when("wp_json_encode")->alias(function ($data, $options = 0, $depth = 512) {
            return json_encode($data, $options, $depth);
        });
        Functions\when("wp_parse_args")->alias(function ($args, $defaults = []) {
            if (is_object($args)) {
                $parsed_args = get_object_vars($args);
            } elseif (is_array($args)) {
                $parsed_args = $args;
            } else {
                parse_str($args, $parsed_args);
            }
            return array_merge($defaults, $parsed_args);
        });

        // Current time function
        Functions\when("current_time")->alias(function ($type, $gmt = 0) {
            switch ($type) {
                case "mysql":
                    return gmdate("Y-m-d H:i:s");
                case "timestamp":
                    return time();
                default:
                    return time();
            }
        });

        // WordPress error class mock
        Functions\when("is_wp_error")->alias(function ($thing) {
            return $thing instanceof \WP_Error;
        });
    }

    /**
     * Mock WordPress option functions
     *
     * Provides a simple in-memory option storage for testing.
     *
     * @since 1.1.12
     * @return void
     */
    protected function mockWordPressOptions(): void
    {
        $options = [];

        Functions\when("get_option")->alias(function ($option, $default = false) use (&$options) {
            return $options[$option] ?? $default;
        });

        Functions\when("update_option")->alias(function ($option, $value) use (&$options) {
            $options[$option] = $value;
            return true;
        });

        Functions\when("delete_option")->alias(function ($option) use (&$options) {
            if (isset($options[$option])) {
                unset($options[$option]);
                return true;
            }
            return false;
        });

        Functions\when("add_option")->alias(function ($option, $value) use (&$options) {
            if (!isset($options[$option])) {
                $options[$option] = $value;
                return true;
            }
            return false;
        });
    }

    /**
     * Mock WordPress transient functions
     *
     * Provides a simple in-memory transient storage for testing.
     *
     * @since 1.1.12
     * @return void
     */
    protected function mockWordPressTransients(): void
    {
        $transients = [];

        Functions\when("get_transient")->alias(function ($transient) use (&$transients) {
            if (isset($transients[$transient])) {
                if ($transients[$transient]["expiration"] === 0 || $transients[$transient]["expiration"] > time()) {
                    return $transients[$transient]["value"];
                }
                unset($transients[$transient]);
            }
            return false;
        });

        Functions\when("set_transient")->alias(function ($transient, $value, $expiration = 0) use (&$transients) {
            $transients[$transient] = [
                "value" => $value,
                "expiration" => $expiration > 0 ? time() + $expiration : 0,
            ];
            return true;
        });

        Functions\when("delete_transient")->alias(function ($transient) use (&$transients) {
            if (isset($transients[$transient])) {
                unset($transients[$transient]);
                return true;
            }
            return false;
        });
    }

    /**
     * Mock WordPress user functions
     *
     * Provides mock user-related functions for testing.
     *
     * @since 1.1.12
     * @return void
     */
    protected function mockWordPressUserFunctions(): void
    {
        Functions\when("is_user_logged_in")->justReturn(false);
        Functions\when("current_user_can")->justReturn(false);
        Functions\when("wp_get_current_user")->alias(function () {
            return (object) [
                "ID" => 0,
                "user_login" => "",
                "user_email" => "",
            ];
        });
    }

    /**
     * Mock WordPress hook functions
     *
     * Provides mock hook functions for testing.
     *
     * @since 1.1.12
     * @return void
     */
    protected function mockWordPressHooks(): void
    {
        Functions\when("add_action")->justReturn(true);
        Functions\when("add_filter")->justReturn(true);
        Functions\when("remove_action")->justReturn(true);
        Functions\when("remove_filter")->justReturn(true);
        Functions\when("do_action")->justReturn(null);
        Functions\when("apply_filters")->returnArg();
        Functions\when("has_action")->justReturn(false);
        Functions\when("has_filter")->justReturn(false);
    }

    /**
     * Create a mock WP_Error object
     *
     * @since 1.1.12
     * @param string $code Error code
     * @param string $message Error message
     * @param mixed $data Optional error data
     * @return \WP_Error
     */
    protected function createWpError(string $code, string $message, $data = ""): \WP_Error
    {
        return new \WP_Error($code, $message, $data);
    }

    /**
     * Assert that a WordPress action was added
     *
     * @since 1.1.12
     * @param string $hook The hook name
     * @param callable|null $callback Optional callback to verify
     * @param int|null $priority Optional priority to verify
     * @return void
     */
    protected function assertActionAdded(string $hook, ?callable $callback = null, ?int $priority = null): void
    {
        $this->assertTrue(
            Monkey\Actions\has($hook),
            "Action '{$hook}' was not added"
        );
    }

    /**
     * Assert that a WordPress filter was added
     *
     * @since 1.1.12
     * @param string $hook The hook name
     * @param callable|null $callback Optional callback to verify
     * @param int|null $priority Optional priority to verify
     * @return void
     */
    protected function assertFilterAdded(string $hook, ?callable $callback = null, ?int $priority = null): void
    {
        $this->assertTrue(
            Monkey\Filters\has($hook),
            "Filter '{$hook}' was not added"
        );
    }
}
