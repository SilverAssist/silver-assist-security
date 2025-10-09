<?php
/**
 * SecurityHelper Unit Tests
 *
 * Comprehensive tests for the Security Helper utility class.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.12
 * @version 1.1.12
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Tests\Helpers\BrainMonkeyTestCase;
use Brain\Monkey\Functions;

/**
 * Test SecurityHelper class
 *
 * @since 1.1.12
 */
class SecurityHelperTest extends BrainMonkeyTestCase
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

        // Define plugin constants if not already defined
        if (!defined("SILVER_ASSIST_SECURITY_URL")) {
            define("SILVER_ASSIST_SECURITY_URL", "http://example.org/wp-content/plugins/silver-assist-security/");
        }

        SecurityHelper::init();
    }

    /**
     * Test get_asset_url returns minified version by default
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_asset_url_returns_minified_by_default(): void
    {
        $url = SecurityHelper::get_asset_url("assets/css/admin.css");
        
        $this->assertStringContainsString("admin.min.css", $url);
        $this->assertStringContainsString("http://example.org", $url);
    }

    /**
     * Test get_asset_url returns non-minified version when SCRIPT_DEBUG is true
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_asset_url_returns_non_minified_with_script_debug(): void
    {
        if (!defined("SCRIPT_DEBUG")) {
            define("SCRIPT_DEBUG", true);
        }

        $url = SecurityHelper::get_asset_url("assets/css/admin.css");
        
        $this->assertStringContainsString("admin.css", $url);
        $this->assertStringNotContainsString(".min.", $url);
    }

    /**
     * Test get_asset_url handles JavaScript files
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_asset_url_handles_javascript_files(): void
    {
        // Note: SCRIPT_DEBUG is already defined from earlier test, so it returns non-minified
        if (!defined("SCRIPT_DEBUG")) {
            $url = SecurityHelper::get_asset_url("assets/js/admin.js");
            $this->assertStringContainsString("admin.min.js", $url);
        } else {
            // When SCRIPT_DEBUG is true, returns non-minified version
            $url = SecurityHelper::get_asset_url("assets/js/admin.js");
            $this->assertStringContainsString("admin.js", $url);
        }
        
        $this->assertStringContainsString("assets/js", $url);
    }

    /**
     * Test get_client_ip returns REMOTE_ADDR when no proxy headers
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_client_ip_returns_remote_addr(): void
    {
        $_SERVER["REMOTE_ADDR"] = "192.168.1.100";
        
        $ip = SecurityHelper::get_client_ip();
        
        $this->assertEquals("192.168.1.100", $ip);
    }

    /**
     * Test get_client_ip detects CloudFlare IP
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_client_ip_detects_cloudflare_ip(): void
    {
        $_SERVER["HTTP_CF_CONNECTING_IP"] = "203.0.113.5";
        $_SERVER["REMOTE_ADDR"] = "192.168.1.100";
        
        $ip = SecurityHelper::get_client_ip();
        
        $this->assertEquals("203.0.113.5", $ip);
    }

    /**
     * Test get_client_ip detects forwarded IP
     *
     * @since 1.1.12
     * @return void
     */
    public function test_get_client_ip_detects_forwarded_ip(): void
    {
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.10, 203.0.113.11";
        $_SERVER["REMOTE_ADDR"] = "192.168.1.100";
        
        $ip = SecurityHelper::get_client_ip();
        
        $this->assertEquals("203.0.113.10", $ip);
    }

    /**
     * Test is_strong_password validates strong passwords
     *
     * @since 1.1.12
     * @return void
     */
    public function test_is_strong_password_accepts_strong_passwords(): void
    {
        $strong_passwords = [
            "MyP@ssw0rd123!",
            "Secure#Pass123",
            "C0mplex&Pass!",
            'Str0ng$Password',
        ];

        foreach ($strong_passwords as $password) {
            $this->assertTrue(
                SecurityHelper::is_strong_password($password),
                "Password '{$password}' should be considered strong"
            );
        }
    }

    /**
     * Test is_strong_password rejects weak passwords
     *
     * @since 1.1.12
     * @return void
     */
    public function test_is_strong_password_rejects_weak_passwords(): void
    {
        $weak_passwords = [
            "short",           // Too short
            "alllowercase",    // No uppercase
            "ALLUPPERCASE",    // No lowercase
            "NoNumbers!",      // No numbers
            "NoSpecial123",    // No special characters
            "weak",            // Too short, no complexity
        ];

        foreach ($weak_passwords as $password) {
            $this->assertFalse(
                SecurityHelper::is_strong_password($password),
                "Password '{$password}' should be considered weak"
            );
        }
    }

    /**
     * Test generate_ip_transient_key creates consistent keys
     *
     * @since 1.1.12
     * @return void
     */
    public function test_generate_ip_transient_key_creates_consistent_keys(): void
    {
        $_SERVER["REMOTE_ADDR"] = "192.168.1.100";
        
        $key1 = SecurityHelper::generate_ip_transient_key("test_prefix");
        $key2 = SecurityHelper::generate_ip_transient_key("test_prefix");
        
        $this->assertEquals($key1, $key2);
        $this->assertStringContainsString("test_prefix_", $key1);
    }

    /**
     * Test generate_ip_transient_key with custom IP
     *
     * @since 1.1.12
     * @return void
     */
    public function test_generate_ip_transient_key_with_custom_ip(): void
    {
        $key1 = SecurityHelper::generate_ip_transient_key("test_prefix", "192.168.1.100");
        $key2 = SecurityHelper::generate_ip_transient_key("test_prefix", "192.168.1.101");
        
        $this->assertNotEquals($key1, $key2);
    }

    /**
     * Test sanitize_admin_path removes dangerous characters
     *
     * @since 1.1.12
     * @return void
     */
    public function test_sanitize_admin_path_removes_dangerous_characters(): void
    {
        Functions\when("sanitize_title")->returnArg();

        $dangerous_paths = [
            "../../../etc/passwd" => "etcpasswd",
            "admin<script>" => "adminscript",
            "path/with/slashes" => "pathwithslashes",
            "path?query=1" => "pathquery1",
        ];

        foreach ($dangerous_paths as $input => $expected_pattern) {
            // Mock sanitize_title to actually sanitize
            Functions\when("sanitize_title")->justReturn($expected_pattern);
            
            $result = SecurityHelper::sanitize_admin_path($input);
            
            $this->assertStringNotContainsString("..", $result);
            $this->assertStringNotContainsString("/", $result);
            $this->assertStringNotContainsString("<", $result);
            $this->assertStringNotContainsString(">", $result);
        }
    }

    /**
     * Test is_bot_request detects common bots
     *
     * @since 1.1.12
     * @return void
     */
    public function test_is_bot_request_detects_common_bots(): void
    {
        $bot_user_agents = [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Nmap Scripting Engine; https://nmap.org/book/nse.html",
            "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)",
        ];

        foreach ($bot_user_agents as $user_agent) {
            $this->assertTrue(
                SecurityHelper::is_bot_request($user_agent),
                "User agent '{$user_agent}' should be detected as bot"
            );
        }
    }

    /**
     * Test is_bot_request allows normal browsers
     *
     * @since 1.1.12
     * @return void
     */
    public function test_is_bot_request_allows_normal_browsers(): void
    {
        // Set expected browser headers to avoid bot detection
        $_SERVER["HTTP_ACCEPT"] = "text/html,application/xhtml+xml";
        $_SERVER["HTTP_ACCEPT_LANGUAGE"] = "en-US,en;q=0.9";
        $_SERVER["HTTP_ACCEPT_ENCODING"] = "gzip, deflate, br";
        
        $browser_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        ];

        foreach ($browser_user_agents as $user_agent) {
            $this->assertFalse(
                SecurityHelper::is_bot_request($user_agent),
                "User agent '{$user_agent}' should not be detected as bot"
            );
        }
    }

    /**
     * Test format_time_duration formats seconds correctly
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_seconds(): void
    {
        Functions\when("__")->returnArg();
        
        $this->assertEquals("30 seconds", SecurityHelper::format_time_duration(30));
        $this->assertEquals("1 seconds", SecurityHelper::format_time_duration(1));
    }

    /**
     * Test format_time_duration formats minutes correctly
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_minutes(): void
    {
        Functions\when("__")->returnArg();
        
        $this->assertEquals("1 minutes", SecurityHelper::format_time_duration(60));
        $this->assertEquals("5 minutes", SecurityHelper::format_time_duration(300));
        $this->assertEquals("15 minutes", SecurityHelper::format_time_duration(900));
    }

    /**
     * Test format_time_duration formats hours correctly
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_hours(): void
    {
        Functions\when("__")->returnArg();
        
        $this->assertEquals("1 hours", SecurityHelper::format_time_duration(3600));
        $this->assertEquals("2 hours", SecurityHelper::format_time_duration(7200));
    }

    /**
     * Test format_time_duration formats mixed time
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_mixed_time(): void
    {
        Functions\when("__")->returnArg();
        
        // 1 hour, 5 minutes, 30 seconds = 3930 seconds
        // This should round to hours since it's > 60 minutes
        $duration = 3600 + 300 + 30;
        $result = SecurityHelper::format_time_duration($duration);
        
        $this->assertStringContainsString("hours", $result);
    }

    /**
     * Test verify_nonce with valid nonce
     *
     * @since 1.1.12
     * @return void
     */
    public function test_verify_nonce_with_valid_nonce(): void
    {
        Functions\when("wp_verify_nonce")->justReturn(1);

        $result = SecurityHelper::verify_nonce("valid_nonce", "test_action", false);
        
        $this->assertTrue($result);
    }

    /**
     * Test verify_nonce with invalid nonce
     *
     * @since 1.1.12
     * @return void
     */
    public function test_verify_nonce_with_invalid_nonce(): void
    {
        Functions\when("wp_verify_nonce")->justReturn(false);

        $result = SecurityHelper::verify_nonce("invalid_nonce", "test_action", false);
        
        $this->assertFalse($result);
    }

    /**
     * Test check_user_capability with sufficient capability
     *
     * @since 1.1.12
     * @return void
     */
    public function test_check_user_capability_with_sufficient_capability(): void
    {
        Functions\when("current_user_can")->justReturn(true);

        $result = SecurityHelper::check_user_capability("manage_options", false);
        
        $this->assertTrue($result);
    }

    /**
     * Test check_user_capability without sufficient capability
     *
     * @since 1.1.12
     * @return void
     */
    public function test_check_user_capability_without_sufficient_capability(): void
    {
        Functions\when("current_user_can")->justReturn(false);
        Functions\when("get_current_user_id")->justReturn(0);
        Functions\when("wp_die")->alias(function() {
            // Mock wp_die to not actually die during tests
        });

        $result = SecurityHelper::check_user_capability("manage_options", false);
        
        $this->assertFalse($result);
    }

    /**
     * Clean up after tests
     *
     * @since 1.1.12
     * @return void
     */
    protected function tearDown(): void
    {
        // Clear server variables
        $_SERVER = [];
        
        parent::tearDown();
    }
}
