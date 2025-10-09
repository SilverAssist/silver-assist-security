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
use WP_UnitTestCase;

/**
 * Test SecurityHelper class
 *
 * @since 1.1.12
 */
class SecurityHelperTest extends WP_UnitTestCase
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
        if (!\defined("SILVER_ASSIST_SECURITY_URL")) {
            \define("SILVER_ASSIST_SECURITY_URL", "http://example.org/wp-content/plugins/silver-assist-security/");
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
        // Use force_debug parameter to simulate SCRIPT_DEBUG = true
        $url = SecurityHelper::get_asset_url("assets/css/admin.css", true);
        
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
        // Test with debug mode (non-minified)
        $url_debug = SecurityHelper::get_asset_url("assets/js/admin.js", true);
        $this->assertStringContainsString("admin.js", $url_debug);
        $this->assertStringNotContainsString(".min.", $url_debug);
        
        // Test with production mode (minified)
        $url_prod = SecurityHelper::get_asset_url("assets/js/admin.js", false);
        $this->assertStringContainsString("admin.min.js", $url_prod);
        
        // Both should contain assets/js
        $this->assertStringContainsString("assets/js", $url_debug);
        $this->assertStringContainsString("assets/js", $url_prod);
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
        $dangerous_paths = [
            "../../../etc/passwd",
            "admin<script>",
            "path/with/slashes",
            "path?query=1",
        ];

        foreach ($dangerous_paths as $input) {
            $result = SecurityHelper::sanitize_admin_path($input);
            
            $this->assertStringNotContainsString("..", $result, "Path should not contain '..'");
            $this->assertStringNotContainsString("/", $result, "Path should not contain '/'");
            $this->assertStringNotContainsString("<", $result, "Path should not contain '<'");
            $this->assertStringNotContainsString(">", $result, "Path should not contain '>'");
            $this->assertStringNotContainsString("?", $result, "Path should not contain '?'");
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
        $result = SecurityHelper::format_time_duration(30);
        $this->assertStringContainsString("30", $result);
        $this->assertStringContainsString("second", $result);
        
        $result = SecurityHelper::format_time_duration(1);
        $this->assertStringContainsString("1", $result);
        $this->assertStringContainsString("second", $result);
    }

    /**
     * Test format_time_duration formats minutes correctly
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_minutes(): void
    {
        $result = SecurityHelper::format_time_duration(60);
        $this->assertStringContainsString("1", $result);
        $this->assertStringContainsString("minute", $result);
        
        $result = SecurityHelper::format_time_duration(300);
        $this->assertStringContainsString("5", $result);
        $this->assertStringContainsString("minute", $result);
        
        $result = SecurityHelper::format_time_duration(900);
        $this->assertStringContainsString("15", $result);
        $this->assertStringContainsString("minute", $result);
    }

    /**
     * Test format_time_duration formats hours correctly
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_hours(): void
    {
        $result = SecurityHelper::format_time_duration(3600);
        $this->assertStringContainsString("1", $result);
        $this->assertStringContainsString("hour", $result);
        
        $result = SecurityHelper::format_time_duration(7200);
        $this->assertStringContainsString("2", $result);
        $this->assertStringContainsString("hour", $result);
    }

    /**
     * Test format_time_duration formats mixed time
     *
     * @since 1.1.12
     * @return void
     */
    public function test_format_time_duration_formats_mixed_time(): void
    {
        // 1 hour, 5 minutes, 30 seconds = 3930 seconds
        // This should round to hours since it's > 60 minutes
        $duration = 3600 + 300 + 30;
        $result = SecurityHelper::format_time_duration($duration);
        
        $this->assertStringContainsString("hour", $result);
    }

    /**
     * Test verify_nonce with valid nonce
     *
     * @since 1.1.12
     * @return void
     */
    public function test_verify_nonce_with_valid_nonce(): void
    {
        $nonce = \wp_create_nonce("test_action");
        $result = SecurityHelper::verify_nonce($nonce, "test_action", false);
        
        $this->assertTrue($result, "Valid nonce should pass verification");
    }

    /**
     * Test verify_nonce with invalid nonce
     *
     * @since 1.1.12
     * @return void
     */
    public function test_verify_nonce_with_invalid_nonce(): void
    {
        $result = SecurityHelper::verify_nonce("invalid_nonce_12345", "test_action", false);
        
        $this->assertFalse($result, "Invalid nonce should fail verification");
    }

    /**
     * Test check_user_capability with sufficient capability
     *
     * @since 1.1.12
     * @return void
     */
    public function test_check_user_capability_with_sufficient_capability(): void
    {
        // Create admin user
        $admin_id = $this->factory()->user->create(["role" => "administrator"]);
        \wp_set_current_user($admin_id);

        $result = SecurityHelper::check_user_capability("manage_options", false);
        
        $this->assertTrue($result, "Administrator should have manage_options capability");
    }

    /**
     * Test check_user_capability without sufficient capability
     *
     * @since 1.1.12
     * @return void
     */
    public function test_check_user_capability_without_sufficient_capability(): void
    {
        // Create subscriber user (no admin capabilities)
        $subscriber_id = $this->factory()->user->create(["role" => "subscriber"]);
        \wp_set_current_user($subscriber_id);

        $result = SecurityHelper::check_user_capability("manage_options", false);
        
        $this->assertFalse($result, "Subscriber should not have manage_options capability");
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
