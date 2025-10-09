<?php
/**
 * Login Security Unit Tests
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Unit;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\LoginSecurity;
use WP_UnitTestCase;

/**
 * Test LoginSecurity class
 */
class LoginSecurityTest extends WP_UnitTestCase
{
    /**
     * LoginSecurity instance
     *
     * @var LoginSecurity
     */
    private LoginSecurity $login_security;

    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Set default options
        update_option("silver_assist_login_attempts", 5);
        update_option("silver_assist_lockout_duration", 900);
        update_option("silver_assist_session_timeout", 30);
        update_option("silver_assist_password_strength_enforcement", 1);
        update_option("silver_assist_bot_protection", 1);

        // Initialize LoginSecurity
        $this->login_security = new LoginSecurity();
    }

    /**
     * Clean up after tests
     */
    protected function tearDown(): void
    {
        parent::tearDown();
    }

    /**
     * Test constructor initializes properly
     */
    public function test_constructor_initializes_properly(): void
    {
        $this->assertInstanceOf(LoginSecurity::class, $this->login_security);
    }

    /**
     * Test failed login tracking
     */
    public function test_failed_login_tracking(): void
    {
        $username = "testuser";
        $ip = "192.168.1.100";

        // Mock IP address
        $_SERVER["REMOTE_ADDR"] = $ip;

        // Simulate failed login
        $this->login_security->handle_failed_login($username);

        // Use SecurityHelper to generate the same key as LoginSecurity
        $key = SecurityHelper::generate_ip_transient_key("login_attempts", $ip);
        $attempts = \get_transient($key);

        $this->assertEquals(1, $attempts, "Failed login attempt should be recorded");
    }

    /**
     * Test lockout after max attempts
     */
    public function test_lockout_after_max_attempts(): void
    {
        $username = "testuser";
        $password = "wrongpassword";
        $ip = "192.168.1.101";

        // Mock IP address
        $_SERVER["REMOTE_ADDR"] = $ip;

        // Set low max attempts for testing and recreate instance
        \update_option("silver_assist_login_attempts", 3);
        $this->login_security = new LoginSecurity();

        // Simulate multiple failed logins
        for ($i = 0; $i < 4; $i++) {
            $this->login_security->handle_failed_login($username);
        }

        // Check lockout is in place using SecurityHelper
        $lockout_key = SecurityHelper::generate_ip_transient_key("lockout", $ip);
        $is_locked = \get_transient($lockout_key);

        $this->assertTrue((bool) $is_locked, "IP should be locked out after max attempts");

        // Verify the detected IP matches what we set
        $detected_ip = SecurityHelper::get_client_ip();
        $this->assertEquals($ip, $detected_ip, "Detected IP should match test IP");

        // Test authentication check
        $result = $this->login_security->check_login_lockout(null, $username, $password);

        $this->assertInstanceOf("WP_Error", $result, "Should return WP_Error when locked out");
        $this->assertEquals("login_locked", $result->get_error_code(), "Error code should be login_locked");
    }

    /**
     * Test successful login clears attempts
     */
    public function test_successful_login_clears_attempts(): void
    {
        $username = "testuser";
        $ip = "192.168.1.102";

        // Mock IP address
        $_SERVER["REMOTE_ADDR"] = $ip;

        // Create a test user using WordPress factory
        $user_id = $this->factory()->user->create(["user_login" => $username]);
        $user = \get_user_by("id", $user_id);

        // Simulate a failed login first
        $this->login_security->handle_failed_login($username);

        // Verify attempt was recorded using SecurityHelper
        $key = SecurityHelper::generate_ip_transient_key("login_attempts", $ip);
        $attempts = \get_transient($key);
        $this->assertEquals(1, $attempts);

        // Simulate successful login
        $this->login_security->handle_successful_login($username, $user);

        // Verify attempts were cleared
        $attempts_after = \get_transient($key);
        $this->assertFalse($attempts_after, "Login attempts should be cleared after successful login");
    }

    /**
     * Test bot detection using SecurityHelper
     */
    public function test_bot_detection_and_blocking(): void
    {
        // Set up browser-like headers to avoid false positives
        $_SERVER["HTTP_ACCEPT"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        $_SERVER["HTTP_ACCEPT_LANGUAGE"] = "en-US,en;q=0.9";
        $_SERVER["HTTP_ACCEPT_ENCODING"] = "gzip, deflate, br";

        // Test various bot user agents
        $bot_user_agents = [
            "Nmap Scripting Engine",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/7.64.1",
            "python-requests/2.25.1",
            "Nikto",
            "WPScan v3.8.0"
        ];

        foreach ($bot_user_agents as $user_agent) {
            $_SERVER["HTTP_USER_AGENT"] = $user_agent;
            $this->assertTrue(
                SecurityHelper::is_bot_request(),
                "Should detect bot: {$user_agent}"
            );
        }

        // Test legitimate user agent with full browser signature
        $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
        $this->assertFalse(
            SecurityHelper::is_bot_request(),
            "Should not block legitimate browser"
        );
    }

    /**
     * Test password strength validation
     */
    public function test_password_strength_validation(): void
    {
        $reflection = new \ReflectionClass($this->login_security);
        $method = $reflection->getMethod("is_strong_password");
        $method->setAccessible(true);

        // Test weak passwords
        $this->assertFalse($method->invoke($this->login_security, "weak"), "Short password should be rejected");
        $this->assertFalse($method->invoke($this->login_security, "alllowercase"), "No uppercase should be rejected");
        $this->assertFalse($method->invoke($this->login_security, "ALLUPPERCASE"), "No lowercase should be rejected");
        $this->assertFalse($method->invoke($this->login_security, "NoNumbers!"), "No numbers should be rejected");
        $this->assertFalse($method->invoke($this->login_security, "NoSpecial123"), "No special chars should be rejected");

        // Test strong password
        $this->assertTrue($method->invoke($this->login_security, "Strong123!"), "Strong password should be accepted");
    }

    /**
     * Test IP address detection
     */
    public function test_ip_address_detection(): void
    {
        $reflection = new \ReflectionClass($this->login_security);
        $method = $reflection->getMethod("get_client_ip");
        $method->setAccessible(true);

        // Test standard REMOTE_ADDR
        $_SERVER["REMOTE_ADDR"] = "192.168.1.1";
        $this->assertEquals("192.168.1.1", $method->invoke($this->login_security));

        // Test CloudFlare header
        $_SERVER["HTTP_CF_CONNECTING_IP"] = "203.0.113.1";
        $this->assertEquals("203.0.113.1", $method->invoke($this->login_security));

        // Test X-Forwarded-For
        unset($_SERVER["HTTP_CF_CONNECTING_IP"]);
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.2, 192.168.1.1";
        $this->assertEquals("203.0.113.2", $method->invoke($this->login_security));
    }

    /**
     * Test session timeout functionality
     */
    public function test_session_timeout(): void
    {
        // Create logged in user using WordPress factory
        $user_id = $this->factory()->user->create();
        wp_set_current_user($user_id);

        // Set short session timeout for testing
        update_option("silver_assist_session_timeout", 1); // 1 minute

        // Set old last activity
        update_user_meta($user_id, "last_activity", time() - 120); // 2 minutes ago

        // Capture redirect attempt
        ob_start();

        try {
            $this->login_security->setup_session_timeout();
        } catch (\Exception $e) {
            // Expected to redirect and exit
        }

        ob_get_clean();

        // Clean up
        wp_set_current_user(0);
    }
}
