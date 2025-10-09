<?php
/**
 * Login Security Unit Tests
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Unit;

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

        // Check that attempt was recorded
        $key = "login_attempts_{md5($ip)}";
        $attempts = get_transient($key);

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

        // Set low max attempts for testing
        update_option("silver_assist_login_attempts", 3);

        // Simulate multiple failed logins
        for ($i = 0; $i < 4; $i++) {
            $this->login_security->handle_failed_login($username);
        }

        // Check lockout is in place
        $lockout_key = "lockout_{md5($ip)}";
        $is_locked = get_transient($lockout_key);

        $this->assertTrue((bool) $is_locked, "IP should be locked out after max attempts");

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
        $user = get_user_by("id", $user_id);

        // Simulate a failed login first
        $this->login_security->handle_failed_login($username);

        // Verify attempt was recorded
        $key = "login_attempts_{md5($ip)}";
        $attempts = get_transient($key);
        $this->assertEquals(1, $attempts);

        // Simulate successful login
        $this->login_security->handle_successful_login($username, $user);

        // Verify attempts were cleared
        $attempts_after = get_transient($key);
        $this->assertFalse($attempts_after, "Login attempts should be cleared after successful login");
    }

    /**
     * Test bot detection and blocking
     */
    public function test_bot_detection_and_blocking(): void
    {
        // Set known bot user agent directly
        $_SERVER["HTTP_USER_AGENT"] = "Nmap Scripting Engine";

        // Capture output to test 404 response
        ob_start();

        // Expect the method to exit, so we'll use output buffering
        try {
            $this->login_security->block_suspicious_bots();
        } catch (\Exception $e) {
            // Expected to exit, so we catch any exceptions
        }

        $output = ob_get_clean();

        // Should contain 404 content
        $this->assertStringContainsString("404 Not Found", $output, "Bot should receive 404 response");
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
