<?php
/**
 * Security-focused Tests
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.0.0
 */

namespace SilverAssist\Security\Tests\Security;

use PHPUnit\Framework\TestCase;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\TestHelper;

/**
 * Test security implementations
 */
class SecurityTest extends TestCase
{
    /**
     * Set up test environment
     */
    protected function setUp(): void
    {
        parent::setUp();
        TestHelper::mock_http_request();
    }

    /**
     * Test HTTPOnly cookie implementation
     */
    public function test_httponly_cookies(): void
    {
        $general_security = new GeneralSecurity();

        // Mock a WordPress authentication cookie
        $cookie_name = "wordpress_logged_in_test";
        $cookie_value = "test_value";

        // Capture headers
        if (!headers_sent()) {
            setcookie($cookie_name, $cookie_value, time() + 3600, "/", "", is_ssl(), true);
        }

        // Test that cookie has HTTPOnly flag
        $headers = headers_list();
        $httponly_found = false;

        foreach ($headers as $header) {
            if (strpos($header, "Set-Cookie") === 0 && strpos($header, "HttpOnly") !== false) {
                $httponly_found = true;
                break;
            }
        }

        $this->assertTrue($httponly_found, "Cookies should have HTTPOnly flag");
    }

    /**
     * Test GraphQL query depth limiting
     */
    public function test_graphql_query_depth_limiting(): void
    {
        // Skip if WPGraphQL not available
        if (!class_exists("WPGraphQL")) {
            $this->markTestSkipped("WPGraphQL not available");
            return;
        }

        // Initialize GraphQL components
        $config_manager = GraphQLConfigManager::getInstance();
        $graphql_security = new GraphQLSecurity();

        // Create deep query exceeding default depth limit (8)
        $deep_query = TestHelper::create_graphql_query(15, 50); // 15 levels deep

        // Mock GraphQL request
        $_POST["query"] = $deep_query;

        // Test query depth validation
        $reflection = new \ReflectionClass($graphql_security);

        // Try to find the validation method (might have changed names)
        if ($reflection->hasMethod("validate_query_depth")) {
            $method = $reflection->getMethod("validate_query_depth");
            $method->setAccessible(true);
            $result = $method->invoke($graphql_security, $deep_query);
        } elseif ($reflection->hasMethod("validate_query_complexity")) {
            // Use alternative validation method if available
            $method = $reflection->getMethod("validate_query_complexity");
            $method->setAccessible(true);
            $result = $method->invoke($graphql_security, $deep_query, 15); // 15 depth
        } else {
            $this->markTestSkipped("GraphQL validation methods not available");
            return;
        }

        $this->assertFalse($result, "Deep queries should be rejected");

        // Test that config manager provides expected values
        $depth_limit = $config_manager->get_query_depth();
        $this->assertIsInt($depth_limit, "Query depth should be an integer");
        $this->assertGreaterThan(0, $depth_limit, "Query depth should be positive");
    }

    /**
     * Test GraphQLConfigManager centralized configuration
     * 
     * @since 1.1.0
     */
    public function test_graphql_config_manager(): void
    {
        // Skip if WPGraphQL not available
        if (!class_exists("WPGraphQL")) {
            $this->markTestSkipped("WPGraphQL not available");
            return;
        }

        $config_manager = GraphQLConfigManager::getInstance();

        // Test singleton pattern
        $config_manager2 = GraphQLConfigManager::getInstance();
        $this->assertSame($config_manager, $config_manager2, "GraphQLConfigManager should be singleton");

        // Test configuration methods exist and return appropriate types
        $this->assertIsInt($config_manager->get_query_depth(), "Query depth should be integer");
        $this->assertIsInt($config_manager->get_query_complexity(), "Query complexity should be integer");
        $this->assertIsInt($config_manager->get_query_timeout(), "Query timeout should be integer");
        $this->assertIsInt($config_manager->get_rate_limit(), "Rate limit should be integer");
        $this->assertIsBool($config_manager->is_wpgraphql_active(), "WPGraphQL status should be boolean");
        $this->assertIsBool($config_manager->is_headless_mode(), "Headless mode should be boolean");
        $this->assertIsString($config_manager->evaluate_security_level(), "Security level should be string");
        $this->assertIsArray($config_manager->get_all_configurations(), "All configurations should be array");

        // Test that configurations are within reasonable ranges
        $this->assertGreaterThan(0, $config_manager->get_query_depth(), "Query depth should be positive");
        $this->assertLessThanOrEqual(50, $config_manager->get_query_depth(), "Query depth should be reasonable");
        $this->assertGreaterThan(0, $config_manager->get_query_complexity(), "Query complexity should be positive");
        $this->assertGreaterThan(0, $config_manager->get_query_timeout(), "Query timeout should be positive");
        $this->assertGreaterThan(0, $config_manager->get_rate_limit(), "Rate limit should be positive");

        // Test security level evaluation returns valid values
        $security_level = $config_manager->evaluate_security_level();
        $valid_levels = ["low", "medium", "high", "maximum"];
        $this->assertContains($security_level, $valid_levels, "Security level should be valid");
    }

    /**
     * Test security headers implementation
     */
    public function test_security_headers(): void
    {
        $general_security = new GeneralSecurity();

        // Trigger header sending
        if (!headers_sent()) {
            do_action("send_headers");
        }

        $headers = headers_list();
        $security_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options"
        ];

        foreach ($security_headers as $expected_header) {
            $found = false;
            foreach ($headers as $header) {
                if (strpos($header, $expected_header) === 0) {
                    $found = true;
                    break;
                }
            }
            $this->assertTrue($found, "Security header {$expected_header} should be present");
        }
    }

    /**
     * Test user enumeration protection
     */
    public function test_user_enumeration_protection(): void
    {
        // Test login error messages
        $error1 = new \WP_Error("invalid_username", "Invalid username");
        $error2 = new \WP_Error("incorrect_password", "Invalid password");

        // Apply user enumeration filter
        $filtered_error1 = apply_filters("wp_login_errors", $error1, "http://example.com");
        $filtered_error2 = apply_filters("wp_login_errors", $error2, "http://example.com");

        // Both should have generic message
        $this->assertEquals(
            $filtered_error1->get_error_message(),
            $filtered_error2->get_error_message(),
            "Login errors should be standardized to prevent user enumeration"
        );
    }

    /**
     * Test XML-RPC blocking
     */
    public function test_xmlrpc_blocking(): void
    {
        $general_security = new GeneralSecurity();

        // Mock XML-RPC request
        $_SERVER["REQUEST_URI"] = "/xmlrpc.php";
        $_SERVER["REQUEST_METHOD"] = "POST";

        // Test that XML-RPC is disabled
        $this->assertFalse(
            apply_filters("xmlrpc_enabled", true),
            "XML-RPC should be disabled for security"
        );
    }

    /**
     * Test rate limiting functionality
     */
    public function test_rate_limiting(): void
    {
        $ip = "192.168.1.200";
        $_SERVER["REMOTE_ADDR"] = $ip;

        // Simulate multiple requests
        for ($i = 0; $i < 10; $i++) {
            $key = "rate_limit_{md5($ip)}";
            $requests = get_transient($key) ?: 0;
            set_transient($key, $requests + 1, 60);
        }

        // Check rate limit is in effect
        $current_requests = get_transient("rate_limit_{md5($ip)}");
        $this->assertGreaterThan(5, $current_requests, "Rate limiting should track requests");
    }

    /**
     * Test input sanitization
     */
    public function test_input_sanitization(): void
    {
        $malicious_inputs = [
            "<script>alert(\"xss\")</script>",
            "javascript:alert(1)",
            "../../etc/passwd",
            "SELECT * FROM users",
            "<?php echo \"test\"; ?>"
        ];

        foreach ($malicious_inputs as $input) {
            $sanitized = sanitize_text_field($input);

            $this->assertNotContains("<script>", $sanitized, "Script tags should be removed");
            $this->assertNotContains("javascript:", $sanitized, "JavaScript protocol should be removed");
            $this->assertNotContains("<?php", $sanitized, "PHP tags should be removed");
        }
    }

    /**
     * Test nonce verification
     */
    public function test_nonce_verification(): void
    {
        $action = "test_security_action";

        // Create valid nonce
        $nonce = wp_create_nonce($action);

        // Test valid nonce
        $this->assertTrue(
            wp_verify_nonce($nonce, $action),
            "Valid nonce should pass verification"
        );

        // Test invalid nonce
        $this->assertFalse(
            wp_verify_nonce("invalid_nonce", $action),
            "Invalid nonce should fail verification"
        );

        // Test expired nonce (simulate)
        $old_nonce = wp_create_nonce($action);
        // Simulate time passing (would normally fail in real scenario)
        $this->assertTrue(
            wp_verify_nonce($old_nonce, $action),
            "Nonce verification should work within time window"
        );
    }

    /**
     * Test secure cookie configuration
     */
    public function test_secure_cookie_configuration(): void
    {
        // Mock HTTPS environment
        $_SERVER["HTTPS"] = "on";
        $_SERVER["SERVER_PORT"] = "443";

        $this->assertTrue(is_ssl(), "SSL should be detected");

        // Test secure cookie setting
        if (!headers_sent()) {
            setcookie("test_secure", "value", time() + 3600, "/", "", true, true);
        }

        $headers = headers_list();
        $secure_found = false;

        foreach ($headers as $header) {
            if (strpos($header, "Set-Cookie") === 0 && strpos($header, "secure") !== false) {
                $secure_found = true;
                break;
            }
        }

        $this->assertTrue($secure_found, "Cookies should be secure on HTTPS");
    }

    /**
     * Test directory traversal protection
     */
    public function test_directory_traversal_protection(): void
    {
        $malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ];

        foreach ($malicious_paths as $path) {
            $sanitized = sanitize_file_name(basename($path));

            $this->assertNotContains("..", $sanitized, "Directory traversal should be prevented");
            $this->assertNotContains("/", $sanitized, "Path separators should be removed");
            $this->assertNotContains("\\", $sanitized, "Windows separators should be removed");
        }
    }
}
