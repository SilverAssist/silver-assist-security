<?php
/**
 * Path Validator Tests
 *
 * Tests for PathValidator utility class including admin path validation,
 * forbidden path detection, and path sanitization.
 *
 * @package SilverAssist\Security\Tests\Core
 * @since 1.1.10
 */

namespace SilverAssist\Security\Tests\Core;

use SilverAssist\Security\Core\PathValidator;
use WP_UnitTestCase;

/**
 * Test PathValidator implementation
 */
class PathValidatorTest extends WP_UnitTestCase
{
    /**
     * Test valid admin paths pass validation
     *
     * @since 1.1.10
     */
    public function test_valid_admin_paths(): void
    {
        $valid_paths = [
            "my-secure-panel",
            "custom-backend-2024",
            "secret-area-xyz",
            "private-console",
            "secure-123"
        ];

        foreach ($valid_paths as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            $this->assertTrue(
                $result["is_valid"],
                "Path '{$path}' should be valid"
            );
            
            $this->assertEmpty(
                $result["error_message"],
                "Valid path '{$path}' should not have error message"
            );
            
            $this->assertNotEmpty(
                $result["sanitized_path"],
                "Valid path '{$path}' should have sanitized version"
            );
        }
    }

    /**
     * Test forbidden admin paths fail validation
     *
     * @since 1.1.10
     */
    public function test_forbidden_admin_paths(): void
    {
        $forbidden_paths = [
            "admin",
            "wp-admin",
            "login",
            "wp-login",
            "dashboard",
            "backend",
            "administrator",
            "root",
            "user",
            "auth",
            "signin",
            "panel",
            "control",
            "manage",
            "system"
        ];

        foreach ($forbidden_paths as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            $this->assertFalse(
                $result["is_valid"],
                "Forbidden path '{$path}' should be invalid"
            );
            
            $this->assertNotEmpty(
                $result["error_message"],
                "Forbidden path '{$path}' should have error message"
            );
            
            $this->assertEquals(
                "forbidden",
                $result["error_type"],
                "Forbidden path '{$path}' should have 'forbidden' error type"
            );
        }
    }

    /**
     * Test empty path validation
     *
     * @since 1.1.10
     */
    public function test_empty_path_validation(): void
    {
        $result = PathValidator::validate_admin_path("");
        
        $this->assertFalse($result["is_valid"], "Empty path should be invalid");
        $this->assertEquals("empty", $result["error_type"], "Error type should be 'empty'");
        $this->assertNotEmpty($result["error_message"], "Should have error message");
    }

    /**
     * Test path length constraints
     *
     * @since 1.1.10
     */
    public function test_path_length_constraints(): void
    {
        // Too short (less than 3 characters)
        $short_result = PathValidator::validate_admin_path("ab");
        $this->assertFalse($short_result["is_valid"], "Path shorter than 3 chars should be invalid");
        $this->assertEquals("too_short", $short_result["error_type"], "Error type should be 'too_short'");

        // Minimum valid length (3 characters)
        $min_result = PathValidator::validate_admin_path("abc");
        $this->assertTrue($min_result["is_valid"], "Path with 3 chars should be valid");

        // Too long (more than 50 characters)
        $long_path = str_repeat("a", 51);
        $long_result = PathValidator::validate_admin_path($long_path);
        $this->assertFalse($long_result["is_valid"], "Path longer than 50 chars should be invalid");
        $this->assertEquals("too_long", $long_result["error_type"], "Error type should be 'too_long'");

        // Maximum valid length (50 characters)
        $max_path = str_repeat("a", 50);
        $max_result = PathValidator::validate_admin_path($max_path);
        $this->assertTrue($max_result["is_valid"], "Path with 50 chars should be valid");
    }

    /**
     * Test path sanitization
     *
     * @since 1.1.10
     */
    public function test_path_sanitization(): void
    {
        $test_cases = [
            ["My Custom Path", "my-custom-path"],
            ["UPPERCASE", "uppercase"],
            ["path_with_underscores", "path_with_underscores"],
            ["  spaces  ", "spaces"],
            ["special@chars#here", "specialcharshere"]
        ];

        foreach ($test_cases as [$input, $expected]) {
            $result = PathValidator::validate_admin_path($input);
            
            if ($result["is_valid"]) {
                $this->assertEquals(
                    $expected,
                    $result["sanitized_path"],
                    "Path '{$input}' should sanitize to '{$expected}'"
                );
            }
        }
    }

    /**
     * Test is_forbidden_path static method
     *
     * @since 1.1.10
     */
    public function test_is_forbidden_path_method(): void
    {
        // Test forbidden paths
        $this->assertTrue(
            PathValidator::is_forbidden_path("admin"),
            "Method should detect 'admin' as forbidden"
        );
        
        $this->assertTrue(
            PathValidator::is_forbidden_path("wp-login"),
            "Method should detect 'wp-login' as forbidden"
        );

        // Test safe paths
        $this->assertFalse(
            PathValidator::is_forbidden_path("my-secure-area"),
            "Method should allow safe custom path"
        );
        
        $this->assertFalse(
            PathValidator::is_forbidden_path("custom-backend-2024"),
            "Method should allow safe custom path with year"
        );
    }

    /**
     * Test validation result structure consistency
     *
     * @since 1.1.10
     */
    public function test_validation_result_structure(): void
    {
        $result = PathValidator::validate_admin_path("test-path");
        
        // Verify all required keys exist
        $this->assertArrayHasKey("is_valid", $result, "Result should have 'is_valid' key");
        $this->assertArrayHasKey("error_message", $result, "Result should have 'error_message' key");
        $this->assertArrayHasKey("error_type", $result, "Result should have 'error_type' key");
        $this->assertArrayHasKey("sanitized_path", $result, "Result should have 'sanitized_path' key");
        
        // Verify data types
        $this->assertIsBool($result["is_valid"], "'is_valid' should be boolean");
        $this->assertIsString($result["error_message"], "'error_message' should be string");
        $this->assertIsString($result["error_type"], "'error_type' should be string");
        $this->assertIsString($result["sanitized_path"], "'sanitized_path' should be string");
    }

    /**
     * Test case-insensitive forbidden path detection
     *
     * @since 1.1.10
     */
    public function test_case_insensitive_forbidden_detection(): void
    {
        $case_variations = [
            "ADMIN",
            "Admin",
            "aDmIn",
            "LOGIN",
            "Login",
            "WP-ADMIN",
            "Wp-Admin"
        ];

        foreach ($case_variations as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            $this->assertFalse(
                $result["is_valid"],
                "Forbidden path '{$path}' should be detected regardless of case"
            );
        }
    }

    /**
     * Test paths containing forbidden keywords as substrings
     *
     * @since 1.1.10
     */
    public function test_paths_containing_forbidden_keywords(): void
    {
        // Paths that contain forbidden keywords but might be considered safe
        $paths_with_keywords = [
            "my-admin-area",      // Contains "admin"
            "super-login-panel",  // Contains "login"
            "dashboard-view"      // Contains "dashboard"
        ];

        foreach ($paths_with_keywords as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            // These should be invalid because they contain forbidden keywords
            $this->assertFalse(
                $result["is_valid"],
                "Path '{$path}' containing forbidden keyword should be invalid"
            );
        }
    }

    /**
     * Test numeric-only paths
     *
     * @since 1.1.10
     */
    public function test_numeric_only_paths(): void
    {
        $numeric_paths = [
            "123",
            "456789",
            "2024"
        ];

        foreach ($numeric_paths as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            // Numeric-only paths should be allowed if they meet length requirements
            if (strlen($path) >= 3 && strlen($path) <= 50) {
                $this->assertTrue(
                    $result["is_valid"],
                    "Numeric path '{$path}' should be valid if length is appropriate"
                );
            }
        }
    }

    /**
     * Test special characters in paths
     *
     * @since 1.1.10
     */
    public function test_special_characters_in_paths(): void
    {
        $special_char_paths = [
            "path-with-dashes",
            "path_with_underscores",
            "path.with.dots",
            "path/with/slashes",
            "path?with=query"
        ];

        foreach ($special_char_paths as $path) {
            $result = PathValidator::validate_admin_path($path);
            
            $this->assertIsArray($result, "Should return validation result array");
            
            if ($result["is_valid"]) {
                // Sanitized path should be safe
                $this->assertNotEmpty(
                    $result["sanitized_path"],
                    "Valid path should have sanitized version"
                );
            }
        }
    }
}
