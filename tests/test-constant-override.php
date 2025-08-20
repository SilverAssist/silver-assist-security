<?php
/**
 * Test script to verify SILVER_ASSIST_HIDE_ADMIN constant functionality
 * 
 * This script can be run independently to test the emergency disable feature
 * 
 * @package SilverAssist\Security\Tests
 * @since 1.1.6
 */

// Simulate WordPress environment for testing
if (!defined('ABSPATH')) {
    define('ABSPATH', '/fake/wordpress/');
}

// Test 1: Define the constant as false (should disable admin hiding)
define('SILVER_ASSIST_HIDE_ADMIN', false);

// Mock WordPress functions for testing
function get_option($option_name, $default = false) {
    // Simulate database returning admin hide as enabled
    if ($option_name === 'silver_assist_admin_hide_enabled') {
        return 1; // Database says it's enabled
    }
    if ($option_name === 'silver_assist_admin_hide_path') {
        return 'custom-admin-path';
    }
    return $default;
}

function sanitize_title($title) {
    return $title;
}

// Load our test classes
require_once __DIR__ . '/../vendor/autoload.php';

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Security\AdminHideSecurity;

echo "=== SILVER ASSIST SECURITY - CONSTANT OVERRIDE TEST ===\n\n";

echo "1. Testing constant override functionality...\n";
echo "   - SILVER_ASSIST_HIDE_ADMIN constant is set to: " . (defined('SILVER_ASSIST_HIDE_ADMIN') ? (SILVER_ASSIST_HIDE_ADMIN ? 'true' : 'false') : 'undefined') . "\n";
echo "   - Database option silver_assist_admin_hide_enabled returns: " . get_option('silver_assist_admin_hide_enabled') . "\n\n";

try {
    // Create AdminHideSecurity instance
    $admin_hide = new AdminHideSecurity();
    
    // Use reflection to check private properties
    $reflection = new ReflectionClass($admin_hide);
    $enabled_property = $reflection->getProperty('admin_hide_enabled');
    $enabled_property->setAccessible(true);
    $admin_hide_enabled = $enabled_property->getValue($admin_hide);
    
    echo "2. AdminHideSecurity initialization result:\n";
    echo "   - admin_hide_enabled property: " . ($admin_hide_enabled ? 'true' : 'false') . "\n";
    
    if (!$admin_hide_enabled) {
        echo "   ✅ SUCCESS: Constant override is working correctly!\n";
        echo "   ✅ Admin hiding is disabled despite database setting being enabled.\n";
    } else {
        echo "   ❌ FAILURE: Constant override is not working!\n";
        echo "   ❌ Admin hiding is still enabled despite constant being false.\n";
    }
    
} catch (Exception $e) {
    echo "   ❌ ERROR: " . $e->getMessage() . "\n";
}

echo "\n3. Test Summary:\n";
echo "   - This test verifies that the SILVER_ASSIST_HIDE_ADMIN constant\n";
echo "     can override database settings for emergency admin access.\n";
echo "   - When set to false, it should disable admin hiding regardless\n";
echo "     of what the database options contain.\n\n";

echo "=== END TEST ===\n";
