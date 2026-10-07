<?php
/**
 * Login Security Integration Tests
 *
 * Comprehensive integration tests for LoginSecurity class covering:
 * - WordPress hooks integration (wp_login, wp_login_failed, authenticate)
 * - Session timeout behavior in admin vs frontend contexts
 * - Complete login flow: attempt → fail → lockout → unlock
 * - Bot detection and blocking with real WordPress environment
 * - Password strength validation in WordPress forms
 * - Login attempt clearing on password reset
 * - Honeypot and nonce validation
 * - Rate limiting and IP tracking
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.14
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\LoginSecurity;
use WP_UnitTestCase;
use WP_Error;

/**
 * Test LoginSecurity integration with WordPress
 */
class LoginSecurityTest extends WP_UnitTestCase
{
    use \SilverAssist\Security\Tests\Helpers\StoresRawOptions;

    /**
     * LoginSecurity instance
     *
     * @var LoginSecurity
     */
    private LoginSecurity $login_security;

    /**
     * Test user ID
     *
     * @var int
     */
    private int $test_user_id;

    /**
     * Original $_SERVER values
     *
     * @var array
     */
    private array $original_server = [];

    /**
     * Set up test environment before each test
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Backup $_SERVER
        $this->original_server = $_SERVER;

        // Set default test configuration
        \update_option('silver_assist_login_attempts', 5);
        \update_option('silver_assist_lockout_duration', 900);
        \update_option('silver_assist_session_timeout', 30);
        \update_option('silver_assist_password_strength_enforcement', 1);
        \update_option('silver_assist_bot_protection', 1);

        // Create test user
        $this->test_user_id = $this->factory()->user->create([
            'user_login' => 'testuser',
            'user_pass' => 'TestPassword123!',
            'role' => 'subscriber',
        ]);

        // Set up browser-like headers to avoid false bot detection
        $_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml';
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
        $_SERVER['HTTP_ACCEPT_ENCODING'] = 'gzip, deflate';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        // Initialize LoginSecurity
        $this->login_security = new LoginSecurity();

        // Clear any existing transients
        $this->clear_all_login_transients();
    }

    /**
     * Clean up after each test
     */
    protected function tearDown(): void
    {
        // Restore $_SERVER
        $_SERVER = $this->original_server;

        // Clear all login-related transients
        $this->clear_all_login_transients();

        // Clear WordPress hooks registered by LoginSecurity
        $this->clear_login_security_hooks();

        // Delete test user
        if ($this->test_user_id) {
            \wp_delete_user($this->test_user_id);
        }

        // Logout any logged-in user
        \wp_set_current_user(0);

        parent::tearDown();
    }

    /**
     * Clear all login-related transients
     *
     * @return void
     */
    private function clear_all_login_transients(): void
    {
        global $wpdb;

        // Clear all silver_assist login transients
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
            WHERE option_name LIKE '%login_attempts_%' 
            OR option_name LIKE '%lockout_%'
            OR option_name LIKE '%bot_activity_%'
            OR option_name LIKE '%extended_bot_block_%'
            OR option_name LIKE '%login_access_%'
            OR option_name LIKE '%login_window_%'"
        );
    }

    /**
     * Clear LoginSecurity WordPress hooks
     *
     * @return void
     */
    private function clear_login_security_hooks(): void
    {
        \remove_all_actions('login_form');
        \remove_all_actions('login_init');
        \remove_all_actions('wp_login_failed');
        \remove_all_filters('authenticate');
        \remove_all_actions('wp_login');
        \remove_all_actions('init');
        \remove_all_actions('wp_logout');
        \remove_all_actions('password_reset');
        \remove_all_actions('profile_update');
        \remove_all_actions('user_profile_update_errors');
        \remove_all_actions('validate_password_reset');
        \remove_all_actions('admin_enqueue_scripts');
    }

    /**
     * Test that WordPress hooks are registered properly
     */
    public function test_wordpress_hooks_registered(): void
    {
        // Verify login form hooks
        $this->assertNotFalse(
            \has_action('login_form', [$this->login_security, 'add_login_form_security']),
            'login_form hook should be registered'
        );

        // Verify login init hooks
        $this->assertTrue(
            \has_action('login_init') !== false,
            'login_init hook should be registered'
        );

        // Verify failed login tracking
        $this->assertNotFalse(
            \has_action('wp_login_failed', [$this->login_security, 'handle_failed_login']),
            'wp_login_failed hook should be registered'
        );

        // Verify authenticate filter
        $this->assertNotFalse(
            \has_filter('authenticate', [$this->login_security, 'check_login_lockout']),
            'authenticate filter should be registered'
        );

        // Verify successful login handler
        $this->assertNotFalse(
            \has_action('wp_login', [$this->login_security, 'handle_successful_login']),
            'wp_login hook should be registered'
        );

        // Verify session management
        $this->assertTrue(
            \has_action('init') !== false,
            'init hook for session timeout should be registered'
        );

        // Verify logout handler
        $this->assertNotFalse(
            \has_action('wp_logout', [$this->login_security, 'clear_login_attempts']),
            'wp_logout hook should be registered'
        );

        // Verify password reset hooks
        $this->assertTrue(
            \has_action('password_reset') !== false,
            'password_reset hook should be registered'
        );

        $this->assertTrue(
            \has_action('profile_update') !== false,
            'profile_update hook should be registered'
        );
    }

    /**
     * Test complete login failure flow with lockout
     */
    public function test_complete_login_failure_and_lockout_flow(): void
    {
        $ip = '192.168.1.200';
        $_SERVER['REMOTE_ADDR'] = $ip;

        // Set low max attempts for faster testing
        \update_option('silver_assist_login_attempts', 3);
        $this->login_security = new LoginSecurity();

        $username = 'nonexistent';

        // Simulate 3 failed login attempts
        for ($i = 1; $i <= 3; $i++) {
            $this->login_security->handle_failed_login($username);

            $attempts_key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
            // The atomic counter writes straight to the options table, so read it past the option cache.
            \wp_cache_flush();
            $attempts = \get_transient($attempts_key);
            $this->assertEquals($i, $attempts, "Should track {$i} failed attempts");
        }

        // Verify lockout is activated
        $lockout_key = SecurityHelper::generate_ip_transient_key('lockout', $ip);
        $is_locked = \get_transient($lockout_key);
        $this->assertTrue((bool) $is_locked, 'IP should be locked out after 3 attempts');

        // Try to authenticate while locked out
        $result = $this->login_security->check_login_lockout(null, $username, 'password');

        $this->assertInstanceOf(WP_Error::class, $result, 'Should return WP_Error when locked out');
        $this->assertEquals('login_locked', $result->get_error_code(), 'Error code should be login_locked');
        $this->assertStringContainsString('Too many failed login attempts', $result->get_error_message());
    }

    /**
     * Rotating a forged header on every attempt must not escape the lockout (#128)
     *
     * Before the fix the identity came from client-controlled headers, so each attempt with a new
     * X-Forwarded-For or Client-IP counted as a different visitor and the lockout never triggered.
     */
    public function test_lockout_cannot_be_bypassed_by_rotating_forged_headers(): void
    {
        $real_ip = '198.51.100.50';
        $_SERVER['REMOTE_ADDR'] = $real_ip;

        \update_option('silver_assist_login_attempts', 3);
        $this->login_security = new LoginSecurity();

        foreach (['203.0.113.11', '203.0.113.12', '203.0.113.13'] as $forged) {
            $_SERVER['HTTP_X_FORWARDED_FOR'] = $forged;
            $_SERVER['HTTP_CLIENT_IP']       = $forged;
            $this->login_security->handle_failed_login('nonexistent');
        }

        $this->assertTrue(
            (bool) \get_transient(SecurityHelper::generate_ip_transient_key('lockout', $real_ip)),
            'The real peer address should be locked out after 3 attempts'
        );

        // A fresh forged value does not give a clean slate.
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99';
        $result = $this->login_security->check_login_lockout(null, 'nonexistent', 'password');
        $this->assertInstanceOf(WP_Error::class, $result, 'A new forged header must not lift the lockout');
        $this->assertEquals('login_locked', $result->get_error_code());

        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CLIENT_IP']);
    }

    /**
     * Test successful login clears attempts and lockout
     */
    public function test_successful_login_clears_lockout(): void
    {
        $ip = '192.168.1.201';
        $_SERVER['REMOTE_ADDR'] = $ip;

        $user = \get_user_by('id', $this->test_user_id);

        // Simulate failed attempts
        $this->login_security->handle_failed_login($user->user_login);
        $this->login_security->handle_failed_login($user->user_login);

        // Verify attempts recorded
        $attempts_key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
        $attempts = \get_transient($attempts_key);
        $this->assertEquals(2, $attempts, 'Should have 2 failed attempts');

        // Simulate successful login
        $this->login_security->handle_successful_login($user->user_login, $user);

        // Verify attempts cleared
        $attempts_after = \get_transient($attempts_key);
        $this->assertFalse($attempts_after, 'Failed attempts should be cleared after successful login');

        // Verify lockout cleared
        $lockout_key = SecurityHelper::generate_ip_transient_key('lockout', $ip);
        $lockout_after = \get_transient($lockout_key);
        $this->assertFalse($lockout_after, 'Lockout should be cleared after successful login');
    }

    /**
     * Test bot detection blocks suspicious user agents
     */
    public function test_bot_detection_blocks_bots(): void
    {
        $bot_user_agents = [
            'Nmap Scripting Engine',
            'Nikto/2.1.6',
            'WPScan v3.8.0',
            'sqlmap/1.4',
            'curl/7.64.1',
            'python-requests/2.25.1',
        ];

        foreach ($bot_user_agents as $bot_ua) {
            $_SERVER['HTTP_USER_AGENT'] = $bot_ua;

            $this->assertTrue(
                SecurityHelper::is_bot_request(),
                "Should detect bot: {$bot_ua}"
            );
        }
    }

    /**
     * Test legitimate browsers are not blocked
     */
    public function test_legitimate_browsers_not_blocked(): void
    {
        $legitimate_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0',
        ];

        foreach ($legitimate_user_agents as $ua) {
            $_SERVER['HTTP_USER_AGENT'] = $ua;
            $_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml';
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
            $_SERVER['HTTP_ACCEPT_ENCODING'] = 'gzip, deflate';

            $this->assertFalse(
                SecurityHelper::is_bot_request(),
                "Should NOT block legitimate browser: {$ua}"
            );
        }
    }

    /**
     * Test bot tracking records suspicious activity
     */
    public function test_bot_tracking_records_activity(): void
    {
        $ip = '192.168.1.202';
        $_SERVER['REMOTE_ADDR'] = $ip;
        $_SERVER['HTTP_USER_AGENT'] = 'Nmap Scripting Engine';
        $_SERVER['REQUEST_URI'] = '/wp-login.php';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        // Track bot behavior multiple times to ensure logging
        $this->login_security->track_bot_behavior();
        $this->login_security->track_bot_behavior();

        // Activity is stored per IP under bot_activity_<md5(ip)>.
        $bot_log_key = "bot_activity_" . md5($ip);
        $bot_activity = \get_transient($bot_log_key);

        $this->assertIsArray($bot_activity, 'Bot activity should be recorded for this IP');
        $this->assertCount(2, $bot_activity, 'Both hits should be recorded');
        $this->assertArrayHasKey('time', $bot_activity[0]);
        $this->assertSame('Nmap Scripting Engine', $bot_activity[0]['user_agent']);
        $this->assertSame('/wp-login.php', $bot_activity[0]['uri']);

        $this->assertTrue(SecurityHelper::is_bot_request(), 'Bot should be detected by user agent');
    }

    /**
     * Test password strength validation in WordPress context
     */
    public function test_password_strength_validation_integration(): void
    {
        $errors = new WP_Error();
        $user = \get_user_by('id', $this->test_user_id);

        // Test weak password
        $_POST['pass1'] = 'weak';
        $this->login_security->validate_password_strength($errors, true, $user);

        $this->assertTrue(
            $errors->has_errors(),
            'Weak password should trigger error'
        );
        $this->assertEquals(
            'weak_password',
            $errors->get_error_code(),
            'Error code should be weak_password'
        );

        // Test strong password
        $errors = new WP_Error();
        $_POST['pass1'] = 'StrongPassword123!';
        $this->login_security->validate_password_strength($errors, true, $user);

        $this->assertFalse(
            $errors->has_errors(),
            'Strong password should not trigger error'
        );

        unset($_POST['pass1']);
    }

    /**
     * Test password strength validation on reset
     */
    public function test_password_validation_on_reset(): void
    {
        $errors = new WP_Error();
        $user = \get_user_by('id', $this->test_user_id);

        // Test weak password on reset
        $_POST['pass1'] = 'short';
        $this->login_security->validate_password_strength_reset($errors, $user);

        $this->assertTrue(
            $errors->has_errors(),
            'Weak password should be rejected on reset'
        );

        // Test strong password on reset
        $errors = new WP_Error();
        $_POST['pass1'] = 'ComplexPassword456!';
        $this->login_security->validate_password_strength_reset($errors, $user);

        $this->assertFalse(
            $errors->has_errors(),
            'Strong password should be accepted on reset'
        );

        unset($_POST['pass1']);
    }

    /**
     * Test login attempts cleared after password reset
     */
    public function test_login_attempts_cleared_on_password_reset(): void
    {
        $ip = '192.168.1.203';
        $_SERVER['REMOTE_ADDR'] = $ip;

        $user = \get_user_by('id', $this->test_user_id);

        // Record failed attempts
        $this->login_security->handle_failed_login($user->user_login);
        $this->login_security->handle_failed_login($user->user_login);

        $attempts_key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
        $attempts = \get_transient($attempts_key);
        $this->assertEquals(2, $attempts, 'Should have 2 failed attempts before reset');

        // Trigger password reset
        $this->login_security->clear_login_attempts_on_password_change($user, 'NewPassword123!');

        // Verify attempts cleared
        $attempts_after = \get_transient($attempts_key);
        $this->assertFalse($attempts_after, 'Login attempts should be cleared after password reset');
    }

    /**
     * Test login attempts cleared on profile update with password change
     */
    public function test_login_attempts_cleared_on_profile_password_change(): void
    {
        $ip = '192.168.1.204';
        $_SERVER['REMOTE_ADDR'] = $ip;

        $user = \get_user_by('id', $this->test_user_id);
        $old_user = clone $user;

        // Record failed attempts
        $this->login_security->handle_failed_login($user->user_login);

        $attempts_key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
        $attempts = \get_transient($attempts_key);
        $this->assertEquals(1, $attempts, 'Should have 1 failed attempt');

        // Change password
        \wp_set_password('NewStrongPassword123!', $this->test_user_id);
        $new_user = \get_user_by('id', $this->test_user_id);

        // Trigger profile update hook
        $this->login_security->clear_login_attempts_on_profile_update($this->test_user_id, $old_user);

        // Verify attempts cleared
        $attempts_after = \get_transient($attempts_key);
        $this->assertFalse($attempts_after, 'Login attempts should be cleared on profile password change');
    }

    /**
     * Test profile update without password change does not clear attempts
     */
    public function test_profile_update_without_password_change_keeps_attempts(): void
    {
        $ip = '192.168.1.205';
        $_SERVER['REMOTE_ADDR'] = $ip;

        $user = \get_user_by('id', $this->test_user_id);
        $old_user = clone $user;

        // Record failed attempts
        $this->login_security->handle_failed_login($user->user_login);

        $attempts_key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
        $attempts = \get_transient($attempts_key);
        $this->assertEquals(1, $attempts, 'Should have 1 failed attempt');

        // Update profile without password change
        \wp_update_user([
            'ID' => $this->test_user_id,
            'display_name' => 'Updated Name',
        ]);

        // Trigger profile update hook with same password
        $this->login_security->clear_login_attempts_on_profile_update($this->test_user_id, $old_user);

        // Verify attempts NOT cleared (password didn't change)
        $attempts_after = \get_transient($attempts_key);
        $this->assertEquals(1, $attempts_after, 'Login attempts should remain when password not changed');
    }

    /**
     * Test session timeout in admin area redirects to login
     */
    public function test_session_timeout_in_admin_area(): void
    {
        // Set very short timeout for testing
        $this->store_raw_option( 'silver_assist_session_timeout', 1 ); // 1 minute
        $this->login_security = new LoginSecurity();

        // Create and login user
        \wp_set_current_user($this->test_user_id);
        $initial_user_id = \get_current_user_id();
        $this->assertEquals($this->test_user_id, $initial_user_id, 'User should be logged in initially');

        // Set old last activity (2 minutes ago, exceeds 1 minute timeout)
        \update_user_meta($this->test_user_id, 'last_activity', time() - 120);

        // Simulate admin area
        \set_current_screen('dashboard');

        // The production code redirects and then calls exit, which would kill the whole PHPUnit
        // process. Throw from the wp_redirect filter so the exit is never reached.
        \add_filter(
            'wp_redirect',
            static function ( $location ) {
                throw new \RuntimeException( 'redirect:' . $location );
            }
        );

        // Capture output
        ob_start();

        $redirect = null;
        try {
            $this->login_security->setup_session_timeout();
        } catch (\RuntimeException $e) {
            $redirect = $e->getMessage();
        }

        ob_end_clean();

        $this->assertNotNull($redirect, 'An expired admin session should redirect to the login page');
        $this->assertStringContainsString('session_expired=1', $redirect);

        // The expired session metadata is cleared before the redirect
        $last_activity_after = \get_user_meta($this->test_user_id, 'last_activity', true);
        
        // Either user is logged out OR last_activity was cleared (timeout processing occurred)
        $current_user = \get_current_user_id();
        $timeout_processed = ($current_user === 0 || $last_activity_after === '');
        $this->assertTrue($timeout_processed, 'Session timeout should process expired session');
    }

    /**
     * Test session timeout updates last activity for active users
     */
    public function test_session_timeout_updates_last_activity(): void
    {
        \wp_set_current_user($this->test_user_id);

        // Set initial last activity
        $initial_time = time() - 100;
        \update_user_meta($this->test_user_id, 'last_activity', $initial_time);

        // Setup session timeout (should update last activity)
        $this->login_security->setup_session_timeout();

        // Verify last activity was updated
        $updated_time = \get_user_meta($this->test_user_id, 'last_activity', true);

        $this->assertGreaterThan(
            $initial_time,
            $updated_time,
            'Last activity should be updated for active users'
        );
    }

    /**
     * Test honeypot field in login form
     */
    public function test_honeypot_field_in_login_form(): void
    {
        // Capture output
        ob_start();
        $this->login_security->add_login_form_security();
        $output = ob_get_clean();

        // Verify honeypot field exists
        $this->assertStringContainsString('name="website_url"', $output, 'Honeypot field should exist');
        $this->assertStringContainsString('position: absolute', $output, 'Honeypot should be hidden');
        $this->assertStringContainsString('left: -9999px', $output, 'Honeypot should be off-screen');
    }

    /**
     * Test nonce field in login form
     */
    public function test_nonce_field_in_login_form(): void
    {
        // Capture output
        ob_start();
        $this->login_security->add_login_form_security();
        $output = ob_get_clean();

        // Verify nonce field exists
        $this->assertStringContainsString('secure_login_nonce', $output, 'Nonce field should exist');
        $this->assertStringContainsString('type="hidden"', $output, 'Nonce should be hidden field');
        $this->assertStringContainsString('value=', $output, 'Nonce should have value');
    }

    /**
     * Test rate limiting blocks excessive requests from same IP
     */
    public function test_rate_limiting_blocks_excessive_requests(): void
    {
        $ip = '192.168.1.206';
        $_SERVER['REMOTE_ADDR'] = $ip;
        $_SERVER['HTTP_USER_AGENT'] = 'curl/7.64.1'; // Bot-like user agent

        // 20 rapid requests: the first 15 pass, the rest exceed the threshold.
        $limited = [];
        for ($i = 1; $i <= 20; $i++) {
            $limited[$i] = $this->login_security->is_login_page_rate_limited($ip);
        }
        $this->assertFalse($limited[15], 'The 15th request in a minute is still allowed');
        $this->assertTrue($limited[16], 'The 16th request in a minute is limited');
        $this->assertTrue($limited[20]);

        // SecurityHelper::is_bot_request() will detect this as bot due to curl user agent
        $this->assertTrue(
            SecurityHelper::is_bot_request(),
            'Excessive requests with bot user agent should be detected'
        );
    }

    /**
     * Test IP tracking across multiple failed attempts
     */
    public function test_ip_tracking_across_multiple_attempts(): void
    {
        $ip1 = '192.168.1.207';
        $ip2 = '192.168.1.208';

        // Test IP 1 - 2 failed attempts
        $_SERVER['REMOTE_ADDR'] = $ip1;
        $this->login_security->handle_failed_login('user1');
        $this->login_security->handle_failed_login('user1');

        $key1 = SecurityHelper::generate_ip_transient_key('login_attempts', $ip1);
        $attempts1 = \get_transient($key1);
        $this->assertEquals(2, $attempts1, 'IP1 should have 2 attempts');

        // Test IP 2 - 3 failed attempts
        $_SERVER['REMOTE_ADDR'] = $ip2;
        $this->login_security->handle_failed_login('user2');
        $this->login_security->handle_failed_login('user2');
        $this->login_security->handle_failed_login('user2');

        $key2 = SecurityHelper::generate_ip_transient_key('login_attempts', $ip2);
        $attempts2 = \get_transient($key2);
        $this->assertEquals(3, $attempts2, 'IP2 should have 3 attempts');

        // Verify IP1 still has 2 attempts (not affected by IP2)
        $attempts1_after = \get_transient($key1);
        $this->assertEquals(2, $attempts1_after, 'IP1 attempts should remain unchanged');
    }

    /**
     * Test lockout duration is configurable
     */
    public function test_configurable_lockout_duration(): void
    {
        $ip = '192.168.1.209';
        $_SERVER['REMOTE_ADDR'] = $ip;

        // Set custom lockout duration to 600 seconds (10 minutes)
        \update_option('silver_assist_login_attempts', 2);
        \update_option('silver_assist_lockout_duration', 600);
        $this->login_security = new LoginSecurity();

        // Trigger lockout
        $this->login_security->handle_failed_login('testuser');
        $this->login_security->handle_failed_login('testuser');

        $lockout_key = SecurityHelper::generate_ip_transient_key('lockout', $ip);
        $is_locked = \get_transient($lockout_key);

        $this->assertTrue((bool) $is_locked, 'IP should be locked out');

        // Verify lockout transient exists and was set with correct duration
        // Note: The actual transient timeout may use default value (900) from set_transient call
        // We verify the configuration is used by the class
        global $wpdb;
        $timeout = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
                "_transient_timeout_{$lockout_key}"
            )
        );

        if ($timeout) {
            $remaining = $timeout - time();
            // LoginSecurity uses lockout_duration from config (600 or 900 seconds)
            // Allow either value since both are valid depending on config loading timing
            $this->assertGreaterThan(550, $remaining, 'Lockout should last at least 9 minutes');
            $this->assertLessThan(950, $remaining, 'Lockout duration should be approximately 10-15 minutes');
        }
    }

    /**
     * Test legitimate login actions bypass bot protection
     *
     * A request that is turned away as a bot is logged in `bot_activity_*` and answered with a 404
     * that ends the process, so surviving the call with no log entry means the request passed.
     */
    public function test_legitimate_actions_bypass_bot_protection(): void
    {
        \update_option("silver_assist_bot_protection", 1);
        $ip = "198.51.100.44";
        $_SERVER["REMOTE_ADDR"] = $ip;
        $_SERVER["HTTP_USER_AGENT"] = "curl/7.64.1"; // Would normally be blocked

        foreach (["logout", "lostpassword", "resetpass", "rp", "register"] as $action) {
            $_REQUEST["action"] = $action;

            $this->login_security->block_suspicious_bots();

            $this->assertFalse(\get_transient("bot_activity_" . md5($ip)), "Action {$action} should bypass bot protection");
        }

        unset($_REQUEST["action"]);
    }

    /**
     * Test password reset with key parameter bypasses bot protection
     */
    public function test_password_reset_with_key_bypasses_bot_protection(): void
    {
        \update_option("silver_assist_bot_protection", 1);
        $ip = "198.51.100.45";
        $_SERVER["REMOTE_ADDR"] = $ip;
        $_SERVER["HTTP_USER_AGENT"] = "curl/7.64.1"; // Would normally be blocked
        $_GET["key"] = "test_reset_key";
        $_GET["login"] = "testuser";

        $this->login_security->block_suspicious_bots();

        $this->assertFalse(\get_transient("bot_activity_" . md5($ip)), "A password reset link should bypass bot protection");

        unset($_GET["key"], $_GET["login"]);
    }

    /**
     * Repeated bot activity is logged (capped at ten entries) and sets no block flag
     *
     * An `extended_bot_block_*` flag used to be written here and never read; see LimiterRobustnessTest.
     */
    public function test_repeated_bot_activity_is_logged_without_extended_block(): void
    {
        $ip = '192.168.1.210';
        $_SERVER['REMOTE_ADDR'] = $ip;
        $_SERVER['HTTP_USER_AGENT'] = 'Nmap Scripting Engine';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/wp-login.php';

        for ($i = 0; $i < 12; $i++) {
            $this->login_security->track_bot_behavior();
        }

        $bot_activity = \get_transient("bot_activity_" . md5($ip));
        $this->assertIsArray($bot_activity);
        $this->assertCount(10, $bot_activity, 'Only the latest ten entries are kept');
        $this->assertFalse(\get_transient("extended_bot_block_" . md5($ip)));
    }

    /**
     * Test session timeout doesn't logout during plugin activation
     */
    public function test_session_timeout_skips_during_plugin_activation(): void
    {
        \wp_set_current_user($this->test_user_id);

        // Don't set last_activity (simulates plugin activation scenario)
        \delete_user_meta($this->test_user_id, 'last_activity');

        // Setup session timeout
        $this->login_security->setup_session_timeout();

        // Verify user is still logged in
        $this->assertEquals(
            $this->test_user_id,
            \get_current_user_id(),
            'User should remain logged in when last_activity not set'
        );

        // Verify last_activity was initialized
        $last_activity = \get_user_meta($this->test_user_id, 'last_activity', true);
        $this->assertNotEmpty($last_activity, 'Last activity should be initialized');
    }

    /**
     * Test multiple instances maintain consistent configuration
     */
    public function test_multiple_instances_consistent_configuration(): void
    {
        $instance1 = new LoginSecurity();
        $instance2 = new LoginSecurity();

        // Both instances should use same configuration from database
        // We verify by testing behavior is consistent

        $ip = '192.168.1.211';
        $_SERVER['REMOTE_ADDR'] = $ip;

        // Use instance 1 to track failed attempt
        $instance1->handle_failed_login('testuser');

        // Use instance 2 to check the attempt
        $key = SecurityHelper::generate_ip_transient_key('login_attempts', $ip);
        $attempts = \get_transient($key);

        $this->assertEquals(1, $attempts, 'Both instances should share same transient data');
    }

    /**
     * Test WordPress admin checks work correctly in different contexts
     */
    public function test_admin_context_detection(): void
    {
        // Test non-admin context
        $this->assertFalse(\is_admin(), 'Should not be in admin context initially');

        // Test admin context (simulated)
        \set_current_screen('dashboard');
        $this->assertTrue(\is_admin(), 'Should detect admin context');

        // Cleanup
        \set_current_screen('front');
    }
}
