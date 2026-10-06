<?php
/**
 * Login Lockout Behavior Tests
 *
 * What visitors and users experience from the login protection: how the per-IP
 * thresholds behave when several people share one IP, whether a lockout really
 * ends and the strength rules. These tests assert the outcome,
 * not that a hook is registered (#131, part of #124).
 *
 * Documented thresholds (defaults): 5 failed logins lock an IP for 15 minutes;
 * more than 15 login-page requests per minute from one IP return 404.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\AdminHideSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\LoginSecurity;
use WP_Error;
use WP_UnitTestCase;

/**
 * Behavior of login lockout, rate limiting and login error messages
 */
class LoginLockoutBehaviorTest extends WP_UnitTestCase
{
    /**
     * Original $_SERVER
     *
     * @var array<string, mixed>
     */
    private array $original_server = [];

    /**
     * Original $_POST
     *
     * @var array<string, mixed>
     */
    private array $original_post = [];

    /**
     * Prepare configuration and clean state
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->original_server = $_SERVER;
        $this->original_post   = $_POST;

        \update_option("silver_assist_login_attempts", 5);
        \update_option("silver_assist_lockout_duration", 900);
        \update_option("silver_assist_bot_protection", 1);
        \update_option("silver_assist_password_strength_enforcement", 1);

        $_SERVER["REMOTE_ADDR"] = "203.0.113.10";
        $_SERVER["REQUEST_METHOD"] = "POST";

        $this->clear_transients();

    }

    /**
     * Restore state
     *
     * @return void
     */
    protected function tearDown(): void
    {
        $_SERVER = $this->original_server;
        $_POST   = $this->original_post;
        $this->clear_transients();
        parent::tearDown();
    }

    /**
     * Remove every login related transient
     *
     * @return void
     */
    private function clear_transients(): void
    {
        global $wpdb;

        $wpdb->query(
            "DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '%login_attempts_%'
            OR option_name LIKE '%lockout_%'
            OR option_name LIKE '%login_access_%'
            OR option_name LIKE '%bot_activity_%'"
        );
    }

    /**
     * Seconds left on an IP's lockout, read from the transient timeout
     *
     * @param string $ip Client IP.
     * @return int
     */
    private function lockout_seconds_left(string $ip): int
    {
        $key     = SecurityHelper::generate_ip_transient_key("lockout", $ip);
        $timeout = (int) \get_option("_transient_timeout_{$key}");

        return max(0, $timeout - time());
    }

    /**
     * Fail five logins as one IP, going through the same hooks core fires
     *
     * @param LoginSecurity $login Login security instance.
     * @param string        $ip    Client IP.
     * @return void
     */
    private function lock_out(LoginSecurity $login, string $ip): void
    {
        $_SERVER["REMOTE_ADDR"] = $ip;
        for ($i = 0; $i < 5; $i++) {
            $login->handle_failed_login("someone");
        }
    }

    /**
     * Heavy login-page traffic from one IP must not return 404 to another IP
     *
     * The 15 requests per minute limit is per IP: people on other addresses are not
     * affected by someone hammering the login page.
     *
     * @return void
     */
    public function test_login_page_rate_limit_is_per_ip(): void
    {
        $login = new LoginSecurity();

        for ($i = 0; $i < 20; $i++) {
            $login->is_login_page_rate_limited("198.51.100.1");
        }

        $this->assertTrue(
            $login->is_login_page_rate_limited("198.51.100.1"),
            "The noisy IP is over the limit"
        );
        $this->assertFalse(
            $login->is_login_page_rate_limited("198.51.100.2"),
            "A different IP must not inherit the noisy IP's count"
        );
    }

    /**
     * The documented threshold: the 16th request in a minute is the first one blocked
     *
     * @return void
     */
    public function test_login_page_rate_limit_threshold_is_fifteen_per_minute(): void
    {
        $login = new LoginSecurity();

        for ($i = 1; $i <= 15; $i++) {
            $this->assertFalse(
                $login->is_login_page_rate_limited("198.51.100.3"),
                "Request {$i} of 15 must be served"
            );
        }

        $this->assertTrue(
            $login->is_login_page_rate_limited("198.51.100.3"),
            "The 16th request in a minute is blocked"
        );
    }

    /**
     * Two people behind one IP share the failed-login budget (documented behavior)
     *
     * The lockout is per IP by design: after five failures from one address, even the right
     * password from that address is refused. This test pins that so a change is deliberate.
     *
     * @return void
     */
    public function test_users_behind_one_ip_share_the_lockout(): void
    {
        $login   = new LoginSecurity();
        $user_id = self::factory()->user->create(["user_login" => "officeuser", "user_pass" => "Correct-Horse-1!"]);
        $user    = \get_userdata($user_id);

        // Four failures by different colleagues: nobody is locked yet.
        $_SERVER["REMOTE_ADDR"] = "192.0.2.50";
        foreach (["alice", "bob", "carol", "dave"] as $name) {
            $login->handle_failed_login($name);
        }
        $this->assertNotInstanceOf(
            WP_Error::class,
            $login->check_login_lockout($user, "officeuser", "Correct-Horse-1!"),
            "Four failures stay under the limit of five"
        );

        // The fifth failure, by anyone, locks the address for everyone.
        $login->handle_failed_login("erin");
        $result = $login->check_login_lockout($user, "officeuser", "Correct-Horse-1!");
        $this->assertInstanceOf(WP_Error::class, $result, "The correct password is refused from a locked IP");
        $this->assertSame("login_locked", $result->get_error_code());

        // A colleague on another address is unaffected.
        $_SERVER["REMOTE_ADDR"] = "192.0.2.51";
        $this->assertNotInstanceOf(
            WP_Error::class,
            $login->check_login_lockout($user, "officeuser", "Correct-Horse-1!"),
            "Another IP is not locked"
        );
    }

    /**
     * Building the admin data provider must not make every failed login count twice
     *
     * SecurityDataProvider created its own LoginSecurity, which registered the whole set of
     * login hooks a second time. The plugin builds the admin panel (and so the provider) on
     * every request, so each failed login was counted twice and "5 attempts" locked the IP
     * after the third failure.
     *
     * @return void
     */
    public function test_a_failed_login_counts_once_even_with_the_admin_data_provider_loaded(): void
    {
        \remove_all_actions("wp_login_failed");

        // Start from a clean singleton, then load the way the plugin does: the component first,
        // the admin panel (data provider) after it.
        $property = new \ReflectionProperty(LoginSecurity::class, "instance");
        $property->setAccessible(true);
        $property->setValue(null, null);

        LoginSecurity::instance();
        new SecurityDataProvider();

        $ip = "192.0.2.80";
        $_SERVER["REMOTE_ADDR"] = $ip;

        for ($i = 0; $i < 3; $i++) {
            \do_action("wp_login_failed", "someone", new WP_Error("incorrect_password"));
        }

        $attempts = \get_transient(SecurityHelper::generate_ip_transient_key("login_attempts", $ip));
        $this->assertSame(3, $attempts, "Three failed logins are three attempts, not six");
        $this->assertFalse(
            (bool) \get_transient(SecurityHelper::generate_ip_transient_key("lockout", $ip)),
            "Three failures must not lock out an IP whose limit is five"
        );
    }

    /**
     * Trying again while locked out must not extend the lockout
     *
     * wp_login_failed fires for the lockout error itself, so each blocked attempt used to
     * renew the lockout for the full duration: a locked user who retried every few minutes
     * (or an attacker on a shared IP) kept the address locked forever.
     *
     * @return void
     */
    public function test_attempts_during_lockout_do_not_extend_it(): void
    {
        $ip    = "192.0.2.60";
        $login = new LoginSecurity();
        $this->lock_out($login, $ip);

        // Pretend 14 minutes passed: one minute is left.
        $key = SecurityHelper::generate_ip_transient_key("lockout", $ip);
        \update_option("_transient_timeout_{$key}", time() + 60);

        // The locked user retries; core fires wp_login_failed for the lockout error.
        $login->handle_failed_login("someone");

        $this->assertLessThanOrEqual(
            60,
            $this->lockout_seconds_left($ip),
            "A blocked attempt must not push the unlock time back out to 15 minutes"
        );
    }

    /**
     * A lockout ends: once it expires the same IP can log in again
     *
     * @return void
     */
    public function test_lockout_expires_and_the_ip_can_log_in_again(): void
    {
        $ip      = "192.0.2.61";
        $login   = new LoginSecurity();
        $user_id = self::factory()->user->create(["user_login" => "unlockme", "user_pass" => "Correct-Horse-1!"]);
        $user    = \get_userdata($user_id);

        $this->lock_out($login, $ip);
        $this->assertInstanceOf(
            WP_Error::class,
            $login->check_login_lockout($user, "unlockme", "Correct-Horse-1!")
        );

        // Expire both transients, as the clock would after the duration.
        foreach (["lockout", "login_attempts"] as $prefix) {
            \delete_transient(SecurityHelper::generate_ip_transient_key($prefix, $ip));
        }

        $this->assertNotInstanceOf(
            WP_Error::class,
            $login->check_login_lockout($user, "unlockme", "Correct-Horse-1!"),
            "After the lockout expires the login goes through"
        );
    }

    /**
     * Strength rules: eight characters with upper, lower, number and symbol
     *
     * @return void
     */
    public function test_password_strength_rules(): void
    {
        $login = new LoginSecurity();
        $user  = \get_userdata(self::factory()->user->create());

        $cases = [
            "Sh0rt!"           => false,
            "alllowercase1!"   => false,
            "ALLUPPERCASE1!"   => false,
            "NoDigitsHere!!"   => false,
            "NoSymbols12345"   => false,
            "Correct-Horse-1!" => true,
        ];

        foreach ($cases as $password => $should_pass) {
            $_POST["pass1"] = $password;
            $errors = new WP_Error();
            $login->validate_password_strength_reset($errors, $user);
            $this->assertSame(
                !$should_pass,
                $errors->has_errors(),
                "Password {$password} should " . ($should_pass ? "pass" : "fail")
            );
        }
    }

    /**
     * With admin hiding on, the expired-session redirect is a well-formed login URL
     *
     * The login URL already carries the admin hiding token as its query string, and the
     * plugin appended "?session_expired=1" to it, producing "...silver_auth=x?session_expired=1".
     * The token then had a wrong value, so a person without the one-hour admin access cookie
     * got a 404 instead of the login screen.
     *
     * @return void
     */
    public function test_session_expired_redirect_keeps_the_admin_hiding_token_intact(): void
    {
        \update_option("silver_assist_admin_hide_enabled", 1);
        \update_option("silver_assist_admin_hide_path", "silver-admin");
        \update_option("silver_assist_session_timeout", 1);
        new AdminHideSecurity();
        $login = new LoginSecurity();

        $user_id = self::factory()->user->create(["role" => "editor"]);
        \wp_set_current_user($user_id);
        \update_user_meta($user_id, "last_activity", time() - 120);
        \set_current_screen("dashboard");

        \add_filter(
            "wp_redirect",
            static function ($location) {
                throw new \RuntimeException("redirect:" . $location);
            },
            1
        );

        $redirect = null;
        ob_start();
        try {
            $login->setup_session_timeout();
        } catch (\RuntimeException $e) {
            $redirect = substr($e->getMessage(), strlen("redirect:"));
        }
        ob_end_clean();

        $this->assertNotNull($redirect, "An idle admin session is sent to the login screen");

        parse_str((string) \wp_parse_url($redirect, PHP_URL_QUERY), $query);
        $this->assertSame("silver-admin", $query["silver_auth"] ?? null, "The token keeps its exact value");
        $this->assertSame("1", $query["session_expired"] ?? null, "The expiry flag is its own parameter");
    }

    /**
     * The attempt that triggers the lockout does not reveal whether the username exists
     *
     * The login errors are left as core wrote them while the IP is locked out, so the lockout
     * notice stays readable. But the fifth failed attempt sets the lockout during the same
     * request that renders its error, so that last error ("The password you entered for the
     * username admin is incorrect", or "Unknown username") escaped the generic message and
     * told an attacker which usernames exist.
     *
     * @return void
     */
    public function test_the_attempt_that_triggers_the_lockout_stays_generic(): void
    {
        \remove_all_filters("login_errors");
        new GeneralSecurity();
        $login = new LoginSecurity();
        $this->lock_out($login, "192.0.2.90");

        $html = \apply_filters(
            "login_errors",
            "<p><strong>Error:</strong> The password you entered for the username <strong>admin</strong> is incorrect.</p>"
        );

        $this->assertSame("Invalid login credentials.", $html);

        // The lockout notice itself is still shown to the locked-out person.
        $notice = $login->check_login_lockout(null, "admin", "x");
        $this->assertInstanceOf(WP_Error::class, $notice);
        $this->assertStringContainsString(
            "Too many failed login attempts",
            \apply_filters("login_errors", "<p>" . $notice->get_error_message() . "</p>")
        );
    }
}
