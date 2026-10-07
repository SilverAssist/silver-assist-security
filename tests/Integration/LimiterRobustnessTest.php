<?php
/**
 * Limiter Robustness Tests
 *
 * Behavior of the login lockout, the login-page limiter and the IP blacklist under a persistent
 * object cache, parallel failures, spaced requests and IPv6 clients (#149, part of #124).
 *
 * A persistent object cache is simulated with `wp_using_ext_object_cache( true )`: core then keeps
 * transients in the object cache only, so no `_transient_*` row ever reaches the options table, as
 * with Redis.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Security\LoginSecurity;
use WP_Error;
use WP_UnitTestCase;

/**
 * Limiter behavior that must hold with and without an object cache
 */
class LimiterRobustnessTest extends WP_UnitTestCase
{
    use \SilverAssist\Security\Tests\Helpers\StoresRawOptions;

    /**
     * Option that indexes the blacklist
     */
    private const INDEX = "silver_assist_ip_blacklist_index";

    /**
     * Original $_SERVER
     *
     * @var array<string, mixed>
     */
    private array $original_server = [];

    /**
     * Prepare configuration and clean state
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->original_server = $_SERVER;

        \update_option("silver_assist_login_attempts", 5);
        \update_option("silver_assist_lockout_duration", 900);
        \update_option("silver_assist_ip_blacklist_enabled", 1);
        \delete_option(self::INDEX);

        $_SERVER["REMOTE_ADDR"]     = "203.0.113.10";
        $_SERVER["REQUEST_METHOD"]  = "POST";

        $this->clear_transients();
    }

    /**
     * Restore state
     *
     * @return void
     */
    protected function tearDown(): void
    {
        \wp_using_ext_object_cache(false);
        $_SERVER = $this->original_server;
        \remove_all_filters("silver_assist_security_ipv6_prefix_length");
        \remove_all_filters("pre_transient_" . SecurityHelper::generate_ip_transient_key("login_attempts", "203.0.113.10"));
        \delete_option(self::INDEX);
        $this->clear_transients();
        parent::tearDown();
    }

    /**
     * Remove every limiter transient row
     *
     * @return void
     */
    private function clear_transients(): void
    {
        global $wpdb;

        $wpdb->query(
            "DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '%login_attempts_%'
            OR option_name LIKE '%login_window_%'
            OR option_name LIKE '%lockout_%'
            OR option_name LIKE '%login_access_%'
            OR option_name LIKE '%bot_activity_%'
            OR option_name LIKE '%ip_blacklist_%'
            OR option_name LIKE '%ip_violations_%'"
        );
    }

    /**
     * Fail five logins as one IP
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
     * Whether a login attempt from an IP is turned away by the lockout
     *
     * @param LoginSecurity $login Login security instance.
     * @param string        $ip    Client IP.
     * @return bool
     */
    private function is_locked_out(LoginSecurity $login, string $ip): bool
    {
        $_SERVER["REMOTE_ADDR"] = $ip;
        return $login->check_login_lockout(null, "someone", "secret") instanceof WP_Error;
    }

    /**
     * Move the clock forward for a login-page counter by shortening its stored expiry
     *
     * @param string $ip      Client IP.
     * @param int    $seconds Seconds to subtract from the expiry rows.
     * @return void
     */
    private function age_login_page_counter(string $ip, int $seconds): void
    {
        global $wpdb;

        foreach (["login_access", "login_access_window"] as $prefix) {
            $key = SecurityHelper::generate_ip_transient_key($prefix, $ip);
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->options} SET option_value = option_value - %d WHERE option_name = %s",
                    $seconds,
                    "_transient_timeout_{$key}"
                )
            );
        }
        \wp_cache_flush();
    }

    // N9: persistent object cache.

    /**
     * The blocked list, count and stats work when transients never reach the options table
     *
     * @return void
     */
    public function test_blacklist_listing_works_with_persistent_object_cache(): void
    {
        global $wpdb;
        \wp_using_ext_object_cache(true);

        $blacklist = new IPBlacklist();
        $blacklist->add_to_blacklist("203.0.113.50", "Manual block", 3600);

        $this->assertSame(
            0,
            (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_%ip_blacklist_%'"),
            "Simulation check: the block must not be stored in the options table"
        );
        $this->assertTrue($blacklist->is_blacklisted("203.0.113.50"));
        $this->assertArrayHasKey("203.0.113.50", $blacklist->get_all_blacklisted_ips());
        $this->assertSame(1, $blacklist->get_blacklist_stats()["total_blacklisted"]);
        $this->assertSame(1, $blacklist->get_blacklist_stats()["manual_blacklisted"]);
    }

    /**
     * Unblocking removes the IP from the list
     *
     * @return void
     */
    public function test_unblocked_ip_leaves_the_list_with_persistent_object_cache(): void
    {
        \wp_using_ext_object_cache(true);

        $blacklist = new IPBlacklist();
        $blacklist->add_to_blacklist("203.0.113.50", "Manual block", 3600);
        $blacklist->add_to_blacklist("203.0.113.51", "Manual block", 3600);

        $this->assertTrue($blacklist->remove_from_blacklist("203.0.113.50"));

        $this->assertSame(["203.0.113.51"], array_keys($blacklist->get_all_blacklisted_ips()));
    }

    /**
     * Violations that reach the threshold show up in the list with a persistent object cache
     *
     * @return void
     */
    public function test_auto_blacklisted_ip_is_listed_with_persistent_object_cache(): void
    {
        \wp_using_ext_object_cache(true);
        $this->store_raw_option( "silver_assist_ip_blacklist_threshold", 2 );

        $blacklist = new IPBlacklist();
        $blacklist->record_violation("203.0.113.60", "sql_injection");
        $blacklist->record_violation("203.0.113.60", "sql_injection");

        $this->assertSame(1, $blacklist->get_blacklist_stats()["auto_blacklisted"]);
    }

    /**
     * Blocks stored before the index existed (options table) are still listed after an upgrade
     *
     * @return void
     */
    public function test_blocks_stored_before_the_index_are_imported(): void
    {
        $key = SecurityHelper::generate_ip_transient_key("ip_blacklist", "203.0.113.70");
        \set_transient($key, ["ip" => "203.0.113.70", "reason" => "old", "timestamp" => time(), "duration" => 3600, "auto" => false], 3600);
        \delete_option(self::INDEX);

        $this->assertArrayHasKey("203.0.113.70", (new IPBlacklist())->get_all_blacklisted_ips());
    }

    /**
     * Cleanup drops expired entries from the index, also with a persistent object cache
     *
     * @return void
     */
    public function test_cleanup_prunes_the_index_with_persistent_object_cache(): void
    {
        \wp_using_ext_object_cache(true);

        $blacklist = new IPBlacklist();
        $blacklist->add_to_blacklist("203.0.113.80", "Manual block", 3600);
        $index = \get_option(self::INDEX);
        $index["ip_blacklist_expired"] = time() - 10;
        \update_option(self::INDEX, $index, false);

        $this->assertSame(1, $blacklist->clean_expired_violations());

        $this->assertArrayNotHasKey("ip_blacklist_expired", \get_option(self::INDEX));
        $this->assertCount(1, \get_option(self::INDEX));
    }

    /**
     * Writing a block prunes expired entries, so the index stays small
     *
     * @return void
     */
    public function test_index_is_pruned_when_a_block_is_written(): void
    {
        \update_option(self::INDEX, ["ip_blacklist_expired" => time() - 10], false);

        (new IPBlacklist())->add_to_blacklist("203.0.113.81", "Manual block", 3600);

        $this->assertArrayNotHasKey("ip_blacklist_expired", \get_option(self::INDEX));
    }

    /**
     * The index is not autoloaded on every request
     *
     * @return void
     */
    public function test_index_option_is_not_autoloaded(): void
    {
        global $wpdb;

        (new IPBlacklist())->add_to_blacklist("203.0.113.82", "Manual block", 3600);

        $autoload = $wpdb->get_var(
            $wpdb->prepare("SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", self::INDEX)
        );
        $this->assertContains($autoload, ["no", "off"]);
    }

    /**
     * The lockout message reports the real remaining time with a persistent object cache
     *
     * @return void
     */
    public function test_lockout_message_shows_remaining_time_with_persistent_object_cache(): void
    {
        \wp_using_ext_object_cache(true);
        $login = new LoginSecurity();

        $this->lock_out($login, "203.0.113.10");
        $error = $login->check_login_lockout(null, "someone", "secret");

        $this->assertInstanceOf(WP_Error::class, $error);
        $this->assertStringContainsString("Try again in 15 minutes", $error->get_error_message());
    }

    /**
     * The lockout message reports the real remaining time without an object cache
     *
     * @return void
     */
    public function test_lockout_message_shows_remaining_time(): void
    {
        $login = new LoginSecurity();

        $this->lock_out($login, "203.0.113.10");
        $error = $login->check_login_lockout(null, "someone", "secret");

        $this->assertInstanceOf(WP_Error::class, $error);
        $this->assertStringContainsString("Try again in 15 minutes", $error->get_error_message());
    }

    /**
     * A locked-out IP is still counted by the dashboard's blocked IPs figure
     *
     * @return void
     */
    public function test_locked_out_ip_is_counted_by_the_dashboard(): void
    {
        \wp_cache_delete("silver_assist_blocked_ips_count", "silver-assist-security");
        $this->lock_out(new LoginSecurity(), "203.0.113.10");
        \wp_cache_delete("silver_assist_blocked_ips_count", "silver-assist-security");

        $this->assertSame(1, (new \SilverAssist\Security\Admin\Data\StatisticsProvider())->get_blocked_ips_count());
    }

    // N15: atomic failed-login counter.

    /**
     * Parallel failures cannot overwrite each other's count
     *
     * A read that returns a stale count, as another process would see mid-update, must not stop
     * the lockout: the counter is incremented atomically, not read, changed and written back.
     *
     * @return void
     */
    public function test_lockout_does_not_depend_on_reading_the_previous_count(): void
    {
        $key = "pre_transient_" . SecurityHelper::generate_ip_transient_key("login_attempts", "203.0.113.10");
        \add_filter($key, static fn() => 0);

        $login = new LoginSecurity();
        $this->lock_out($login, "203.0.113.10");

        $this->assertTrue($this->is_locked_out($login, "203.0.113.10"));
    }

    /**
     * Five failures lock the IP with a persistent object cache too
     *
     * @return void
     */
    public function test_lockout_after_failures_with_persistent_object_cache(): void
    {
        \wp_using_ext_object_cache(true);
        $login = new LoginSecurity();

        $this->lock_out($login, "203.0.113.10");

        $this->assertTrue($this->is_locked_out($login, "203.0.113.10"));
        $this->assertFalse($this->is_locked_out($login, "203.0.113.99"));
    }

    /**
     * Four failures do not lock out, and the counting window does not slide
     *
     * @return void
     */
    public function test_failures_spread_over_more_than_the_window_do_not_lock_out(): void
    {
        global $wpdb;
        $login = new LoginSecurity();
        $_SERVER["REMOTE_ADDR"] = "203.0.113.10";

        for ($i = 0; $i < 4; $i++) {
            $login->handle_failed_login("someone");
        }
        $this->assertFalse($this->is_locked_out($login, "203.0.113.10"));

        // The window (first failure plus the lockout duration) elapses.
        foreach (["login_attempts", "login_window"] as $prefix) {
            $key = SecurityHelper::generate_ip_transient_key($prefix, "203.0.113.10");
            $wpdb->update($wpdb->options, ["option_value" => time() - 1], ["option_name" => "_transient_timeout_{$key}"]);
        }
        \wp_cache_flush();

        $login->handle_failed_login("someone");
        $this->assertFalse($this->is_locked_out($login, "203.0.113.10"), "The fifth failure opens a new window");
    }

    // N14: login-page limiter, bot signals, user agents.

    /**
     * Fifteen requests in a minute pass, the sixteenth is turned away
     *
     * @return void
     */
    public function test_login_page_limit_is_fifteen_per_window(): void
    {
        $login = new LoginSecurity();

        for ($i = 1; $i <= 15; $i++) {
            $this->assertFalse($login->is_login_page_rate_limited("203.0.113.20"), "Request {$i}");
        }
        $this->assertTrue($login->is_login_page_rate_limited("203.0.113.20"));
    }

    /**
     * A monitor that hits the login page every 50 seconds is never blocked
     *
     * The window starts at the first request and ends a minute later; later requests do not
     * extend it.
     *
     * @return void
     */
    public function test_spaced_requests_never_reach_the_limit(): void
    {
        $login = new LoginSecurity();

        for ($i = 1; $i <= 40; $i++) {
            $this->assertFalse($login->is_login_page_rate_limited("203.0.113.21"), "Request {$i}");
            $this->age_login_page_counter("203.0.113.21", 50);
        }
    }

    /**
     * Ordinary failed logins are not recorded as bot activity
     *
     * @return void
     */
    public function test_failed_logins_are_not_bot_activity(): void
    {
        $_SERVER["REMOTE_ADDR"]     = "203.0.113.22";
        $_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";

        \do_action("wp_login_failed", "someone");

        $this->assertFalse(\get_transient(SecurityHelper::generate_ip_transient_key("bot_activity", "203.0.113.22")));
    }

    /**
     * Repeated bot activity is logged but sets no two-hour block flag that nothing reads
     *
     * @return void
     */
    public function test_bot_activity_does_not_write_an_unread_block_flag(): void
    {
        $_SERVER["REMOTE_ADDR"]     = "203.0.113.23";
        $_SERVER["HTTP_USER_AGENT"] = "Nmap Scripting Engine";

        $login = new LoginSecurity();
        for ($i = 0; $i < 6; $i++) {
            $login->track_bot_behavior();
        }

        $this->assertCount(6, \get_transient(SecurityHelper::generate_ip_transient_key("bot_activity", "203.0.113.23")));
        $this->assertFalse(\get_transient("extended_bot_block_" . md5("203.0.113.23")));
    }

    /**
     * User agents of real browsers and phones are not bots
     *
     * @dataProvider legitimate_user_agents
     * @param string $user_agent User agent.
     * @return void
     */
    public function test_real_user_agents_are_not_bots(string $user_agent): void
    {
        $_SERVER["HTTP_ACCEPT"] = "text/html";

        $this->assertFalse(SecurityHelper::matches_bot_user_agent($user_agent));
        $this->assertFalse(SecurityHelper::is_bot_request($user_agent));
    }

    /**
     * Known bots, crawlers, scanners and scripting clients are bots
     *
     * @dataProvider bot_user_agents
     * @param string $user_agent User agent.
     * @return void
     */
    public function test_bot_user_agents_are_bots(string $user_agent): void
    {
        $this->assertTrue(SecurityHelper::matches_bot_user_agent($user_agent));
    }

    /**
     * Real User-Agent strings
     *
     * @return array<string, array<int, string>>
     */
    public function legitimate_user_agents(): array
    {
        return [
            "CUBOT phone"       => ["Mozilla/5.0 (Linux; Android 12; CUBOT KingKong 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"],
            "CUBOT underscore"  => ["Mozilla/5.0 (Linux; Android 13; CUBOT_P80) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"],
            "Chrome Windows"    => ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"],
            "Safari iPhone"     => ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"],
            "Firefox Linux"     => ["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"],
            "Samsung Internet"  => ["Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36"],
        ];
    }

    /**
     * Bot User-Agent strings
     *
     * @return array<string, array<int, string>>
     */
    public function bot_user_agents(): array
    {
        return [
            "Googlebot"  => ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
            "bingbot"    => ["Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"],
            "AhrefsBot"  => ["Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"],
            "curl"       => ["curl/8.4.0"],
            "wget"       => ["Wget/1.21.4"],
            "python"     => ["python-requests/2.31.0"],
            "Java"       => ["Java/17.0.2"],
            "PHP"        => ["PHP/8.2.12"],
            "perl"       => ["libwww-perl/6.67"],
            "nmap"       => ["Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"],
            "sqlmap"     => ["sqlmap/1.7.2#stable (https://sqlmap.org)"],
            "scanner"    => ["Mozilla/5.0 (compatible; Vulnerability Scanner 1.0)"],
        ];
    }

    // N16: IPv6 /64 grouping.

    /**
     * Limiter keys use the /64 prefix for IPv6, the exact address for IPv4
     *
     * @return void
     */
    public function test_ip_normalization(): void
    {
        $this->assertSame("203.0.113.10", SecurityHelper::normalize_ip_for_limits("203.0.113.10"));
        $this->assertSame("2001:db8:abcd:12::/64", SecurityHelper::normalize_ip_for_limits("2001:db8:abcd:12:1:2:3:4"));
        $this->assertSame("2001:db8:abcd:12::/64", SecurityHelper::normalize_ip_for_limits("2001:0db8:abcd:0012::ffff"));
        $this->assertSame("203.0.113.5", SecurityHelper::normalize_ip_for_limits("::ffff:203.0.113.5"));
        $this->assertSame("not-an-ip", SecurityHelper::normalize_ip_for_limits("not-an-ip"));
        $this->assertSame("lockout_" . md5("203.0.113.10"), SecurityHelper::generate_ip_transient_key("lockout", "203.0.113.10"));
    }

    /**
     * The prefix length is filterable and 128 disables grouping
     *
     * @return void
     */
    public function test_ipv6_prefix_length_filter(): void
    {
        \add_filter("silver_assist_security_ipv6_prefix_length", static fn() => 48);
        $this->assertSame("2001:db8:abcd::/48", SecurityHelper::normalize_ip_for_limits("2001:db8:abcd:12::1"));
        \remove_all_filters("silver_assist_security_ipv6_prefix_length");

        \add_filter("silver_assist_security_ipv6_prefix_length", static fn() => 128);
        $this->assertSame("2001:db8:abcd:12::1", SecurityHelper::normalize_ip_for_limits("2001:db8:abcd:12:0:0:0:1"));
        $this->assertNotSame(
            SecurityHelper::generate_ip_transient_key("lockout", "2001:db8:abcd:12::1"),
            SecurityHelper::generate_ip_transient_key("lockout", "2001:db8:abcd:12::2")
        );
    }

    /**
     * Rotating addresses inside one /64 does not escape the login lockout
     *
     * @return void
     */
    public function test_lockout_covers_the_whole_ipv6_prefix(): void
    {
        $login = new LoginSecurity();

        // Five failures, each from a different address of the same /64.
        for ($i = 1; $i <= 5; $i++) {
            $_SERVER["REMOTE_ADDR"] = "2001:db8:abcd:12::{$i}";
            $login->handle_failed_login("someone");
        }

        $this->assertTrue($this->is_locked_out($login, "2001:db8:abcd:12::beef"));
        $this->assertFalse($this->is_locked_out($login, "2001:db8:abcd:13::1"), "Another /64 is not affected");
    }

    /**
     * Without grouping, IPv6 addresses are limited one by one
     *
     * @return void
     */
    public function test_lockout_is_per_address_when_grouping_is_disabled(): void
    {
        \add_filter("silver_assist_security_ipv6_prefix_length", static fn() => 128);
        $login = new LoginSecurity();

        $this->lock_out($login, "2001:db8:abcd:12::1");

        $this->assertTrue($this->is_locked_out($login, "2001:db8:abcd:12::1"));
        $this->assertFalse($this->is_locked_out($login, "2001:db8:abcd:12::2"));
    }

    /**
     * IPv4 clients keep their own lockout
     *
     * @return void
     */
    public function test_ipv4_lockout_is_per_address(): void
    {
        $login = new LoginSecurity();

        $this->lock_out($login, "203.0.113.30");

        $this->assertTrue($this->is_locked_out($login, "203.0.113.30"));
        $this->assertFalse($this->is_locked_out($login, "203.0.113.31"));
    }

    /**
     * The login-page limit is shared by the addresses of one /64
     *
     * @return void
     */
    public function test_login_page_limit_covers_the_whole_ipv6_prefix(): void
    {
        $login = new LoginSecurity();

        for ($i = 1; $i <= 15; $i++) {
            $this->assertFalse($login->is_login_page_rate_limited("2001:db8:abcd:12::{$i}"));
        }

        $this->assertTrue($login->is_login_page_rate_limited("2001:db8:abcd:12::ffff"));
        $this->assertFalse($login->is_login_page_rate_limited("2001:db8:abcd:13::1"));
    }

    /**
     * Blocking one IPv6 address blocks its /64, and the list still shows the address that was blocked
     *
     * @return void
     */
    public function test_blacklist_covers_the_whole_ipv6_prefix(): void
    {
        $blacklist = new IPBlacklist();
        $blacklist->add_to_blacklist("2001:db8:abcd:12::1", "Manual block", 3600);

        $this->assertTrue($blacklist->is_blacklisted("2001:db8:abcd:12::2"));
        $this->assertFalse($blacklist->is_blacklisted("2001:db8:abcd:13::1"));
        $this->assertSame(["2001:db8:abcd:12::1"], array_keys($blacklist->get_all_blacklisted_ips()));

        $this->assertTrue($blacklist->remove_from_blacklist("2001:db8:abcd:12::99"));
        $this->assertFalse($blacklist->is_blacklisted("2001:db8:abcd:12::1"));
    }
}
