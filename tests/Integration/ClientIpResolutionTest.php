<?php
/**
 * Client IP Resolution Tests
 *
 * The client IP is the identity behind login lockout, the IP blacklist, form protection and the
 * REST/GraphQL rate limits. A client must not be able to choose it by sending headers (#128).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\RestAPISecurity;
use WP_UnitTestCase;

/**
 * Test SecurityHelper::get_client_ip() and the components that depend on it
 */
class ClientIpResolutionTest extends WP_UnitTestCase
{
    private const FORGED_KEYS = [
        "HTTP_X_FORWARDED_FOR",
        "HTTP_CLIENT_IP",
        "HTTP_CF_CONNECTING_IP",
        "HTTP_X_REAL_IP",
        "HTTP_X_FORWARDED",
        "HTTP_FORWARDED_FOR",
        "HTTP_FORWARDED",
    ];

    /**
     * Start from a clean request environment
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->clean_server();
        $this->assertFalse(\defined("SILVER_ASSIST_TRUSTED_PROXY_CIDRS"), "These tests need the constant undefined");
    }

    /**
     * Restore the request environment
     *
     * @return void
     */
    protected function tearDown(): void
    {
        $this->clean_server();
        parent::tearDown();
    }

    /**
     * Remove every header and the peer address from $_SERVER
     *
     * @return void
     */
    private function clean_server(): void
    {
        foreach (self::FORGED_KEYS as $key) {
            unset($_SERVER[$key]);
        }
        unset($_SERVER["REMOTE_ADDR"]);
    }

    /**
     * Direct connection from a public address: no header may change the identity
     *
     * @return void
     */
    public function test_forged_headers_are_ignored_when_peer_is_public(): void
    {
        $_SERVER["REMOTE_ADDR"] = "198.51.100.7";
        foreach (self::FORGED_KEYS as $key) {
            $_SERVER[$key] = "203.0.113.99";
        }

        $this->assertSame("198.51.100.7", SecurityHelper::get_client_ip());
    }

    /**
     * Rotating a forged header on every request must not create new identities
     *
     * @return void
     */
    public function test_rotating_forged_values_keep_the_same_identity(): void
    {
        $_SERVER["REMOTE_ADDR"] = "198.51.100.7";
        $seen = [];
        foreach (["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"] as $forged) {
            $_SERVER["HTTP_X_FORWARDED_FOR"] = $forged;
            $_SERVER["HTTP_CLIENT_IP"]       = $forged;
            $seen[] = SecurityHelper::get_client_ip();
        }

        $this->assertSame(["198.51.100.7"], \array_values(\array_unique($seen)));
    }

    /**
     * Behind an internal load balancer the address it appended (rightmost) is the client
     *
     * @return void
     */
    public function test_private_peer_uses_the_rightmost_public_forwarded_address(): void
    {
        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.99, 198.51.100.20";

        $this->assertSame("198.51.100.20", SecurityHelper::get_client_ip(), "A client-supplied leftmost value must not win");
    }

    /**
     * A private client behind the proxy is the client, not infrastructure
     *
     * Skipping private hops would step over the real client (VPN, office network) and reach the
     * forged value to its left.
     *
     * @return void
     */
    public function test_private_client_behind_a_proxy_is_not_skipped(): void
    {
        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "8.8.8.8, 10.0.2.55";

        $this->assertSame("10.0.2.55", SecurityHelper::get_client_ip());
    }

    /**
     * A proxy that appends the client port still yields the client, not a forged value
     *
     * @return void
     */
    public function test_forwarded_address_with_a_port_is_normalized(): void
    {
        $_SERVER["REMOTE_ADDR"] = "10.0.1.42";

        $_SERVER["HTTP_X_FORWARDED_FOR"] = "8.8.8.8, 198.51.100.20:54321";
        $this->assertSame("198.51.100.20", SecurityHelper::get_client_ip(), "IPv4 with port");

        $_SERVER["HTTP_X_FORWARDED_FOR"] = "8.8.8.8, [2606:4700:4700::1111]:443";
        $this->assertSame("2606:4700:4700::1111", SecurityHelper::get_client_ip(), "IPv6 with port");
    }

    /**
     * An unvalidatable appended hop must not expose the forged values to its left
     *
     * @return void
     */
    public function test_unparseable_last_hop_falls_back_to_the_peer(): void
    {
        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "8.8.8.8, not-an-ip";

        $this->assertSame("10.0.1.42", SecurityHelper::get_client_ip());
    }

    /**
     * Opting out of the private-peer heuristic ignores forwarded headers entirely
     *
     * @return void
     */
    public function test_opting_out_of_private_proxy_trust_uses_the_peer(): void
    {
        \add_filter("silver_assist_trust_private_proxies", "__return_false");

        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "198.51.100.20";

        $this->assertSame("10.0.1.42", SecurityHelper::get_client_ip());
    }

    /**
     * Only X-Forwarded-For is honored behind a private peer; single-value headers are not
     *
     * @return void
     */
    public function test_other_headers_are_ignored_even_behind_a_private_peer(): void
    {
        $_SERVER["REMOTE_ADDR"]            = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"]   = "198.51.100.20";
        $_SERVER["HTTP_CF_CONNECTING_IP"]  = "203.0.113.77";
        $_SERVER["HTTP_CLIENT_IP"]         = "203.0.113.88";
        $_SERVER["HTTP_X_REAL_IP"]         = "203.0.113.66";

        $this->assertSame("198.51.100.20", SecurityHelper::get_client_ip());
    }

    /**
     * Garbage in the chain falls back to the peer address
     *
     * @return void
     */
    public function test_invalid_forwarded_values_fall_back_to_the_peer(): void
    {
        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "not-an-ip, garbage, 999.1.1.1";

        $this->assertSame("10.0.1.42", SecurityHelper::get_client_ip());
    }

    /**
     * Missing peer address keeps the documented placeholder
     *
     * @return void
     */
    public function test_missing_remote_addr_returns_the_unspecified_address(): void
    {
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.99";

        $this->assertSame("0.0.0.0", SecurityHelper::get_client_ip());
    }

    /**
     * IPv6 public peers get the same treatment
     *
     * @return void
     */
    public function test_public_ipv6_peer_ignores_headers(): void
    {
        // Not 2001:db8::/32: that documentation range counts as reserved, hence as internal.
        $_SERVER["REMOTE_ADDR"]          = "2606:4700:4700::1111";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.99";

        $this->assertSame("2606:4700:4700::1111", SecurityHelper::get_client_ip());
    }

    /**
     * With configured CIDRs a private peer that is not listed is not trusted
     *
     * @return void
     */
    public function test_configured_cidrs_do_not_trust_other_private_peers(): void
    {
        \add_filter("silver_assist_trusted_proxy_cidrs", static fn (): array => ["172.16.0.0/12"]);

        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "198.51.100.20";

        $this->assertSame("10.0.1.42", SecurityHelper::get_client_ip());
    }

    /**
     * With configured CIDRs, trusted hops are discarded right to left
     *
     * @return void
     */
    public function test_configured_cidrs_discard_trusted_hops(): void
    {
        \add_filter("silver_assist_trusted_proxy_cidrs", static fn (): array => ["10.0.0.0/8", "52.84.0.0/15"]);

        $_SERVER["REMOTE_ADDR"]          = "10.0.1.42";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.5, 52.84.1.1, 10.0.1.42";

        $this->assertSame("203.0.113.5", SecurityHelper::get_client_ip());
    }

    /**
     * Every component that needs the client IP must agree with the single implementation
     *
     * @return void
     */
    public function test_components_resolve_the_same_identity_under_a_forged_header(): void
    {
        $_SERVER["REMOTE_ADDR"]          = "198.51.100.7";
        $_SERVER["HTTP_X_FORWARDED_FOR"] = "203.0.113.99";
        $_SERVER["HTTP_CLIENT_IP"]       = "203.0.113.98";
        $_SERVER["HTTP_CF_CONNECTING_IP"] = "203.0.113.97";

        $expected = SecurityHelper::get_client_ip();
        $this->assertSame("198.51.100.7", $expected);

        foreach ([GraphQLSecurity::class, LoginSecurity::class, RestAPISecurity::class] as $class) {
            $instance = new $class();
            $method   = new \ReflectionMethod($instance, "get_client_ip");
            $method->setAccessible(true);
            $this->assertSame($expected, $method->invoke($instance), "{$class} must not resolve its own IP");
        }
    }
}
