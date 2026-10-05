<?php
/**
 * oEmbed Result Sanitization Tests
 *
 * Core runs provider HTML through wp_filter_oembed_result() on the
 * oembed_dataparse filter so a hostile or compromised provider cannot inject
 * markup into a post. The plugin must not remove that sanitizer (#129).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test that provider HTML is still sanitized with security hooks active
 */
class OEmbedSanitizationTest extends WP_UnitTestCase
{
    /**
     * Activate the hardening hooks the way a real request would
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $general = new GeneralSecurity();
        $general->remove_unnecessary_headers();
        $general->disable_user_enumeration();
        $GLOBALS["wp_rest_server"] = null;
        do_action("rest_api_init", rest_get_server());
    }

    /**
     * Reset REST server and user
     *
     * @return void
     */
    protected function tearDown(): void
    {
        $GLOBALS["wp_rest_server"] = null;
        wp_set_current_user(0);
        parent::tearDown();
    }

    /**
     * Build provider data the way WP_oEmbed::data2html() receives it
     *
     * @param string $html Provider HTML.
     * @return object
     */
    private function provider_data(string $html): object
    {
        return (object) [
            "version"       => "1.0",
            "type"          => "rich",
            "provider_name" => "Example",
            "html"          => $html,
        ];
    }

    /**
     * The core sanitizer stays registered on oembed_dataparse
     *
     * @return void
     */
    public function test_core_oembed_sanitizer_stays_registered(): void
    {
        $this->assertSame(
            10,
            has_filter("oembed_dataparse", "wp_filter_oembed_result"),
            "wp_filter_oembed_result must stay hooked to oembed_dataparse."
        );
    }

    /**
     * Hostile markup from a provider does not reach the page
     *
     * @return void
     */
    public function test_hostile_provider_html_is_sanitized(): void
    {
        $html   = '<iframe src="https://www.youtube.com/embed/abc" width="560" height="315"></iframe>'
            . '<script>alert(document.cookie)</script><img src=x onerror="alert(1)">';
        $result = apply_filters("oembed_dataparse", $html, $this->provider_data($html), "https://example.com/v");

        $this->assertIsString($result);
        $this->assertStringNotContainsString("<script", $result);
        $this->assertStringNotContainsString("onerror", $result);
        $this->assertStringNotContainsString("<img", $result);
    }

    /**
     * A well-formed provider iframe still renders
     *
     * @return void
     */
    public function test_trusted_provider_iframe_is_kept(): void
    {
        $html   = '<iframe src="https://www.youtube.com/embed/abc" width="560" height="315"></iframe>';
        $result = apply_filters("oembed_dataparse", $html, $this->provider_data($html), "https://example.com/v");

        $this->assertIsString($result);
        $this->assertStringContainsString("<iframe", $result);
        $this->assertStringContainsString("youtube.com/embed/abc", $result);
    }

    /**
     * Mock the YouTube endpoint and an unlisted provider with an iframe plus hostile markup
     *
     * @return callable The filter callback, so the caller can remove it.
     */
    private function mock_provider(): callable
    {
        $mock = static function ($pre, $args, $url) {
            $ok = ["headers" => [], "response" => ["code" => 200, "message" => "OK"], "cookies" => [], "filename" => null];
            if (0 === strpos($url, "https://unknown-provider.test/post")) {
                // Autodiscovery page pointing at an unlisted (untrusted) provider.
                return $ok + [
                    "body" => '<html><head><link rel="alternate" type="application/json+oembed" href="https://unknown-provider.test/oembed?url=x" /></head></html>',
                ];
            }
            if (false === strpos($url, "youtube.com/oembed") && false === strpos($url, "unknown-provider.test/oembed")) {
                return $pre;
            }
            return [
                "headers"  => [],
                "body"     => wp_json_encode(
                    [
                        "version"       => "1.0",
                        "type"          => "video",
                        "provider_name" => "YouTube",
                        "width"         => 560,
                        "height"        => 315,
                        "html"          => '<iframe src="https://www.youtube.com/embed/abc" width="560" height="315"></iframe><script>alert(1)</script>',
                    ]
                ),
                "response" => ["code" => 200, "message" => "OK"],
                "cookies"  => [],
                "filename" => null,
            ];
        };
        add_filter("pre_http_request", $mock, 10, 3);
        return $mock;
    }

    /**
     * Restoring the sanitizer does not touch the editor's proxy (WEB-1222)
     *
     * The proxy returns the provider response for the editor to render inside a
     * sandboxed iframe; it does not go through oembed_dataparse. An editor must
     * still get a 200 with the embed markup.
     *
     * @return void
     */
    public function test_editor_proxy_still_serves_the_embed(): void
    {
        wp_set_current_user(self::factory()->user->create(["role" => "editor"]));
        $mock = $this->mock_provider();

        $request = new \WP_REST_Request("GET", "/oembed/1.0/proxy");
        $request->set_param("url", "https://www.youtube.com/watch?v=abc");
        $response = rest_do_request($request);
        remove_filter("pre_http_request", $mock, 10);

        $this->assertSame(200, $response->get_status(), wp_json_encode($response->get_data()));
        $this->assertStringContainsString("<iframe", $response->get_data()->html);
    }

    /**
     * Rendering an embed in content (wp_oembed_get) sanitizes provider HTML
     *
     * Core leaves trusted providers (YouTube and the like) untouched and sanitizes
     * the ones found by autodiscovery, so the provider here is not on the list.
     *
     * @return void
     */
    public function test_rendered_embed_is_sanitized_end_to_end(): void
    {
        $mock   = $this->mock_provider();
        $result = wp_oembed_get("https://unknown-provider.test/post");
        remove_filter("pre_http_request", $mock, 10);

        $this->assertIsString($result);
        $this->assertStringContainsString("<iframe", $result);
        $this->assertStringNotContainsString("<script", $result);
    }
}
