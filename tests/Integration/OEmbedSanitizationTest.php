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
}
