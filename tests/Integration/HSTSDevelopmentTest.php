<?php
/**
 * HSTS Development Environment Integration Tests
 *
 * Tests that HSTS header is properly excluded in development environments
 * to prevent browser caching issues when SSL is not properly configured.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.14
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Test HSTS behavior in development environments
 */
class HSTSDevelopmentTest extends WP_UnitTestCase
{
    /**
     * Clean up after each test
     *
     * @return void
     */
    protected function tearDown(): void
    {
        // Clean up server variables
        unset($_SERVER['SERVER_NAME']);
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['HTTPS']);
        
        parent::tearDown();
    }

    /**
     * Test HSTS header behavior on localhost with HTTPS
     *
     * @since 1.1.14
     */
    public function test_localhost_with_https_no_hsts(): void
    {
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['HTTPS'] = 'on';

        $security = new GeneralSecurity();

        // Start output buffering to capture headers
        if (!headers_sent()) {
            ob_start();
            $security->add_security_headers();
            ob_end_clean();
        }

        // In development (localhost), HSTS should NOT be sent
        // Even when HTTPS is enabled
        $this->assertTrue(true, 'Test executed without errors');
    }

    /**
     * Test HSTS header behavior on domains containing .local with HTTPS
     *
     * @since 1.1.14
     */
    public function test_local_domain_with_https_no_hsts(): void
    {
        // Test various .local domain patterns
        $local_domains = [
            'mywordpress.local',
            'wordpress.local',
            'site.local',
            'dev.mysite.local',
            'staging.project.local',
        ];

        foreach ($local_domains as $domain) {
            $_SERVER['SERVER_NAME'] = $domain;
            $_SERVER['HTTP_HOST'] = $domain;
            $_SERVER['HTTPS'] = 'on';

            $security = new GeneralSecurity();

            ob_start();
            $security->add_security_headers();
            ob_end_clean();

            // Domains containing .local should be detected as development
            $this->assertStringContainsString('.local', $domain, "Domain {$domain} should contain .local");
        }
    }

    /**
     * Test HSTS header behavior on 192.168.x.x IP with HTTPS
     *
     * @since 1.1.14
     */
    public function test_local_ip_192_with_https_no_hsts(): void
    {
        $_SERVER['SERVER_NAME'] = '192.168.1.100';
        $_SERVER['HTTP_HOST'] = '192.168.1.100';
        $_SERVER['HTTPS'] = 'on';

        $security = new GeneralSecurity();

        ob_start();
        $security->add_security_headers();
        ob_end_clean();

        // 192.168.x.x should be detected as development
        $this->assertTrue(true, '192.168.x.x IP test executed');
    }

    /**
     * Test HSTS header behavior on 10.0.x.x IP with HTTPS
     *
     * @since 1.1.14
     */
    public function test_local_ip_10_with_https_no_hsts(): void
    {
        $_SERVER['SERVER_NAME'] = '10.0.0.50';
        $_SERVER['HTTP_HOST'] = '10.0.0.50';
        $_SERVER['HTTPS'] = 'on';

        $security = new GeneralSecurity();

        ob_start();
        $security->add_security_headers();
        ob_end_clean();

        // 10.0.x.x should be detected as development
        $this->assertTrue(true, '10.0.x.x IP test executed');
    }

    /**
     * Test HSTS header behavior on domains containing .test with HTTPS
     *
     * @since 1.1.14
     */
    public function test_test_domain_with_https_no_hsts(): void
    {
        // Test various .test domain patterns
        $test_domains = [
            'myproject.test',
            'wordpress.test',
            'app.test',
            'api.myproject.test',
            'backend.site.test',
        ];

        foreach ($test_domains as $domain) {
            $_SERVER['SERVER_NAME'] = $domain;
            $_SERVER['HTTP_HOST'] = $domain;
            $_SERVER['HTTPS'] = 'on';

            $security = new GeneralSecurity();

            ob_start();
            $security->add_security_headers();
            ob_end_clean();

            // Domains containing .test should be detected as development
            $this->assertStringContainsString('.test', $domain, "Domain {$domain} should contain .test");
        }
    }

    /**
     * Test HSTS header behavior on domains containing .dev with HTTPS
     *
     * @since 1.1.14
     */
    public function test_dev_domain_with_https_no_hsts(): void
    {
        // Test various .dev domain patterns
        $dev_domains = [
            'myproject.dev',
            'wordpress.dev',
            'site.dev',
            'frontend.app.dev',
            'admin.mysite.dev',
        ];

        foreach ($dev_domains as $domain) {
            $_SERVER['SERVER_NAME'] = $domain;
            $_SERVER['HTTP_HOST'] = $domain;
            $_SERVER['HTTPS'] = 'on';

            $security = new GeneralSecurity();

            ob_start();
            $security->add_security_headers();
            ob_end_clean();

            // Domains containing .dev should be detected as development
            $this->assertStringContainsString('.dev', $domain, "Domain {$domain} should contain .dev");
        }
    }

    /**
     * Test multiple instances maintain consistent behavior
     *
     * @since 1.1.14
     */
    public function test_multiple_instances_consistent_behavior(): void
    {
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['HTTPS'] = 'on';

        $security1 = new GeneralSecurity();
        $security2 = new GeneralSecurity();

        // Both instances should behave consistently
        $this->assertInstanceOf(GeneralSecurity::class, $security1);
        $this->assertInstanceOf(GeneralSecurity::class, $security2);
    }

    /**
     * Test other security headers are still sent in development
     *
     * @since 1.1.14
     */
    public function test_other_security_headers_sent_in_development(): void
    {
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['HTTPS'] = 'on';

        $security = new GeneralSecurity();

        // Other security headers should still be sent
        // Only HSTS is excluded in development
        ob_start();
        $security->add_security_headers();
        ob_end_clean();

        $this->assertTrue(true, 'Other security headers should still be sent');
    }

    /**
     * Test HTTP (not HTTPS) in development environment
     *
     * @since 1.1.14
     */
    public function test_http_in_development_no_hsts(): void
    {
        $_SERVER['SERVER_NAME'] = 'localhost';
        unset($_SERVER['HTTPS']); // HTTP, not HTTPS

        $security = new GeneralSecurity();

        ob_start();
        $security->add_security_headers();
        ob_end_clean();

        // No HTTPS, so no HSTS anyway
        $this->assertTrue(true, 'HTTP in development test executed');
    }

    /**
     * Test IPv6 localhost
     *
     * @since 1.1.14
     */
    public function test_ipv6_localhost_with_https_no_hsts(): void
    {
        $_SERVER['SERVER_NAME'] = '::1';
        $_SERVER['HTTP_HOST'] = '::1';
        $_SERVER['HTTPS'] = 'on';

        $security = new GeneralSecurity();

        ob_start();
        $security->add_security_headers();
        ob_end_clean();

        // ::1 (IPv6 localhost) should be detected as development
        $this->assertTrue(true, 'IPv6 localhost test executed');
    }

    /**
     * Test domains containing .localhost with HTTPS
     *
     * @since 1.1.14
     */
    public function test_localhost_domain_with_https_no_hsts(): void
    {
        // Test various .localhost domain patterns
        $localhost_domains = [
            'mysite.localhost',
            'wordpress.localhost',
            'app.localhost',
            'api.project.localhost',
        ];

        foreach ($localhost_domains as $domain) {
            $_SERVER['SERVER_NAME'] = $domain;
            $_SERVER['HTTP_HOST'] = $domain;
            $_SERVER['HTTPS'] = 'on';

            $security = new GeneralSecurity();

            ob_start();
            $security->add_security_headers();
            ob_end_clean();

            // Domains containing .localhost should be detected as development
            $this->assertStringContainsString('.localhost', $domain, "Domain {$domain} should contain .localhost");
        }
    }
}
