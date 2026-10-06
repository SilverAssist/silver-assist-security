<?php
/**
 * Admin Hide Routing Behavior Tests
 *
 * Which request paths admin hiding treats as the admin or login area (and therefore
 * answers with 404 to anonymous visitors), and which it leaves alone. The question a
 * visitor cares about is "does my page or form still work", so the cases below are
 * public pages and public endpoints that must not be caught (#131, part of #124).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\AdminHideSecurity;
use WP_UnitTestCase;

/**
 * Classification of request paths when admin hiding is enabled
 */
class AdminHideRoutingTest extends WP_UnitTestCase
{
    /**
     * Admin hiding instance
     *
     * @var AdminHideSecurity
     */
    private AdminHideSecurity $hide;

    /**
     * Enable admin hiding with the default path
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        \update_option("silver_assist_admin_hide_enabled", 1);
        \update_option("silver_assist_admin_hide_path", "silver-admin");
        $this->hide = new AdminHideSecurity();
    }

    /**
     * Default admin and login entry points are hidden
     *
     * @return void
     */
    public function test_default_admin_and_login_paths_are_hidden(): void
    {
        $this->assertSame("login", $this->hide->classify_request_path("wp-login.php"));
        $this->assertSame("admin", $this->hide->classify_request_path("wp-admin"));
        $this->assertSame("admin", $this->hide->classify_request_path("wp-admin/index.php"));
        $this->assertSame("admin", $this->hide->classify_request_path("wp-admin/plugins.php"));
        $this->assertSame("custom", $this->hide->classify_request_path("silver-admin"));
    }

    /**
     * A public page whose slug merely starts with "wp-admin" is not the admin area
     *
     * The old prefix match returned 404 to anonymous visitors for pages such as
     * /wp-admin-guide/ or /wp-admin-tips/.
     *
     * @return void
     */
    public function test_public_slug_starting_with_wp_admin_is_not_hidden(): void
    {
        $this->assertSame("none", $this->hide->classify_request_path("wp-admin-guide"));
        $this->assertSame("none", $this->hide->classify_request_path("wp-admin-tips/step-1"));
    }

    /**
     * The public form endpoint under wp-admin stays reachable
     *
     * admin-post.php is the front-end form target for admin_post_nopriv_* handlers, like
     * admin-ajax.php (which is already exempt). Anonymous visitors got a 404 for any form
     * that posts there.
     *
     * @return void
     */
    public function test_admin_post_endpoint_is_not_hidden(): void
    {
        $this->assertSame("none", $this->hide->classify_request_path("wp-admin/admin-post.php"));
        $this->assertSame("admin", $this->hide->classify_request_path("wp-admin/admin.php"), "Other wp-admin files stay hidden");
    }

    /**
     * Ordinary front-end pages are never classified as admin
     *
     * @return void
     */
    public function test_front_end_pages_are_not_hidden(): void
    {
        $this->assertSame("none", $this->hide->classify_request_path(""));
        $this->assertSame("none", $this->hide->classify_request_path("about-us"));
        $this->assertSame("none", $this->hide->classify_request_path("blog/wp-login-problems-fixed"));
        $this->assertSame("none", $this->hide->classify_request_path("wp-json/wp/v2/posts"));
        $this->assertSame("none", $this->hide->classify_request_path("wp-cron.php"));
    }

    /**
     * The email change confirmation link keeps its token as plain text
     *
     * Core builds the link with esc_url(), which writes the second query parameter after an
     * "&#038;" entity. Plain-text email shows that entity literally, so the browser read
     * "#038;silver_auth=..." as a fragment, the token never reached the server and the
     * person who clicked the link got a 404 instead of the login screen.
     *
     * @return void
     */
    public function test_email_change_link_in_the_email_keeps_a_working_token(): void
    {
        require_once ABSPATH . "wp-admin/includes/user.php";

        $user_id = self::factory()->user->create(["role" => "editor", "user_email" => "old@example.test"]);
        \wp_set_current_user($user_id);

        $sent = [];
        \add_filter(
            "pre_wp_mail",
            static function ($return, $atts) use (&$sent) {
                $sent[] = $atts;
                return true;
            },
            10,
            2
        );

        $_POST["user_id"] = (string) $user_id;
        $_POST["email"]   = "new@example.test";
        \send_confirmation_on_profile_email();

        $this->assertNotEmpty($sent, "Core sends the confirmation email");
        $message = (string) $sent[0]["message"];

        $this->assertMatchesRegularExpression(
            '~/wp-admin/profile\.php\?newuseremail=[0-9a-f]+&silver_auth=silver-admin~',
            $message,
            "The link in the email is clickable as written: a plain ampersand before the token"
        );
        $this->assertStringNotContainsString("&#038;", $message);
    }
}
