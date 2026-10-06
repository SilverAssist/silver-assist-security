<?php
/**
 * Idle session timeout and password policy behavior tests (#150)
 *
 * Idle timeout means "no real user activity for the configured minutes". Heartbeat, REST reads
 * and other background calls do not count as activity, administrators are included, and the
 * last_activity write is throttled. The password policy covers every request path that carries
 * the plain password (profile form, reset form, REST user routes) and checks the raw value, the
 * same string WordPress stores.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\LoginSecurity;
use WP_Error;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Test the session and password behavior as a user experiences it
 */
class SessionAndPasswordPolicyTest extends WP_UnitTestCase
{
    /**
     * Original $_SERVER values
     *
     * @var array<string, mixed>
     */
    private array $original_server = [];

    /**
     * Configure a 30 minute timeout and enforced passwords
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->original_server = $_SERVER;
        \update_option("silver_assist_session_timeout", 30);
        \update_option("silver_assist_password_strength_enforcement", 1);
    }

    /**
     * Restore globals changed by a test
     *
     * @return void
     */
    protected function tearDown(): void
    {
        $_SERVER = $this->original_server;
        unset($_POST["pass1"], $_POST["action"], $_REQUEST["action"], $_GET["rest_route"]);
        $GLOBALS["wp_rest_server"] = null;
        \wp_set_current_user(0);
        parent::tearDown();
    }

    /**
     * Run setup_session_timeout() and report what it did
     *
     * @return array{redirect: ?string, user_id: int}
     */
    private function run_session_check(LoginSecurity $login): array
    {
        \add_filter(
            "wp_redirect",
            static function ($location) {
                throw new \RuntimeException("redirect:" . $location);
            },
            1
        );

        $redirect = null;
        \ob_start();
        try {
            $login->setup_session_timeout();
        } catch (\RuntimeException $e) {
            $redirect = \substr($e->getMessage(), \strlen("redirect:"));
        }
        \ob_end_clean();

        return ["redirect" => $redirect, "user_id" => \get_current_user_id()];
    }

    /**
     * Log a user in with a given idle time
     *
     * @param string $role         User role.
     * @param int    $idle_seconds Seconds since the last activity.
     * @return int User ID.
     */
    private function user_idle_for(string $role, int $idle_seconds): int
    {
        $user_id = self::factory()->user->create(["role" => $role]);
        \wp_set_current_user($user_id);
        \update_user_meta($user_id, "last_activity", \time() - $idle_seconds);
        return $user_id;
    }

    /**
     * Make the request look like an admin-ajax.php call
     *
     * @param string $action AJAX action.
     * @return void
     */
    private function pretend_admin_ajax(string $action): void
    {
        \add_filter("wp_doing_ajax", "__return_true");
        $_POST["action"]    = $action;
        $_REQUEST["action"] = $action;
        $_SERVER["REQUEST_METHOD"] = "POST";
        \set_current_screen("dashboard");
    }

    /**
     * An administrator idle for two hours is logged out on wp-admin/index.php
     *
     * @return void
     */
    public function test_idle_administrator_is_logged_out_in_wp_admin(): void
    {
        $login = new LoginSecurity();
        $this->user_idle_for("administrator", 2 * HOUR_IN_SECONDS);
        \set_current_screen("dashboard");

        $result = $this->run_session_check($login);

        $this->assertNotNull($result["redirect"], "An idle administrator is sent to the login screen");
        $this->assertStringContainsString("session_expired=1", (string) $result["redirect"]);
        $this->assertSame(0, $result["user_id"], "The session ends");
    }

    /**
     * Administrators browsing a settings page (?page=) are idle-logged-out as well
     *
     * @return void
     */
    public function test_idle_administrator_on_a_plugin_page_is_logged_out(): void
    {
        $login = new LoginSecurity();
        $this->user_idle_for("administrator", 2 * HOUR_IN_SECONDS);
        \set_current_screen("dashboard");
        $_GET["page"] = "silver-assist-security";

        $result = $this->run_session_check($login);
        unset($_GET["page"]);

        $this->assertNotNull($result["redirect"]);
    }

    /**
     * A page view by an active administrator extends the session
     *
     * @return void
     */
    public function test_page_view_extends_the_session(): void
    {
        $login   = new LoginSecurity();
        $user_id = $this->user_idle_for("administrator", 10 * MINUTE_IN_SECONDS);
        \set_current_screen("dashboard");

        $result = $this->run_session_check($login);

        $this->assertNull($result["redirect"]);
        $this->assertGreaterThan(\time() - 5, (int) \get_user_meta($user_id, "last_activity", true));
    }

    /**
     * A Heartbeat tick does not count as activity
     *
     * @return void
     */
    public function test_heartbeat_does_not_extend_the_session(): void
    {
        $login   = new LoginSecurity();
        $user_id = $this->user_idle_for("administrator", 10 * MINUTE_IN_SECONDS);
        $before  = (int) \get_user_meta($user_id, "last_activity", true);
        $this->pretend_admin_ajax("heartbeat");

        $result = $this->run_session_check($login);

        $this->assertNull($result["redirect"]);
        $this->assertSame($user_id, $result["user_id"], "Ten idle minutes is within a 30 minute timeout");
        $this->assertSame($before, (int) \get_user_meta($user_id, "last_activity", true), "Heartbeat must not refresh last_activity");
    }

    /**
     * Heartbeat from a tab left open past the timeout ends the session without a redirect
     *
     * @return void
     */
    public function test_heartbeat_after_the_timeout_ends_the_session_without_redirect(): void
    {
        $login = new LoginSecurity();
        $this->user_idle_for("administrator", 2 * HOUR_IN_SECONDS);
        $this->pretend_admin_ajax("heartbeat");

        $result = $this->run_session_check($login);

        $this->assertNull($result["redirect"], "An AJAX response is not redirected");
        $this->assertSame(0, $result["user_id"], "The open tab no longer keeps the session alive");
    }

    /**
     * A REST read (polling) does not count as activity
     *
     * @return void
     */
    public function test_rest_read_does_not_extend_the_session(): void
    {
        $login   = new LoginSecurity();
        $user_id = $this->user_idle_for("editor", 10 * MINUTE_IN_SECONDS);
        $before  = (int) \get_user_meta($user_id, "last_activity", true);
        $_SERVER["REQUEST_METHOD"] = "GET";
        $_GET["rest_route"]        = "/wp/v2/users/me";

        $this->run_session_check($login);

        $this->assertSame($before, (int) \get_user_meta($user_id, "last_activity", true));
    }

    /**
     * last_activity is not written again inside the throttle window
     *
     * @return void
     */
    public function test_activity_write_is_throttled(): void
    {
        $login   = new LoginSecurity();
        $user_id = $this->user_idle_for("editor", 10);
        $before  = (int) \get_user_meta($user_id, "last_activity", true);

        $writes = 0;
        \add_filter(
            "update_user_metadata",
            static function ($check, $object_id, $meta_key) use (&$writes) {
                if ("last_activity" === $meta_key) {
                    ++$writes;
                }
                return $check;
            },
            10,
            3
        );

        $this->run_session_check($login);
        $this->run_session_check($login);

        $this->assertSame(0, $writes, "No user meta write per request inside the throttle window");
        $this->assertSame($before, (int) \get_user_meta($user_id, "last_activity", true));
    }

    /**
     * A site can reclassify a request as background polling
     *
     * @return void
     */
    public function test_background_classification_can_be_filtered(): void
    {
        $login   = new LoginSecurity();
        $user_id = $this->user_idle_for("editor", 10 * MINUTE_IN_SECONDS);
        $before  = (int) \get_user_meta($user_id, "last_activity", true);
        \add_filter("silver_assist_security_is_background_request", "__return_true");

        $this->run_session_check($login);

        $this->assertSame($before, (int) \get_user_meta($user_id, "last_activity", true));
    }

    /**
     * REST users routes with the password policy active
     *
     * @return void
     */
    private function boot_password_policy(): void
    {
        new LoginSecurity();
        (new GeneralSecurity())->disable_user_enumeration();
        $GLOBALS["wp_rest_server"] = null;
    }

    /**
     * An editor cannot set a weak password through POST /wp/v2/users/me
     *
     * @return void
     */
    public function test_rest_users_me_rejects_a_weak_password(): void
    {
        $this->boot_password_policy();
        $user_id = self::factory()->user->create(["role" => "editor"]);
        \wp_set_current_user($user_id);
        $hash_before = \get_userdata($user_id)->user_pass;

        $request = new WP_REST_Request("POST", "/wp/v2/users/me");
        $request->set_param("password", "password");
        $response = \rest_do_request($request);

        $this->assertSame(400, $response->get_status());
        $this->assertSame("weak_password", $response->as_error()->get_error_code());
        \wp_cache_delete($user_id, "users");
        $this->assertSame($hash_before, \get_userdata($user_id)->user_pass, "The password is unchanged");
    }

    /**
     * A strong password is accepted through POST /wp/v2/users/me
     *
     * @return void
     */
    public function test_rest_users_me_accepts_a_strong_password(): void
    {
        $this->boot_password_policy();
        $user_id = self::factory()->user->create(["role" => "editor"]);
        \wp_set_current_user($user_id);

        $request = new WP_REST_Request("POST", "/wp/v2/users/me");
        $request->set_param("password", "Str0ng!Passw0rd");
        $response = \rest_do_request($request);

        $this->assertSame(200, $response->get_status());
        \wp_cache_delete($user_id, "users");
        $this->assertTrue(\wp_check_password("Str0ng!Passw0rd", \get_userdata($user_id)->user_pass, $user_id));
    }

    /**
     * An update that does not carry a password is not affected
     *
     * @return void
     */
    public function test_rest_update_without_password_is_unaffected(): void
    {
        $this->boot_password_policy();
        \wp_set_current_user(self::factory()->user->create(["role" => "editor"]));

        $request = new WP_REST_Request("POST", "/wp/v2/users/me");
        $request->set_param("description", "About me");
        $response = \rest_do_request($request);

        $this->assertSame(200, $response->get_status());
    }

    /**
     * An administrator cannot create a user with a weak password through REST
     *
     * @return void
     */
    public function test_rest_user_create_rejects_a_weak_password(): void
    {
        $this->boot_password_policy();
        \wp_set_current_user(self::factory()->user->create(["role" => "administrator"]));

        $request = new WP_REST_Request("POST", "/wp/v2/users");
        $request->set_body_params(
            [
                "username" => "weakling",
                "email"    => "weakling@example.org",
                "password" => "abc12345",
            ]
        );
        $response = \rest_do_request($request);

        $this->assertSame(400, $response->get_status());
        $this->assertFalse(\get_user_by("login", "weakling"), "No user is created");
    }

    /**
     * The policy switch also turns the REST check off
     *
     * @return void
     */
    public function test_rest_check_follows_the_enforcement_setting(): void
    {
        \update_option("silver_assist_password_strength_enforcement", 0);
        // The plugin's own instance was built with enforcement on; drop its hooks first.
        \remove_all_filters("rest_request_before_callbacks");
        $this->boot_password_policy();
        \wp_set_current_user(self::factory()->user->create(["role" => "editor"]));

        $request = new WP_REST_Request("POST", "/wp/v2/users/me");
        $request->set_param("password", "password");

        $this->assertSame(200, \rest_do_request($request)->get_status());
    }

    /**
     * The profile form check sees the raw value, not a sanitized copy
     *
     * "Abcde1<b>!</b>" is strong as stored; sanitize_text_field() strips the tags and leaves
     * "Abcde1!" (seven characters), so the old check rejected a good password.
     *
     * @return void
     */
    public function test_profile_check_validates_the_raw_password(): void
    {
        $login = new LoginSecurity();
        $user  = \get_user_by("id", self::factory()->user->create());
        $_POST["pass1"] = \wp_slash("Abcde1<b>!</b>");
        $errors = new WP_Error();

        $login->validate_password_strength($errors, true, $user);

        $this->assertFalse($errors->has_errors(), "The stored value is strong, so it must be accepted");
    }

    /**
     * The reset form check sees the raw value, not a sanitized copy
     *
     * @return void
     */
    public function test_reset_check_validates_the_raw_password(): void
    {
        $login = new LoginSecurity();
        $user  = \get_user_by("id", self::factory()->user->create());
        $_POST["pass1"] = "Abcde1<b>!</b>";
        $errors = new WP_Error();

        $login->validate_password_strength_reset($errors, $user);

        $this->assertFalse($errors->has_errors());
    }

    /**
     * A password that is weak as stored is rejected even if a sanitized copy would pass
     *
     * "Aa1<abc" is seven characters as stored; sanitize_text_field() turns the bare "<" into
     * "&lt;" (ten characters, with a "special" character), so the old check accepted it.
     *
     * @return void
     */
    public function test_profile_check_rejects_what_is_weak_as_stored(): void
    {
        $login = new LoginSecurity();
        $user  = \get_user_by("id", self::factory()->user->create());
        $_POST["pass1"] = "Aa1<abc";
        $errors = new WP_Error();

        $login->validate_password_strength($errors, true, $user);

        $this->assertSame("weak_password", $errors->get_error_code());
    }
}
