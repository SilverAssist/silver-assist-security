# Changelog

All notable changes to Silver Assist Security Essentials will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **oEmbed provider HTML is sanitized again (#129)**: the plugin removed core's `wp_filter_oembed_result` from `oembed_dataparse`, the filter that restricts provider HTML to safe markup (iframes, blockquotes). Without it, a hostile or compromised provider (one found by autodiscovery; core leaves its built-in trusted providers untouched) could inject `<script>` or event-handler markup into a post. No hardening goal needed the removal, so the filter is no longer removed.
- **Client IP can no longer be chosen with request headers (#128)**: `SecurityHelper::get_client_ip()` checked `HTTP_CLIENT_IP`, `X-Forwarded-For` and similar headers before `REMOTE_ADDR` and returned the first public value, so a client could rotate a forged header to escape login lockout, the IP blacklist, form protection and the GraphQL rate limit. It now starts from `REMOTE_ADDR` and reads only `X-Forwarded-For`, only from a trusted proxy, right to left. `Client-IP`, `CF-Connecting-IP` and `X-Real-IP` are never read.
- One implementation for every component: `GraphQLSecurity` had its own copy of the vulnerable logic and `RestAPISecurity` its own trusted-proxy logic; both now delegate to `SecurityHelper`.
- **Behavior change**: when no proxy CIDRs are declared, a connecting peer in a private or reserved range (an internal load balancer such as an ALB) is trusted and the last `X-Forwarded-For` entry (the one the balancer appended) is used; no hop is skipped in this mode, and an entry that cannot be validated (after accepting `ip:port` and `[ipv6]:port`) falls back to the peer address. Known limit: a client that reaches the origin directly from a private network can still choose its identity until CIDRs are declared. This also fixes sites behind a load balancer sharing one REST rate-limit bucket for all anonymous traffic. Declare `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` for CDN setups, or return `false` from `silver_assist_trust_private_proxies` to ignore forwarded headers until you do. See the README section "Proxies, Load Balancers and CDNs".
- **GraphQL rate limit never ran (#132)**: `GraphQLSecurity` hooked a `graphql_request` action that WPGraphQL does not fire, so the per-IP limit was dead code. It now runs on `do_graphql_request`. Authenticated requests (API key, application password, session) are not counted, and the counter is the atomic fixed-window counter the REST limiter uses (now `SecurityHelper::increment_rate_window()`), keyed by the hashed IP (it was a literal `{md5($ip)}` string holding the raw IP). **Behavior change**: anonymous GraphQL traffic is now throttled as documented (60 per minute, 120 in headless mode, plus 10 per batch slot WPGraphQL allows). A headless server that calls without credentials from one IP is throttled; send the API key.
- **Batched GraphQL queries skipped the query checks (#132)**: `graphql_request_data` receives a list for a batch, and only a single operation was validated, so alias, depth, directive, length and introspection checks were bypassed by sending the same query in a batch. Every operation of a batch is now validated.
- **GraphQL complexity limit never triggered (#132)**: the rule was registered under the `DocumentNode` visitor key (graphql-php matches `Document`) and measured the JSON form of the AST instead of the query text. It now runs and counts the query as documented. **Behavior change**: a query above 100 (200 in headless mode) is now rejected.
- **Introspection protection ignored the real environment (#132)**: it only acted when the `WP_ENVIRONMENT_TYPE` constant was defined as `production`, while WordPress treats an unset environment as production and the authentication bypass already followed `wp_get_environment_type()`. All GraphQL environment checks now use `wp_get_environment_type()`. **Behavior change**: sites that set nothing now block introspection (`__schema`, `__type`) like production; set `WP_ENVIRONMENT_TYPE` to `staging`, `development` or `local` where tooling needs it.
- **API key authenticated any URL containing `/graphql` (#132)**: a valid key sent to, for example, `/wp-json/wp/v2/users/me?next=/graphql` logged the client in as the service user on REST. It now authenticates only requests to the GraphQL endpoint as WPGraphQL defines it, which also makes the key work on a custom endpoint path.
- **The attempt that triggered a lockout revealed whether the username exists (#131)**: an IP is locked out in the same request that renders its fifth failed login, and the error filter left every message untouched while locked out, so that last error ("The password you entered for the username admin is incorrect" or "Unknown username") escaped the generic message. Only the lockout notice is left readable now.
- **Idle session timeout now means what it says (#150)**: administrators were never idle-logged-out inside wp-admin (the condition exempted anyone who can activate plugins), every logged-in request including REST, admin-ajax and Heartbeat refreshed `last_activity` so an open tab never went idle, and user meta was written on every request. Administrators are now included, only foreground requests (page views, form posts, REST writes) count as activity (Heartbeat, REST reads and admin-ajax reads do not; filter `silver_assist_security_is_background_request`), AJAX and REST requests past the limit are logged out without a redirect, and the write is throttled to once a minute. The auth cookie still lasts exactly the timeout from login and is not renewed, so a session also ends that long after login; the README documents it.
- **Password policy reaches the REST user routes and checks the stored value (#150)**: a weak password was accepted through `POST /wp/v2/users` and `/wp/v2/users/{id|me}`; these now answer 400 `weak_password` (via `rest_request_before_callbacks`, because core ignores an error returned from `rest_pre_insert_user`). The profile and reset checks ran `sanitize_text_field()` on the password, so the checked string differed from the stored one (`Aa1<abc`, seven characters, passed as ten); they now check the raw value. Not covered, documented in the README: WP-CLI, `wp_insert_user()` and `wp_set_password()`.
- **GraphQL responses carried none of the baseline security headers (#152)**: WPGraphQL answers on `parse_request` and exits before `send_headers`, so neither `GraphQLSecurity::add_graphql_security_headers` nor `GeneralSecurity::add_security_headers` ever ran for a GraphQL response. The baseline headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS on SSL, as filtered by `silver_assist_security_headers`) are now added through WPGraphQL's `graphql_response_headers_to_send` filter, on any endpoint path, without overriding headers WPGraphQL or another filter already set. The `send_headers` callback matched the substring `/graphql` (it would have framed `/graphql-guide/` and missed a custom endpoint) and was removed.
- **Validation errors no longer allow the query (#152)**: the depth, alias, directive and field duplicate checks caught `\Exception` and returned no errors, so a failure while checking let the query through, and a `\Error` such as a `TypeError` was not caught at all. They now catch `\Throwable` and reject the query.
- **Removed dead introspection hooks (#152)**: `graphql_introspection_enabled`, `graphql_show_in_graphiql` and the removal of `WPGraphQL\Type\Introspection::register_introspection_fields` do not exist in WPGraphQL 2.23.1 and did nothing. Production introspection stays blocked by the plugin's `validate_single_operation` and WPGraphQL's `DisableIntrospection` rule.

- **Limiters work with a persistent object cache (#149)**: the blocked-IP list, count and blacklist statistics scanned `_transient_*` rows of `wp_options`, which a Redis object cache never writes, so they were empty; the lockout message read `_transient_timeout_lockout_*` directly and said "Try again in 0 minutes." A companion `lockout_until_*` transient now holds the time the lockout ends, and blocks are listed from a small non-autoloaded index option (`silver_assist_ip_blacklist_index`, at most 1000 entries, pruned on write and by the daily cleanup; blocks already in the options table are imported on first read; removed on uninstall). Cleanup skips the options-table scans when an object cache is active.
- **Failed logins are counted atomically (#149)**: parallel failed logins read, incremented and wrote the count back, so simultaneous attempts overwrote each other and could stay under the limit. The counter is now `SecurityHelper::increment_rate_window()`. **Behavior change**: the failures are counted in a fixed window that opens at the first failure and lasts the lockout duration, instead of being renewed by each failure.
- **Login-page limit is a fixed window (#149)**: every request renewed the one-minute expiry, so a monitor hitting `wp-login.php` once a minute was blocked after 16 requests. The window now opens at the first request and ends a minute later.
- **Failed logins no longer count as bot activity, and fewer real devices look like bots (#149)**: `track_bot_behavior` was hooked on `wp_login_failed`, so ordinary typos filled the bot log; it now runs only for requests actually turned away as bots. The `extended_bot_block_*` flag, written after four bot entries but never read, was removed (enforcing a two-hour block on a shared IP is heavier than the 404 plus the per-minute limit). User agents are matched by whole word: `bot`, `scan`, `probe`, `php`, `perl`, `java`, `curl`, `wget` and `python` no longer match inside names such as CUBOT phones, while `Googlebot`, `python-requests`, `Java/17` and `libwww-perl` still do. One list now serves `block_suspicious_bots` and `SecurityHelper::is_bot_request()`. A failed `secure_login_nonce` is still only logged, on purpose (documented, not changed): login pages are often page-cached, so enforcing the nonce would lock out real users.
- **IPv6 clients are limited by /64 (#149)**: every limiter keyed on the exact address, so an attacker with a /64 had effectively unlimited identities. Lockout, login-page limit, blacklist and violation keys, form protection and the REST and GraphQL limits now key on the /64 prefix (an IPv4-mapped address on its IPv4 address). **Behavior change**: blocking or locking out one IPv6 address covers its /64; filter `silver_assist_security_ipv6_prefix_length` (default 64, 128 keeps the exact address). IPv4 is unchanged. See the README section "Proxies, Load Balancers and CDNs".

### Added

- Tests (#149): `LimiterRobustnessTest` (persistent object cache simulation, parallel failure counting, spaced login-page requests, bot signals and user agents, IPv6 prefix).
- Tests (#146): `FormSubmissionBehaviorTest::test_rapid_fire_submits_hit_rate_limit_then_blacklist_and_the_block_expires` (submits within seconds from one IP hit the form rate limit, then the blacklist, and the block ends after its duration) and `IPProtectionScopeTest` (a blacklisted IP can still log in and reach REST, a login lockout does not block the forms, the dashboard and IP Management strings name the protection they belong to).
- Tests (#148): `DashboardFiguresTest` (an auto-blacklisted IP shows its real expiry and violations, real failed logins, lockouts and blacklist blocks are counted, periods and retention, admin hide inactive when off, a statistics poll writes no transient).
- Settings registry and saver (#159): `SettingsRegistry` declares every option the settings screen saves (section, type, range, whether it has a field, whether auto-save may write it) and `SettingsSaver::save( $input, $section, $mode )` is the only code that unslashes, sanitizes, clamps and writes them. `SettingsHandler` (Save buttons) and `SecurityAjaxHandler::auto_save()` both delegate to it and report what was saved, adjusted (submitted and stored value), rejected and ignored through `SaveResult`. Behavior is kept: the same auto-save set and the same ranges.
- Tests (#159): `SettingsSaverTest`, `SettingsRegistryTest` (defaults, rendered fields inside their own section's form, auto-save set) and `SettingsFormsTest`, which renders every tab, parses the HTML and posts each form's own fields, so a Save button that persists nothing fails the suite. An E2E spec edits a field on the Login Protection and IP Management tabs, clicks Save, reloads and reads it back.
- Tests (#147): `IPBlacklistSettingsTest` (the toggle and threshold change the blacklist's behavior, manual blocks survive, the dashboard reports the real default, a save does not touch options without a field).
- The E2E workflow builds the minified assets (`npm run build`) before starting wp-env: the plugin loads `assets/**/*.min.*` unless `SCRIPT_DEBUG` is on, those files are git-ignored, and without them the admin screens loaded no CSS or JavaScript in CI (#156).
- Tests (#156): `SettingsTabStructureTest` (every settings card is inside one tab panel, the branding card is inside the Login Protection panel) and an E2E spec that clicks through every tab of the settings screen (`tests/e2e/admin-settings.spec.ts`).
- Updater tests (#145): the metadata must equal the plugin header, the configured token constant is `SILVER_GITHUB_TOKEN`, and a configured token is sent to `api.github.com` (private-repo updates). Two older tests that compared a literal with itself were replaced by these.
- Behavior-test (TDD) policy (#134) in the README and `.github/copilot-instructions.md`, with a short guide to adding an integration and an E2E behavior test, and a pull request template (`.github/pull_request_template.md`) whose checklist asks that tests assert user-visible behavior and that a bug fix test fails before the fix.
- Behavior audit matrix (#130): the "Behavior Audit Matrix" section of `.github/copilot-instructions.md` lists every hook, removal, cron event, AJAX action, constant and extension filter the plugin registers (81 hook names under `src/` and the bootstrap), with the core behavior touched, the contexts affected, the risk and the test that covers it, plus a gaps list with a proposed test for each and four suspected bugs found while auditing (not fixed here). README points to it from Development & Testing.
- Tests: `OEmbedSanitizationTest` (the core sanitizer stays registered, hostile provider HTML is stripped end to end, a provider iframe is kept, and the editor's `/oembed/1.0/proxy` still serves the embed) and an E2E check that the editor Embed block can be inserted and reaches the oEmbed proxy.
- Tests: `ClientIpResolutionTest` (forged headers, rotation, private and configured proxies, IPv6, parity across components) and a login-lockout test that rotates forged headers.
- General hardening and forms audit (#133): `GeneralHardeningBehaviorTest` (headers per request context, HSTS, cookies, `wp_head`, XML-RPC, login messages, admin bar) and `FormSubmissionBehaviorTest` (real CF7 submit passes, bot, flood and injection are blocked, realistic enquiries are not).
- Filters: `silver_assist_security_headers`, `silver_assist_security_is_development_environment`, `silver_assist_security_disable_xmlrpc`, `silver_assist_security_remove_feed_links`, `silver_assist_security_cf7_spam_patterns` and `silver_assist_security_sql_injection_patterns`, so a site can keep a header, XML-RPC or feed discovery that an integration needs. Documented in the README.
- Behavior tests for headless clients (#132): `RestAPIHeadlessBehaviorTest` (rate limit boundary, 429 shape, logged-in and application password bypass, shared IP, batch endpoint) and `GraphQLHeadlessBehaviorTest` (authentication, API key through `X-API-Key` and Bearer, application passwords, introspection per environment, limits, rate limit), run through `rest_do_request()` and WPGraphQL's `graphql()`. Shared helpers in `tests/Helpers/HeadlessTestSupport.php`.
- `silver_assist_security_environment_type` filter to override the environment type the GraphQL protections use (`wp_get_environment_type()` has no filter and caches its first answer).
- README section "Headless Clients: REST and GraphQL" documenting the limits and how to tune them.
- Login and admin hiding behavior (#131): `LoginLockoutBehaviorTest` (shared IP, lockout lifetime, thresholds, session redirect with admin hiding) and `AdminHideRoutingTest` (which paths admin hiding treats as admin, the email change link). Playwright specs with admin hiding enabled in `tests/e2e/admin-hide/` (`npm run test:e2e:admin-hide`, smoke subset `npm run test:e2e:admin-hide:smoke`) cover the `/silver-admin` flow, 404s without a session, login, logout, password reset and email change links, `admin-ajax.php`, `admin-post.php`, REST with cookie auth, update screens, WP-Cron, lockout and unlock, session timeout and password rules.
- README section "Login Protection and Admin Hiding Behind a Shared IP" documenting the thresholds.

### Fixed

- **Deactivation and uninstall left data behind (#151)**: the `silver_assist_security_cleanup` cron event was never unscheduled (now cleared on deactivate and uninstall), and uninstall removed only the `DefaultConfig` options and two transient prefixes. It now also removes the legacy `silver_assist_ip_violation_threshold` option, every transient family the plugin writes (`ip_blacklist_*`, `ip_violations_*`, `lockout_*`, `login_attempts_*`, `login_access_*`, `bot_activity_*`, `extended_bot_block_*`, `cf7_total_attacks`, `graphql_rate_*`, `bot_blocks_count_*`, form rate keys, the updater caches), their timeout rows, and the `last_activity` user meta. Activation reads only user IDs when it looks for sessions (it loaded every user row with a session). Form rate limit keys were built with the IP and the prefix swapped (`{ip}_{md5}`); they are now `form_rate_{md5(ip)}`, and uninstall also removes the old shape.
- Multisite is documented as not supported or tested (single-site installs only) in the README and `.github/copilot-instructions.md`; no multisite code is planned (#151).
- **Five Save buttons persisted nothing (#159)**: the Login settings, Admin Hide, GraphQL settings, Contact Form 7 and IP forms posted neither the hidden `save_silver_assist_security` field nor a nonce under the name the handler verifies (`_wpnonce`), so the handler returned early; only auto-save saved anything. Every form now posts the gate field, its `settings_section` and `_wpnonce`, and maps to exactly one section.
- Auto-save no longer claims success when it saved nothing (#159): fields outside its set (REST API, branding, GraphQL authentication, the CF7 rate limit, the GraphQL query timeout, the admin path) were silently dropped behind a "settings auto-saved" message. It now answers with `saved_count`, `saved`, `adjusted`, `errors` and `ignored`, and the indicator shows "Nothing was saved" for 0. The indicator also shows the error text PHP sends (`data.error`).
- Saving a settings form without a section now writes nothing and shows an error notice; the unreachable "save everything" branch was removed. The GraphQL query timeout, the CF7 rate limit and the GraphQL query depth and complexity are now saved by the Save buttons of their sections.
- An invalid or empty admin path is no longer replaced silently: the save shows a notice that lists the adjusted values, and the fallback is reported by the saver (#159).
- The settings screen no longer repeats `id="submit"` four times (and `id="_wpnonce"` on every form): each Save button and nonce field has an id of its own (#159).
- The GraphQL query timeout is capped at 30 seconds when PHP has no execution limit (`max_execution_time` 0); it used to fall to 1 second (#159).
- The "IP Blacklist" toggle in IP Management now works (#147). Nothing read it: automatic blacklisting was always on while the dashboard showed it as Disabled. Automatic blacklisting is on by default and stops when the toggle is off; manual blocks still apply.
- The violation threshold is a control on the IP Management tab ("Violations Before Blacklisting", 3 to 20, saved by auto-save) and is the value the blacklist uses (`silver_assist_ip_blacklist_threshold`). The settings handler saved it as `silver_assist_ip_violation_threshold`, which nothing read; a value already stored under that old name is still honored until the new option is saved.
- The "Contact Form 7 protection" toggle can be saved by auto-save: it was missing from the auto-save toggle list, so it could not be switched off from the screen.
- Saving settings no longer writes options its form does not carry (#147): a save without the field left the CF7 honeypot, CF7 protection and the IP Blacklist toggle switched off. The CF7 timing, obsolete browser and SQL injection options were saved but never read (those checks always run) and are no longer written.
- The "Login Page Branding" card is shown only on the Login Protection tab (#156). It was rendered after the closing tag of that tab's panel, so the tab script (which toggles only `.silver-tab-content`) never hid it and it appeared under every tab.
- Updater metadata no longer contradicts the plugin (#145): `Updater` hard-coded `requires_php` 8.3 (and `requires_wordpress` 6.5) while the plugin runs on PHP 8.2, so WordPress refused the update on PHP 8.2 hosts and the plugin-information modal showed 8.3. Both values are now read from the plugin header (`Requires PHP`, `Requires at least`). `Tested up to` is now 7.1 (the suite runs on 7.1.2 and CI runs the latest WordPress).
- **`__typename` was rejected in production (#132)**: the introspection check matched `__typename`, which Apollo Client and urql add to every query, so headless front ends would have broken once the environment check above applied. Only `__schema` and `__type` field selections count as introspection now, found by parsing the query, so the same text in a string argument or comment is allowed.
- Test suite: a full `vendor/bin/phpunit` run no longer stops early (it reported about 178 of 511 tests with exit code 0). `LoginSecurityTest::test_session_timeout_in_admin_area` now intercepts the redirect before the plugin's `exit`, and `AdminHideSecurityTest` uses the `wp_doing_ajax` filter instead of defining `DOING_AJAX`, which leaked into every later test.
- `LoginBrandingTest::test_custom_bg_color_applied` asserted that the footer contains no `style=`, but the SVG illustration carries its own; it now asserts the configured color is not inlined.
- `GraphQLConfigManagerTest::test_security_level_no_double_counting_auth` compared scenarios that are not equivalent (headless mode does not restrict the endpoint); it now measures the score directly. It was previously always skipped locally.
- `UpdaterIntegrationTest::test_updater_php_requirements` required PHP 8.3 while the plugin (header and `composer.json`) and the whole CI matrix are on PHP 8.2, so it failed in CI and passed on newer local PHP. It now reads the minimum from the plugin header. CI had not noticed because failing tests did not fail `run-quality-checks.sh` (see Changed). `.github/copilot-instructions.md` listed PHP 8.3+ and now says 8.2+.
- `LoginSecurityTest::test_session_timeout` (unit) made no assertions because the timeout was changed after the object was built; it now verifies the silent front-end logout.
- **Security headers were missing outside the front end (#133)**: they were sent only on `send_headers`, which wp-admin, `wp-login.php` and REST responses never fire, so `Referrer-Policy`, `Permissions-Policy` and HSTS were absent there. They are now sent from `admin_init`, `login_init` and before a REST response is served.
- **A locked-out visitor was told the credentials were invalid (#133)**: the `login_errors` filter replaced every message on every `wp-login.php` screen with "Invalid login credentials.", hiding the lockout notice and core's password reset messages ("passwords do not match", "link expired"). Only the login and lost-password screens are generic now, and not during a lockout.
- **Logged-in cookie dropped on a site with an http home URL (#133)**: `secure_logged_in_cookie` was forced to Secure whenever the request was SSL, ignoring core's rule that it is Secure only when the home URL is https. The core value is now respected (still never Secure over plain HTTP).
- **Real enquiries rejected by the form filters (#133)**: a bare `--` or `/*` counted as SQL injection, and `make $`, `earn $` and `win $` counted as spam, so a family writing "we make $3,200 a month" was blocked and counted toward an IP blacklist. SQL comment markers now count only after a quote and the three money patterns are gone. Contact Form 7 checkbox fields (arrays) no longer raise "Array to string conversion". The excessive-capitals rule lowercased the text before counting capitals, so it never fired; it now works as documented (more than 70% capitals in text over 50 characters), which means shouting in all caps can now be rejected.
- **Lockout counted every failed login twice (#131)**: `SecurityDataProvider` built its own `LoginSecurity`, `GeneralSecurity` and `AdminHideSecurity` instead of using the shared instances, so the admin panel (loaded on every request) registered all their hooks a second time. With the default of 5 attempts, an IP was locked out after the third failure, and the login page rate limit (15 requests per minute) triggered at the ninth request. The login form also carried duplicate nonce and honeypot fields. The data provider now uses the shared instances.
- **A locked-out visitor who kept trying was never let back in (#131)**: core fires `wp_login_failed` for the lockout error itself, which renewed the lockout, so the "try again in 15 minutes" message was never true while the person (or an attacker sharing the IP) retried. Attempts during a lockout no longer extend it.
- **Public forms posting to `wp-admin/admin-post.php` got a 404 with admin hiding on (#131)**: `admin_post_nopriv_*` handlers are the front-end counterpart of `admin-ajax.php`, which was already exempt. A public page whose slug starts with `wp-admin` (for example `/wp-admin-guide/`) was also hidden; only the `wp-admin` path itself is now.
- **Email change confirmation link returned 404 with admin hiding on (#131)**: core writes the link with `esc_url()`, which turns the `&` before the plugin's access token into `&#038;`; plain text mail shows that literally and the browser read the token as a URL fragment. The entity is replaced in the outgoing message.
- **Expired session redirect had a malformed URL with admin hiding on (#131)**: `?session_expired=1` was appended to a login URL that already had a query string, corrupting the access token. A visitor without the one-hour admin access cookie (session timeouts go up to 120 minutes) got a 404 instead of the login screen.
- The 16th login page request in a minute from one IP is now the first one blocked (the 17th was, despite the documented limit of 15). The per-IP counters for the login page and bot activity were also keyed with a literal `{md5($ip)}`; they now use a real hash like the other transients, and `LoginSecurityTest` asserts the stored values instead of tolerating their absence.
- **Dashboard figures matched nothing real (#148)**: blacklist records store `timestamp` and `duration` but the dashboard read `blocked_at` and `expires`, so every blocked IP showed "blocked now, 15 minutes left" and `violations` was an array cast to 1. It now shows the real expiry and the violation count. The "Admin Security" card read the option `silver_assist_admin_path`, which does not exist, so it always reported active and inflated the score; it now follows `silver_assist_admin_hide_enabled`.
- **Statistics were always 0 or depended on `WP_DEBUG` (#148)**: failed logins compared an attempt count with a Unix timestamp, blocked IPs read the wrong field, and bot blocks were parsed from log files that exist only with debug logging (with `debug.log` possibly read twice through two paths). Each poll also wrote a new transient, because the cache key contained the current second. The 24 hours, 7 days and 30 days figures now come from `SecurityEventCounter`, hourly buckets in one non-autoloaded option (`silver_assist_security_event_counts`) holding at most 30 days, incremented on a failed login, a login lockout, a blacklist block and a bot block. Polling writes nothing and reads no log. Figures start at zero after upgrading and the period boundary has one-hour resolution. The security log viewer lists each log file once.

### Changed

- The IP blacklist is named and documented for what it is, the Contact Form 7 form flood protection (#146). It was never meant to block login, and no code path used it for that (`ContactForm7Integration` is its only caller); the labels said otherwise. IP Management now reads "Form Flood Protection (Contact Form 7)", the toggle is "Form Flood Blacklist" (was "IP Blacklist"), the list that was headed "Login Security - Blocked IPs" is headed "Form Flood Blacklist - Blocked IPs" (it always listed the blacklist, never login lockouts), and the manual block text no longer says blocked IPs are denied access to login (it blocks the forms for 30 days). The dashboard's Login Security card now shows "Locked-out IPs", the number of IPs currently locked out of the login (it showed the blacklist count under the label "Blocked IPs"), and "Form Flood Blocked IPs" moved to the Form Protection card and the statistics. README has a "Two IP Protections" section that compares them and records the decision to keep the two implementations separate (shared logic stays in `SecurityHelper`).
- `EditorCompatibilityTest` now sends real REST requests as the role that uses each route and asserts the editor is not refused (it only checked that the route existed in the route table); the anonymous oEmbed check requests the route and expects `rest_no_route`. Re-adding the WEB-1222 `wp_oembed_register_route` removal makes it fail (#134).
- Tests that asserted the old behavior (`CF-Connecting-IP` winning, first `X-Forwarded-For` value winning) now assert the new contract.
- `scripts/run-quality-checks.sh` runs PHPUnit through the new `scripts/run-phpunit-complete.sh`, which fails when the run stops early (JUnit log missing or incomplete; for a full run, fewer tests than PHPUnit declares). It also fixes a blind spot: `run_phpunit` runs on the left of `||`, where bash disables `set -e`, so a failing test left the script at exit 0 and CI could not fail on broken tests; the status is now returned explicitly.
- `RestAPISecurityIntegrationTest::test_graphql_endpoints_not_affected` (quarantined, wrong premise) is replaced by `RestAPIHeadlessBehaviorTest::test_graphql_requests_do_not_consume_the_rest_budget`, which sends real GraphQL requests (#132).
- GraphQL tests no longer skip in CI: a missing WPGraphQL fails when `CI` is set, and the local/development-only authentication tests set the environment explicitly instead of skipping. Tests no longer define `WP_ENVIRONMENT_TYPE`, which leaked into every later test.
- README: local setup now lists the WPGraphQL and Contact Form 7 installers used by CI.

## [1.5.3] - 2026-10-05

### Fixed

- **Block editor `TypeError: _ is not a function` (WEB-1222)**: `?ver=` is no longer stripped from assets in wp-admin, during AJAX requests, or from WordPress core bundles (`/wp-includes/`, `/wp-admin/`). Without the cache-buster a browser or CDN could serve a stale `data.min.js` next to a newer `editor.min.js` after a core update. Front-end theme and plugin assets keep the existing version hiding. Core assets on the front end now keep `ver=` (this exposes the WordPress version through those URLs; use the new filter below if that trade-off is not acceptable).
- `/wp/v2/users` is now available to logged-in users who can edit posts (the block editor needs it). Anonymous and low-privilege users still get no users route.
- The block editor Embed block works again: the plugin no longer removes `wp_oembed_register_route`, which also registers `/oembed/1.0/proxy`. Only the public `/oembed/1.0/embed` route is hidden, for users who cannot edit posts.

### Added

- `silver_assist_security_strip_asset_version` filter to keep (or force removal of) `ver=` per asset.
- Behavior tests for core compatibility (`tests/Integration/AssetVersioningTest.php`, `RestUsersEndpointTest.php`, `EditorCompatibilityTest.php`).
- Playwright E2E suite on `@wordpress/env` (`tests/e2e/`), with `npm run wp-env:start`, `npm run test:e2e` and `npm run test:e2e:smoke`, and a `.github/workflows/e2e.yml` workflow (smoke on pull requests, full nightly).

### Changed

- `GeneralSecurityTest::test_version_query_string_removed` now uses a plugin asset; it previously asserted that core scripts lose `ver=`.

## [1.5.2] - 2026-09-25

### Changed

- Requires `silverassist/wp-github-updater` `^1.4`, which can read the releases of a private GitHub repository with a token (the `SILVER_GITHUB_TOKEN` constant or environment variable). Sites keep updating from a public repository without a token.
- Declared Composer `vcs` repositories (with `"no-api": true`) for the SilverAssist packages in `composer.json`, so `composer install` resolves them from GitHub instead of Packagist.org. `no-api` makes Composer read tags with git instead of the GitHub API, which otherwise spends about 100 requests of the token's hourly quota per install.
- The workflows pass the `COMPOSER_AUTH` secret to `composer install`, because those repositories can require authentication.

### Documentation

- README: new section "Composer authentication (private packages)".

## [1.5.1] - 2026-08-13

### 🏗️ Changed

- **Migrated to `silverassist/wp-plugin-kernel`**: adopted the shared `AbstractPlugin`/`LoadableInterface` bootstrap pattern used across the Silver Assist plugin portfolio. `LoginSecurity`, `GeneralSecurity`, `RestAPISecurity`, `LoginBranding`, `AdminHideSecurity`, `GraphQLSecurity`, `ContactForm7Integration`, and `AdminPanel` now implement `LoadableInterface` and expose a singleton `instance()`; existing public constructors are unchanged, so direct `new` construction (used throughout the test suite) still works exactly as before.
- **Three loading tiers, not one**: this plugin has genuine cross-component hook-timing requirements a single bootstrap hook can't serve — brute-force/login protection needs `plugins_loaded` priority 1 (wp-login.php acts before `init`), GraphQL API-key authentication needs `plugins_loaded` priority 5 (before WordPress resolves the current user, but after WPGraphQL defines its class), and everything else loads on `init`. Introduced `Core\SecurityLoader` and `GraphQL\GraphQLLoader` — both `AbstractPlugin` subclasses — alongside the plugin root (`Core\Plugin`) to preserve these exact pre-existing timings.
- **Extracted `Core\Activator`**: activation/deactivation/uninstall logic moved out of the main plugin file's `SilverAssistSecurityBootstrap` class (removed) into a dedicated static class, registered directly against `register_activation_hook()` / `register_deactivation_hook()` / `register_uninstall_hook()`.
- **Removed the hand-rolled `spl_autoload_register` PSR-4 autoloader** from the main plugin file — it duplicated `composer.json`'s own `SilverAssist\Security\` → `src/` PSR-4 mapping and didn't cover the plugin's Composer dependencies anyway, so it provided no real vendor-less-distribution fallback.
- `ContactForm7Integration` now checks `SecurityHelper::is_contact_form_7_active()` internally (not just the `silver_assist_cf7_protection_enabled` option) before registering its hooks or constructing its sub-components — previously this was only enforced by the caller (`Plugin::init_cf7_integration()`), which every other construction path skipped.
- The main plugin file shrank from a ~280-line file with an embedded bootstrap class to a ~110-line file that only defines constants, loads the Composer autoloader, and wires the three bootstrap hooks.

### ✅ Tests

- Fixed three tests still referencing the removed `SilverAssistSecurityBootstrap` class to call `Core\Activator` directly.
- Fixed singleton-reset reflection in `RestAPISecurityIntegrationTest` to target the new per-class `$instance` property (previously reflected on `Core\Plugin`, whose singleton storage now lives on `AbstractPlugin`).

## [1.5.0] - 2026-08-09

### 🔒 Security

- **REST API Batch Endpoint Protection**: Block unauthenticated requests to `/batch/v1` endpoint with 403 Forbidden response, preventing WP2Shell pre-auth RCE entry point (CVE-2026-60137 + CVE-2026-63030)
- **REST API Rate Limiting**: Limit unauthenticated REST API requests to 100 per 60 seconds per IP address using WordPress transients for stateless, scalable protection
- **Proxy-Aware IP Detection**: Trust `X-Forwarded-For` only when `REMOTE_ADDR` matches a proxy CIDR declared via the `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` constant (or the filter of the same name), and parse the chain right-to-left so trusted hops (AWS CloudFront edges, ALB private ranges) are discarded and only the real client address is used
- **Atomic Rate-Limit Counter**: Fixed-window counter initialized via `wp_cache_add` on persistent object caches and `INSERT IGNORE` + `UPDATE ... value + 1` on the transient row otherwise, closing the flood-bypass race at every window boundary

### ✨ Added

- New `RestAPISecurity` class for centralized REST API batch endpoint and rate limiting protection
- Configuration options in `DefaultConfig`:
  - `silver_assist_rest_batch_endpoint_protection` (enabled by default)
  - `silver_assist_rest_rate_limiting_enabled` (enabled by default)
  - `silver_assist_rest_rate_limit_requests` (default: 100 requests per window)
  - `silver_assist_rest_rate_limit_window` (default: 60 seconds)
- Features independently toggleable via plugin settings
- Lazy initialization in Plugin singleton with `get_rest_api_security()` getter

### ✅ Tests

- Unit tests for batch endpoint restriction: unauthenticated blocking, authenticated pass-through, non-batch endpoints regression
- Unit tests for rate limiting: transient counting, authenticated bypass, configuration validation, feature disable
- Integration tests for REST API security: plugin initialization, real WordPress REST API blocking, GraphQL endpoint non-interference, partial feature initialization, trusted-proxy client IP extraction from X-Forwarded-For

### 🛡️ Defense-in-Depth

- Recommended for all WordPress 7.0.2 sites pending core update to 7.0.3
- Protects against WP2Shell variant exploits even after core patches deployed
- Authenticated users (admin/editor) bypass restrictions for legitimate API operations
- Minimal performance impact: 2 lightweight filters + transient-based rate limiting (leverages external object cache when available; falls back to WordPress options table)

## [1.4.0] - 2026-06-03

### ✨ Added

- **Login Page Branding**: Custom-branded login page with modern split-layout design (#83)
  - Two-column layout: login form (left) + decorative illustration panel (right)
  - Silver Assist logo via CSS background-image replacing the WordPress logo
  - Rocket/mountains illustration in the right panel with dark gradient background
  - Brand colors (`#00D1FF` cyan), custom typography, and styled form inputs
  - CTA button: full-width, 48px height, uppercase bold, cyan background
  - Responsive: 50/50 > 1024px, 60/40 768–1024px, single column < 768px
  - Togglable via admin settings (enabled by default)
  - Custom logo URL support via Media Library
  - Configurable illustration panel visibility and background color
  - New class `LoginBranding` independent from existing `LoginSecurity`
  - Unit tests for hook registration, filter outputs, and conditional rendering

### 🗑️ Removed

- **Under Attack Mode**: Removed entirely. The feature's core mechanism (HTML CAPTCHA injection) is architecturally incompatible with headless WordPress where end users never access WordPress directly. The escalation it provided is already covered by IP blacklist + violation tracking.
  - Deleted `src/Security/UnderAttackMode.php`, `templates/captcha-field.php`, `assets/js/captcha.js`, `assets/css/captcha.css`
  - Removed CAPTCHA validation, injection, and asset enqueueing from `ContactForm7Integration` and `LoginSecurity`
  - Removed `under_attack_*` options from `DefaultConfig`
  - Removed Under Attack Mode settings from admin UI, dashboard badge, and settings handler
  - Closes #52 (REST API CAPTCHA incompatibility)
  - Resolves PR #76 CI instability (WP 7.0 test failures caused by Under Attack transient timing)

## [1.3.1] - 2026-03-16

### 🐛 Fixed

- **API Key Auth Filter Priority**: Move `determine_current_user` filter from priority 5 to 30, running after WordPress core's `wp_validate_auth_cookie` (prio 10) and `wp_validate_logged_in_cookie` (prio 20). Previously, core callbacks overwrote the authenticated user ID with `false`
- **GraphQL Init Timing**: Move `GraphQLSecurity` initialization from `init` hook to `plugins_loaded` (priority 5) so the `determine_current_user` filter is registered before WordPress resolves the current user
- **X-API-Key CSRF Downgrade**: Add `graphql_authentication_errors` filter to prevent WPGraphQL from downgrading API key-authenticated users to guest. WPGraphQL's Router only recognizes `Authorization` header as non-cookie auth; `X-API-Key` was incorrectly treated as cookie-based, triggering nonce-less downgrade
- **Service User Validation on Key Generation**: Generate API key AJAX handler now checks if a valid service user is configured and returns a warning prompting the admin to select one, preventing silent authentication failure after key generation

## [1.3.0] - 2026-03-11

### 🔒 Security

- **GraphQL Authentication Requirement**: Enforce authentication for all GraphQL requests via `graphql_request_data` filter, using WPGraphQL's native `restrict_endpoint_to_logged_in_users` setting as the single source of truth (RSM pentest audit finding)
- **Custom API Key Authentication**: Plugin-managed API key system supporting `X-API-Key` header and `Authorization: Bearer` token for server-to-server authentication
- **Secure Key Storage**: API keys stored as hashed values using `wp_hash_password()`, verified with `wp_check_password()`
- **Service User Binding**: API key authentication resolves to a configurable WordPress service account user
- **Environment-Aware Bypass**: Authentication enforcement is bypassed only in `local`/`development` environments to allow development tooling

### ✨ Added

- **Authentication Settings UI**: Admin panel section showing WPGraphQL authentication status badge with direct link to WPGraphQL settings, API key management (generate/regenerate/revoke), service user dropdown, and one-time key display
- **Dashboard Auth Indicator**: Authentication status ("Required" / "Public") shown in GraphQL Security dashboard card
- **Security Level Scoring**: Authentication requirement contributes to the GraphQL security level calculation
- **AJAX API Key Management**: Generate, regenerate, and revoke API keys via AJAX without page reload, keeping the user on the GraphQL Security tab
- **API Key Usage Example**: Success-styled notice showing `X-API-Key` and `Authorization: Bearer` header formats, visible only when an API key is configured

### 🐛 Fixed

- **Undefined Property**: Remove dead `$this->headless_mode` assignments in `enable_headless_mode()` and `disable_headless_mode()`
- **Security Score Double-Counting**: `calculate_security_level()` no longer awards points twice when both endpoint access is restricted and authentication is required

### ✅ Tests

- Unit tests for `is_authentication_required()` covering WPGraphQL setting on/off and security level scoring
- Integration tests for auth enforcement, `validate_authentication()`, and `authenticate_api_key()` (filter registration, logged-in pass-through, unauthenticated blocking, env bypass, API key via X-API-Key and Bearer headers)
- Unit tests for `GraphQLApiKeyAjaxHandler`: generate success, nonce validation, capability checks, key regeneration, revoke flow, hex format validation

### 🌐 Translations

- Updated POT file with new translatable strings
- Added Spanish (es_ES) translations for all authentication UI strings

## [1.2.1] - 2026-03-09

### 🔧 CI

- **Release Workflow**: Make Node.js setup, npm install, and build steps conditional on `package.json` existence

## [1.2.0] - 2026-03-03

### 🐛 Fixed

- **Vendor Assets**: Ensure vendor package assets (CSS/JS) are included in release builds
- **Null Safety**: Add null guards for `UnderAttackMode` in CF7 CAPTCHA methods (`inject_captcha_field`, `ajax_generate_captcha`, `enqueue_captcha_assets`)

### 🧹 Code Quality

- **PHPCS**: Fix 7 auto-fixable formatting issues in `ContactForm7AjaxHandler`, `ContactForm7Integration`, and `LoginSecurity`
- **PHPStan**: Resolve all 5 nullable type errors — now 0 errors at configured level

### ♻️ Refactoring

- **Release Pipeline**: Unify release workflow and build script across all plugins
  - Selective copy strategy replaces copy-all-then-clean approach
  - Remove `composer.json` from ZIP (not needed at runtime)
  - Auto-detect plugin structure (directories, main file, version)
  - Generate MD5 + SHA256 checksums

### 🔒 Security

- **GitHub Actions**: Pin all dependencies to SHA hashes for supply chain protection
  - `actions/checkout@v4.3.1`
  - `shivammathur/setup-php@v2.36.0`
  - `softprops/action-gh-release@v2.5.0`

## [1.1.16] - 2026-03-02

### ♻️ Refactoring & Architecture

- **Settings Hub Integration**: Renamed plugin tab from "Security" to "Security Essentials" for clearer identification
- **Update Check Delegation**: Simplified update checking by delegating to `wp-github-updater` v1.3.0 built-in `enqueueCheckUpdatesScript()`, removing custom AJAX handler and `update-check.js`
- **Removed `update-check.js`**: Eliminated standalone update check script in favor of centralized wp-github-updater functionality
- **Removed duplicate `<h1>` title**: AdminPageRenderer no longer renders standalone page title (handled by Settings Hub)
- **Version badge CSS**: Added `.version-badge` component style using CSS design system variables

### 📦 Dependencies

- **wp-github-updater**: Updated from `^1.0` to `^1.3` for built-in update check UI support
- **wp-settings-hub**: Updated from `^1.1.3` to `^1.2` for `plugin_file` registration support
- **Updater config**: Added `text_domain` parameter for localized update notifications

### 🔧 CI/CD

- **Copilot Setup Steps**: Added `.github/workflows/copilot-setup-steps.yml` for automated PHP dependency setup in Copilot coding agents

## [1.1.15] - 2026-02-28

### 🚨 Under Attack Mode & CAPTCHA Protection

- **Login CAPTCHA**: Math-based CAPTCHA challenge on WordPress login page when Under Attack Mode is active
  - Validates CAPTCHA answer server-side before authentication
  - Accessible design with ARIA labels and screen reader support
- **CF7 CAPTCHA**: CAPTCHA challenge injected into Contact Form 7 forms during Under Attack Mode
  - Automatic injection via `wpcf7_form_elements` filter
  - Server-side validation via `wpcf7_validate` hook
- **Shared Template System**: `templates/captcha-field.php` renders consistent CAPTCHA across all entry points
  - `SecurityHelper::render_template()` for output-buffered template rendering
  - JavaScript-powered refresh without page reload
  - Dedicated `captcha.css` and `captcha.js` assets with build pipeline integration
- **Remember Me Removal**: "Remember Me" checkbox hidden via CSS on login page
  - Session cookie lifetime enforced to match configured session timeout
  - Prevents users from bypassing session timeout policies
- **Singleton Pattern**: `UnderAttackMode` converted to singleton matching `IPBlacklist` pattern
  - `getInstance()` used consistently across `LoginSecurity`, `ContactForm7Integration`, and `SecurityDataProvider`

### 📊 Dashboard Card Enhancements

- **Under Attack Mode Status**: Real-time Active/Inactive indicator in General Security dashboard card
- **IP Blacklisting Status**: Enabled/Disabled indicator in General Security dashboard card
- **Session Timeout Stat**: Displays configured timeout value (minutes) in Admin Security card
- **Dashboard Auto-Refresh**: Switching to dashboard tab automatically refreshes security status and login stats
- **Bot Protection Selector Fix**: Updated JS selector from `:last-child` to `:nth-child(2)` after Session Timeout stat addition

### 🐛 Autosave Indicator Fix

- **Persistent Indicator Bug**: Fixed `showSavingIndicator()` only showing visual feedback on first save
  - Root cause: `.fadeOut()` left indicator in DOM with `display:none`, subsequent calls found existing div and did nothing
  - Fix: `.stop(true, true).html(savingText).removeClass("error").show()` on existing indicator
  - Changed `$("form").append()` to `$("form").first().append()` to prevent duplicates

### 🌍 Translations Update

- **POT Regenerated**: `wp i18n make-pot` — 791 → 1087 lines, all new translatable strings captured
- **Spanish (es_ES)**: 82 new strings translated, 61 fuzzy flags resolved, 4 format errors fixed
- **Binary Compiled**: `.mo` file regenerated with `msgfmt --check` validation (234 translated messages)

### 📚 Documentation

- **README.md**: Added Under Attack Mode, CAPTCHA, IP Blacklisting, Session Timeout, Remember Me removal sections
- **Test Coverage**: Updated counts to reflect current test suite (350+ unit, 50+ integration)

### 🎨 Dashboard UI Overhaul

- **Card-Based Layout**: Complete redesign of the security dashboard with status cards
  - Login Security, Admin Security, GraphQL Security, General Security, and Form Protection cards
  - `stat-value`/`stat-label` components for consistent data display
  - Feature-status rows with enabled/disabled indicators and `::before` icons
  - Security Statistics section: Blocked IPs, Failed Attempts (24h), Security Events (7d)
- **Activity Tabs**: New tabbed interface (Blocked IPs / Security Logs) in Recent Activity section
  - Loading spinners and loading-text placeholders for async content
  - Interactive tab switching with smooth transitions
- **Settings Tabs Card Migration**: All 4 settings tabs now use `.status-card` with `.card-header`/`.card-content`
  - Login Protection, GraphQL Security, Contact Form 7, and IP Management sections wrapped in styled cards
  - Consistent card structure with header icons across all tabs
- **Status Indicator Semantics**: Renamed `.disabled` to `.inactive` for clarity
- **Toggle Switch Refactor**: Native `:checked` selector with `.toggle-slider` class instead of JS class toggling

### 🛡️ Admin Hide Security Restored

- Toggle switch to enable/disable admin URL hiding
- Custom admin path input with real-time validation and preview
- Security warning notice with recovery instructions
- Path validation fallback for undefined error messages

### 📊 Security Logs & IP Management

- **Security Logs Panel**: New logs viewer in dashboard Recent Activity
  - AJAX-loaded table with timestamp, event type, and details columns
  - Secure DOM construction using jQuery `.text()` to prevent XSS
- **IP Unblock Functionality**: Unblock IPs directly from IP Management tab
  - `unblock_ip` AJAX endpoint in `SecurityAjaxHandler`
  - Full table view with per-IP unblock buttons
  - Compact dashboard summary (last 3 IPs) with "View all" link
- **Blocked IPs Display**: Split into compact dashboard summary and full IP Management table

### 🔒 Security Hardening

- **DOM XSS Prevention**: Added `escapeHtml()` helper to admin.js for all user-data DOM insertion
  - Blocked IPs table: IP addresses, reasons, timestamps all escaped
  - Security logs: Rebuilt with jQuery DOM construction (`.text()`) instead of template literals
  - CF7 blocked IPs: Table headers use `esc_html__()`, cell values use `esc_html()`
- **AJAX Scope Fix**: Resolved `ReferenceError` — `ajaxurl`/`nonce` now destructured in correct scope for unblock button handlers
- **Smart Logging System**: Severity-based security event logging
  - 58 event types classified as error (13), warning (33), or info (12)
  - `WP_DEBUG` gate — no log output when debugging is disabled
  - Test environment filtering — only errors logged during tests
  - `[ERROR]`/`[WARNING]`/`[INFO]` severity prefixes in log format
  - Eliminated ~70 noisy log lines from test output

### 🧩 New Components

- **RenderHelper Utility Class** (`src/Admin/Renderer/RenderHelper.php`): Shared static methods for UI rendering
  - `render_feature_status()` — Feature enabled/disabled rows
  - `render_stat()` — Numeric stat values with label and optional suffix
  - `render_async_stat()` — AJAX-loaded stat cards with loading spinner
- **SecurityDataProvider Expanded**: Added `form_protection`, GraphQL detail fields (`query_depth_limit`, `query_complexity_limit`, `query_timeout`, `introspection_disabled`), `xmlrpc_disabled`, `version_hiding`, and overall statistics
- **StatisticsProvider**: Cross-component stats with inlined log file reading to avoid circular dependency
- **DashboardRenderer Refactored**: All repetitive HTML blocks replaced with `RenderHelper` calls (8 feature-status, 7 stat, 3 async-stat)

### 🔒 Autosave / Submit Race-Condition Guard

- Submit buttons disabled with "Saving..." label during autosave
- Manual submit cancels pending autosave timer
- 15s fallback timeout re-enables buttons if autosave hangs
- CSS `.is-saving` class for visual feedback

### 🐛 Bug Fixes

- **CF7 Detection (CF7 v6.x)**: Removed deprecated `function_exists('wpcf7_get_contact_form_by_id')` check — this function was removed in CF7 v6.x, causing the CF7 tab to not appear
- **CF7 Blocked IPs Loading**: `loadCF7BlockedIPs()` now targets both `#cf7-blocked-ips-content` and `#cf7-blocked-ips-container`
- **CF7 Tab Data Loading**: Added `cf7-security` case to `switchToTab` for CF7 tab activation
- **CF7 Empty State Styling**: Changed to `.no-threats` class for consistent green styling
- **Admin Path Validation**: Added fallback `"Invalid path"` for undefined error messages; removed static div (JS creates it dynamically)
- **Toggle Switch Initialization**: Skip checkboxes already inside `.toggle-switch` labels to prevent double-wrapping
- **Blocked IPs Data Extraction**: Handle both array and object response formats
- **GraphQL Timeout Option Key**: Fixed `silver_assist_graphql_timeout` → `silver_assist_graphql_query_timeout` to show correct dashboard value
- **PHP Function Prefixes**: Added `\` to `wp_json_encode()`, removed unnecessary `\` from `round()` (PHP built-in)
- **SecurityDataProvider PHPDoc**: Fixed mis-indented docblock for `$stats_provider` property
- **Noisy Log Removed**: Removed `IP_CLEANUP_INITIALIZED` log from Plugin.php

### 🧪 Test Suite

- **AjaxTestHelper Trait**: Reusable AJAX testing infrastructure
  - `AjaxTestDieError extends \Error` bypasses WordPress die handlers in tests
  - `setup_ajax_environment()`, `call_ajax_handler()`, `teardown_ajax_environment()` methods
- **36 Pre-Existing Test Failures Fixed** across 5 categories:
  - UI structure mismatches — updated tab IDs, CSS classes, text labels
  - Removed/refactored methods — rewired tests to `SettingsHandler::save_security_settings()`
  - Hook registration issues — fixed test isolation and explicit component creation
  - Singleton/void/input ID — `getInstance()`, `ob_start()` buffering, correct field IDs
- **283 Tests Passing**: Unit (122), Functional (42), Security (62), Integration (57+)

### 🎨 Code Quality

- **PHPCS Compliance**: Auto-fixed 223 violations via PHPCBF (0 errors, 3 pre-existing warnings remaining)
  - `SettingsRenderer.php`: 200 fixes (spacing, brace placement, indentation)
  - `SecurityDataProvider.php`: 23 fixes
- **PHPStan Level 8**: Resolved all 37 static analysis errors (100% compliance)

### 📚 Documentation & AI Config

- **Copilot Instructions Updated**: Documentation rule now distinguishes between project docs and Copilot config files
  - `.github/skills/` — Copilot Skills (domain knowledge)
  - `.github/prompts/` — Copilot Prompt Files (reusable workflows)
  - `.github/instructions/` — Copilot Instruction Files (scoped context)
- **Dashboard Styles Skill**: `.github/skills/dashboard-styles/SKILL.md` — CSS classes, HTML patterns, component usage guide
- **Dependabot Auto-Merge**: Documented GitHub Actions limitation for workflow file modifications

### Changed

- 📦 **Contact Form 7 Stubs**: Added `miguelcolmenares/cf7-stubs` ^6.1 for PHPStan static analysis
- 🔧 **GitHub Workflow Permissions**: Added `contents: write` and `pull-requests: write` to quality-checks workflow
- 🚀 **Quality Checks Script**: Improved non-interactive mode, CI/CD integration, WP_VERSION environment variable support
- ⚙️ **GitHub Actions Workflow**: Simplified to use unified `run-quality-checks.sh` script

### Removed

- 🗑️ Deleted temporary documentation files (`.github/FIX_SUMMARY.md`, `.github/GITHUB_APP_PERMISSIONS.md`)

## [1.1.15] - 2025-11-06

### 🎛️ Major Feature: Tab Navigation System & Contact Form 7 Integration

#### 🚀 New Multi-Tab Security Dashboard

- **Advanced Tab Structure**: Enhanced from 3 tabs to comprehensive 5-tab interface
  - **Security Dashboard**: Real-time overview, compliance status, and security alerts
  - **Login Protection**: Brute force settings, session management, bot protection
  - **GraphQL Security**: Query limits, rate limiting, introspection control
  - **Form Protection**: Contact Form 7 integration (conditional tab when CF7 active)
  - **IP Management**: Comprehensive IP blocking, allowlists, and monitoring

#### 📧 Contact Form 7 Integration & Form Protection  

- **Seamless Integration**: Automatic detection and integration with Contact Form 7
  - Dynamic tab appearance: Form Protection tab shows only when CF7 is active
  - Zero configuration required - automatically activates when CF7 detected
  - Complete compatibility with existing CF7 installations

- **Advanced Form Security**:
  - **Rate Limiting**: IP-based submission limits to prevent spam floods
  - **Bot Protection**: Advanced detection of automated form submission attempts
  - **CSRF Enhancement**: Strengthened nonce validation for form security
  - **Real-time Monitoring**: Track and display blocked form submissions
  - **IP Blocking**: Temporary blocks for IPs exceeding submission thresholds

#### 🎯 Tab Namespace Separation & Settings Hub Compatibility

- **Dual Navigation System**: Revolutionary namespace separation enables coexistence
  - **Settings Hub Level**: `.nav-tab` classes for plugin switching (Security ↔ SEO ↔ etc.)
  - **Security Plugin Level**: `.silver-nav-tab` classes for internal feature navigation
  - **Zero Conflicts**: Both navigation systems work independently and simultaneously

- **Technical Implementation**:
  - **CSS Namespace Isolation**: Complete class separation prevents style conflicts
  - **JavaScript Scope Separation**: Dynamic tab detection with conditional CF7 handling
  - **Responsive Design**: Both navigation levels adapt to screen size and content
  - **Accessibility**: Full keyboard navigation and screen reader support maintained

#### 🔧 Enhanced Admin Architecture

- **Component Separation**: Professional admin component architecture
  - `AdminPageRenderer.php`: Main page structure with namespace-separated navigation
  - `SettingsRenderer.php`: All settings tabs with `.silver-tab-content` classes
  - `DashboardRenderer.php`: Security dashboard with real-time statistics

- **Dynamic Tab Management**:
  - JavaScript automatically detects available tabs from DOM structure
  - Handles conditional CF7 tab without hardcoded dependencies
  - URL hash routing with browser back/forward support
  - Smooth transitions with fade effects between tab content

#### 🧪 Comprehensive Test Suite Expansion

- **CI/CD Matrix Expansion**: Enhanced from 3 to 12 test combinations
  - **Quality Checks**: PHP 8.0-8.3 × WordPress 6.5, 6.6, latest (9 combinations)
  - **CF7 Integration**: PHP 8.3 × WordPress 6.5, 6.6, latest (3 combinations)
  - **Complete Coverage**: All WordPress versions tested with Contact Form 7

- **WordPress Real Environment Testing**:
  - 250+ tests across security components with real WordPress + MySQL
  - Integration tests for tab navigation and CF7 compatibility
  - Security validation for all form protection features
  - CI/CD pipeline ensures all 12 environments pass before deployment

#### 🎨 Modern Asset Management & Build System

- **Enhanced Minification**: PostCSS + cssnano for CSS, Grunt + uglify for JavaScript
  - **admin.js**: 55kB → 16.7kB (70% reduction)
  - **CSS optimization**: Modern CSS features preserved (layers, nesting, container queries)
  - **Build automation**: `npm run build` for complete asset pipeline

### 🤖 Automated Dependency Management System

#### 🚀 New CI/CD Infrastructure

- **GitHub Actions + Dependabot Integration**: Complete automation for dependency updates
  - Weekly automated checks for Composer, npm, and GitHub Actions dependencies
  - Automatic Pull Request creation for outdated packages
  - Intelligent grouping of minor/patch updates in single PRs
  - Separate PRs for major versions requiring manual review
  
- **Quality Assurance Automation**:
  - `check-composer-updates` job: PHP dependencies validation with PHPStan and PHPCS
  - `check-npm-updates` job: JavaScript dependencies with build verification
  - `security-audit` job: CVE scanning for both Composer and npm packages
  - `validate-pr` job: Comprehensive validation of all Dependabot PRs
  - `auto-merge-dependabot` job: Safe auto-merge for patch/minor updates

- **Security-First Approach**:
  - Continuous vulnerability scanning (reports stored for 90 days)
  - Critical packages flagged for manual review on major versions:
    - `silverassist/wp-settings-hub` (Settings Hub integration)
    - `silverassist/wp-github-updater` (Update system)
  - GitHub Copilot automatically reviews all dependency PRs
  - Automated security audits for both PHP and JavaScript ecosystems

- **Configuration Files Added**:
  - `.github/dependabot.yml`: Dependency scanning and PR creation configuration
  - `.github/workflows/dependency-updates.yml`: CI/CD workflow with 5 automated jobs

- **Schedule**:
  - Monday 9:00 AM (Mexico City): Composer packages check
  - Monday 9:30 AM (Mexico City): npm packages check
  - Monday 10:00 AM (Mexico City): GitHub Actions check
  - 24/7: Security vulnerability monitoring and alerts

#### 📊 Developer Benefits

- Zero manual intervention for safe updates (minor/patch versions)
- Automated quality gates ensure code standards maintained
- Complete audit trail via GitHub PRs
- Time savings on dependency maintenance
- Early detection of security vulnerabilities
- GitHub Copilot AI reviews provide intelligent feedback

#### 🔧 Implementation Details

- Auto-merge enabled for `version-update:semver-patch` and `version-update:semver-minor`
- Major version updates require manual review and approval
- All PRs labeled automatically: `dependencies`, `composer`/`npm`/`github-actions`, `automated`
- Comprehensive reporting: outdated packages, security audits, build results
- Artifacts retention: outdated reports (30 days), security audits (90 days)

### 📚 Documentation Philosophy Change

- **Consolidated Documentation**: All documentation maintained in core files (README, CHANGELOG, copilot-instructions)
- **No Separate MD Files**: Prevents documentation fragmentation and maintenance overhead
- **Single Source of Truth**: Easier to maintain and keep up-to-date
- **AI Instruction**: Explicit guidance added to prevent creation of separate documentation files

## [1.1.13] - 2025-10-09

### 🎯 Major Feature: Settings Hub Integration

#### ⚠️ BREAKING CHANGES

- **Menu Structure Changed**: Plugin now registers under centralized "Silver Assist" menu via Settings Hub
  - **Before**: Standalone menu in WordPress Settings → "Security Essentials"
  - **After**: Top-level "Silver Assist" menu → "Security" submenu
  - **URL Change**: Admin page URL structure modified for hub integration
  - **Backward Compatibility**: Automatic fallback to standalone menu when Settings Hub unavailable

#### 🚀 New Features

- **Settings Hub Integration** (`silverassist/wp-settings-hub v1.1.0`):
  - Centralized admin interface for all Silver Assist plugins
  - Professional plugin dashboard with cards and metadata display
  - Cross-plugin navigation via tabs (when multiple plugins installed)
  - Dynamic action buttons support
  - Enhanced user experience with consistent UI across Silver Assist ecosystem

- **"Check Updates" Button**:
  - New action button in Settings Hub plugin card
  - One-click update checking via AJAX
  - Automatic redirection to WordPress Updates page when update available
  - Real-time feedback with user-friendly messages
  - Seamless integration with existing wp-github-updater package

- **Removed Plugin Updates Section**:
  - Eliminated redundant "Plugin Updates" card from admin page
  - Update functionality consolidated into Settings Hub action button
  - Cleaner admin interface with reduced UI clutter
  - Maintained all update checking capabilities

#### 🔧 Technical Implementation

- **New Methods in AdminPanel**:
  - `register_with_hub()`: Main hub registration with automatic fallback
  - `get_hub_actions()`: Configures action buttons for plugin card
  - `render_update_check_script()`: JavaScript callback for update button
  - `ajax_check_updates()`: AJAX handler for update verification
  - `add_admin_menu()`: Fallback method for standalone menu registration

- **Settings Hub Registration**:

  ```php
  $hub->register_plugin(
      'silver-assist-security',
      __('Security', 'silver-assist-security'),
      [$this, 'render_admin_page'],
      [
          'description' => __('Security configuration for WordPress', 'silver-assist-security'),
          'version' => SILVER_ASSIST_SECURITY_VERSION,
          'tab_title' => __('Security', 'silver-assist-security'),
          'actions' => [
              [
                  'label' => __('Check Updates', 'silver-assist-security'),
                  'callback' => [$this, 'render_update_check_script'],
                  'class' => 'button button-primary',
              ]
          ]
      ]
  );
  ```

- **Intelligent Fallback System**:
  - Automatic detection of Settings Hub availability
  - Graceful degradation to standalone menu when hub absent
  - Zero functionality loss in fallback mode
  - Exception handling with security event logging

#### 🧪 Comprehensive Testing

- **New Test Suite**: `tests/Integration/SettingsHubTest.php` (10 test cases):
  - Settings Hub class detection and availability
  - Fallback menu registration verification
  - Update button configuration validation
  - AJAX handler functionality tests
  - Security validation for update checks
  - Update script rendering verification
  - Hub registration metadata validation
  - Actions array structure tests
  - Admin hooks registration checks
  - Integration testing with wp-github-updater

#### 🔒 Security Enhancements

- **AJAX Security**:
  - Nonce validation for all update check requests
  - User capability verification (`manage_options`)
  - Comprehensive error handling and logging
  - Sanitized JavaScript output with `esc_js()`, `esc_url()`
  - SecurityHelper integration for event logging

#### 📊 Impact Assessment

- **User Experience**:
  - ✅ Unified admin interface for Silver Assist plugins
  - ✅ Professional dashboard with plugin cards
  - ✅ Quick access to update checking
  - ✅ Consistent UI across plugin ecosystem
  - ⚠️ URL change may affect bookmarks (acceptable for major version)

- **Developer Experience**:
  - ✅ Modular architecture with clean separation
  - ✅ Easy to extend with additional action buttons
  - ✅ Comprehensive test coverage
  - ✅ Well-documented integration patterns

- **Compatibility**:
  - ✅ Works with or without Settings Hub
  - ✅ Maintains all existing functionality
  - ✅ Backward compatible via fallback mechanism
  - ✅ No data migration required

#### 🎨 Code Quality

- **Standards Compliance**: Full WordPress coding standards adherence
- **Type Safety**: Strict PHP 8+ type declarations throughout
- **Documentation**: Complete PHPDoc for all new methods
- **Error Handling**: Comprehensive try-catch blocks with logging
- **Internationalization**: All user-facing strings properly translated

### 📦 Dependencies

- **Added**: `silverassist/wp-settings-hub` ^1.1 (production dependency)
- **Maintained**: All existing dependencies (wp-github-updater, PHPUnit, etc.)

### 🔄 Migration Guide

**For End Users**:

1. Update plugin to v1.1.13
2. Admin menu location changes automatically
3. Find plugin under "Silver Assist" → "Security" (or Settings if hub not installed)
4. Update bookmarks if accessing settings directly

**For Developers**:

1. Install/update via Composer: `composer update`
2. Settings Hub automatically detected if installed
3. Fallback mechanism ensures compatibility
4. No code changes required in consuming applications

## [1.1.12] - 2025-09-10

### 🎨 Modern CSS Minification System Upgrade

#### PostCSS + cssnano Implementation

- **🚀 CRITICAL FIX**: Replaced broken grunt-contrib-cssmin with modern PostCSS + cssnano system:
  - **CSS Corruption Fixed**: grunt-contrib-cssmin was corrupting modern CSS features (@layer, nesting)
  - **All Classes Preserved**: Fixed loss of CSS classes during minification (46/46 classes now preserved)
  - **Modern CSS Support**: Full support for @layer directives, CSS nesting, container queries
  - **Better Compression**: Improved compression rates (37-50% vs previous inconsistent results)
  - **Build System Hybrid**: PostCSS for CSS + Grunt for JavaScript (best of both worlds)

#### Updated Build Commands

- **New Primary Command**: `npm run build` - Complete CSS + JS minification
- **Granular Control**: `npm run minify:css` (PostCSS) and `npm run minify:js` (Grunt)
- **Enhanced Script**: `./scripts/minify-assets-npm.sh` with detailed logging and verification
- **Development Friendly**: `npm run clean` to remove minified files during development

#### Developer Experience Improvements

- **Real-time Verification**: Script shows compression ratios and file size reductions
- **Dependency Management**: Auto-installs and updates npm packages
- **Error Prevention**: Validates all required configuration files (postcss.config.js, Gruntfile.js)
- **Comprehensive Logging**: Detailed build process information with colored output

### 📚 Documentation Updates

- **Complete Guide**: Updated all documentation to reflect new PostCSS + Grunt workflow
- **Script README**: Added comprehensive `minify-assets-npm.sh` documentation
- **Release Workflow**: Updated release process to include asset minification step
- **Developer Instructions**: Enhanced Copilot instructions with modern CSS minification details

### 🔧 Technical Details

- **CSS Pipeline**: assets/css/*.css → PostCSS + cssnano → assets/css/*.min.css
- **JS Pipeline**: assets/js/*.js → Grunt + uglify → assets/js/*.min.js  
- **Configuration**: postcss.config.js (CSS) + Gruntfile.js (JS) + package.json (dependencies)
- **Compression**: CSS 37-50% reduction, JavaScript 69-79% reduction
- **Compatibility**: Node.js 16+, npm 8+, modern CSS features fully supported

### 🎯 Impact

- **Fixed Critical Issue**: Admin styles no longer lost during minification
- **Enhanced Performance**: Better compression rates for faster page loads
- **Future-Proof**: Support for cutting-edge CSS features as they're adopted
- **Reliable Builds**: No more random minification failures or corrupted output
- **Developer Productivity**: Clear build commands and comprehensive error reporting

## [1.1.11] - 2025-08-29

### ⬆️ Dependencies Update

#### GitHub Updater Package Enhancement

- **📦 Updated silverassist/wp-github-updater**: Upgraded to version 1.1.3 (latest)
  - **Enhanced Reliability**: Improved auto-update system stability
  - **Better Error Handling**: More robust GitHub API interaction
  - **Performance Optimization**: Faster update checks and download processes
  - **WordPress 6.7+ Compatibility**: Full compatibility with latest WordPress versions

### 🔧 Code Quality Improvements

- **Clean Architecture**: Maintained consistent coding standards across all components
- **Version Synchronization**: All version references updated consistently using automated script
- **Documentation Updates**: Updated version numbers in headers and constants

## [1.1.10] - 2025-08-25

### 🐛 Critical Frontend Session Fix

#### Frontend Session Timeout Behavior Correction

- **🐛 Fixed Frontend Redirect Issue**: Session timeouts now handle frontend vs admin differently:
  - **Frontend**: Silent logout without redirect - users stay on their current page
  - **Admin**: Logout with redirect to login page showing `session_expired=1`
- **Better UX**: Users visiting public pages no longer get redirected to login when session expires
- **SEO Friendly**: Google search traffic and direct links to blog posts work properly even with expired sessions
- **Root Cause**: Previous implementation redirected all session timeouts to login, regardless of context
- **Solution**: Added conditional logic in `LoginSecurity::setup_session_timeout()` to differentiate frontend vs admin behavior

### 🔒 Security Impact

- **Maintained Security**: All session timeout protections remain active for legitimate sessions
- **Admin Protection**: Admin area maintains proper session timeout redirect behavior
- **Frontend Preservation**: Public pages no longer interrupted by authentication flows

### ⚡ New Production Asset Optimization

#### NPM + Grunt Minification Implementation

- **🎉 MAJOR UPGRADE**: Complete replacement of unreliable bash/API minification with professional NPM + Grunt system:
  - **Outstanding Results**: 38-79% file size reduction vs. previous 6-8%
  - **Industry Standard**: Uses `grunt-contrib-cssmin` and `grunt-contrib-uglify`
  - **Reliable**: No more API dependency failures or inconsistent compression
  - **CI/CD Ready**: Node.js and npm available in GitHub Actions by default

#### Dramatic Performance Improvements

- **📊 Actual Compression Results**:
  - **admin.css**: 57% reduction (23,139 → 9,838 bytes)
  - **password-validation.css**: 38% reduction (4,297 → 2,647 bytes)
  - **variables.css**: 48% reduction (9,735 → 4,981 bytes)
  - **admin.js**: 69% reduction (38,679 → 11,950 bytes)
  - **password-validation.js**: 79% reduction (10,945 → 2,274 bytes)

#### New Build Infrastructure

- **📦 package.json**: NPM dependencies with correct PolyForm-Noncommercial-1.0.0 license
- **⚙️ Gruntfile.js**: Professional CSS and JavaScript minification configuration
- **🔧 scripts/minify-assets-npm.sh**: Node.js-based minification script with comprehensive error handling
- **🔄 Updated build-release.sh**: NPM-first approach with bash fallback for maximum reliability

#### Technical Architecture

- **WordPress Compatibility**: Preserves jQuery, $, window, document globals for WordPress integration
- **License Preservation**: Maintains copyright headers and important comments
- **Modern CSS Support**: Handles CSS nesting (with warnings) while achieving excellent compression
- **IE9+ Compatibility**: CSS minification maintains compatibility for WordPress requirements

#### Asset Loading Architecture

- **Dynamic URL Generation**: Intelligent path construction for minified vs. original assets
- **WordPress Integration**: Seamless integration with WordPress `wp_enqueue_style()` and `wp_enqueue_script()`
- **Backward Compatibility**: Zero impact on existing functionality - graceful fallback to original files
- **Production Optimization**: Faster asset loading in production without compromising functionality

### ♻️ Major Code Architecture Improvement

#### SecurityHelper Centralization System

- **🔧 New SecurityHelper Class**: Created `src/Core/SecurityHelper.php` as centralized utility system:
  - **Asset Management**: `get_asset_url()` with SCRIPT_DEBUG-aware minification support
  - **Network Security**: `get_client_ip()`, `is_bot_request()`, `send_404_response()` functions
  - **Authentication**: `is_strong_password()`, `verify_nonce()`, `check_user_capability()` utilities
  - **Data Management**: `generate_ip_transient_key()`, `sanitize_admin_path()` helpers
  - **Logging & Monitoring**: `log_security_event()`, `format_time_duration()` structured logging
  - **AJAX Utilities**: `validate_ajax_request()` with comprehensive security validation
- **📚 Documentation Standards**: Comprehensive Copilot instructions with mandatory usage patterns
- **🚫 Code Deduplication**: Eliminated ~100 lines of duplicated utility code across components
- **🔄 Component Integration**: Updated all security classes to use centralized helper functions:
  - `AdminPanel.php` - Uses SecurityHelper for asset loading
  - `LoginSecurity.php` - Uses SecurityHelper for IP detection, logging, and bot detection  
  - `GeneralSecurity.php` - Uses SecurityHelper for asset management
  - `AdminHideSecurity.php` - Uses SecurityHelper for path validation and responses

#### Development Guidelines Enhancement

- **📋 Helper Function Categories**: Established 6 mandatory function categories for future development
- **🚨 Critical Coding Standards**: Added SecurityHelper to mandatory compliance section
- **🔧 Integration Patterns**: Documented correct/incorrect usage examples for developers
- **♻️ Migration Process**: Created systematic approach for centralizing future utility functions
- **📝 Auto-Initialization**: SecurityHelper auto-initializes without manual setup requirements

#### Architecture Benefits

- **Code Quality**: Centralized security utilities ensure consistent behavior across all components
- **Maintainability**: Single source of truth for utility functions reduces maintenance overhead
- **Developer Experience**: Clear guidelines and patterns for future helper function development
- **Performance**: Optimized helper functions with intelligent caching and minimal overhead

## [1.1.9] - 2025-08-21

### 🐛 Critical Login Bug Fixes

#### Session Management Loop Prevention

- **Fixed Login Loop Bug**: Resolved infinite redirect loop where users were sent to `?session_expired=1` after logout and subsequent login attempts
- **Root Cause**: `last_activity` metadata was persisting after logout, causing immediate session timeout on new login attempts
- **Session Cleanup**: Added comprehensive session metadata cleanup in multiple points:
  - `clear_login_attempts()` - Clears `last_activity` during logout process
  - `handle_successful_login()` - Removes stale metadata before establishing new session
  - `setup_session_timeout()` - Enhanced with login process detection

#### Login Process Intelligence

- **New Function**: `is_in_login_process()` - Intelligent detection of login workflow to prevent premature timeouts
- **Detection Points**:
  - wp-login.php page access
  - POST login requests
  - Recent login activity (< 30 seconds)
  - Login-related actions (login, logout, register, resetpass, etc.)
- **Session Protection**: Prevents session timeout during active login processes

#### Enhanced Session Security

- **Pre-logout Cleanup**: Session metadata cleared before logout to prevent state persistence
- **Fresh Session Initialization**: Each successful login starts with clean session state
- **Improved User Experience**: Eliminates frustrating login loops while maintaining security

### 🔒 Security Enhancements

- **Maintained Security**: All session timeout protections remain active for legitimate sessions
- **Login Flow Protection**: Timeout checks skip during login processes to allow smooth authentication
- **Stale Session Prevention**: Automatic cleanup prevents old session data from interfering with new logins

### ♻️ Major Code Architecture Improvement

#### SecurityHelper Centralization System

- **🔧 New SecurityHelper Class**: Created `src/Core/SecurityHelper.php` as centralized utility system:
  - **Asset Management**: `get_asset_url()` with SCRIPT_DEBUG-aware minification support
  - **Network Security**: `get_client_ip()`, `is_bot_request()`, `send_404_response()` functions
  - **Authentication**: `is_strong_password()`, `verify_nonce()`, `check_user_capability()` utilities
  - **Data Management**: `generate_ip_transient_key()`, `sanitize_admin_path()` helpers
  - **Logging & Monitoring**: `log_security_event()`, `format_time_duration()` structured logging
  - **AJAX Utilities**: `validate_ajax_request()` with comprehensive security validation
- **📚 Documentation Standards**: Comprehensive Copilot instructions with mandatory usage patterns
- **🚫 Code Deduplication**: Eliminated ~100 lines of duplicated utility code across components
- **🔄 Component Integration**: Updated all security classes to use centralized helper functions:
  - `AdminPanel.php` - Uses SecurityHelper for asset loading
  - `LoginSecurity.php` - Uses SecurityHelper for IP detection, logging, and bot detection  
  - `GeneralSecurity.php` - Uses SecurityHelper for asset management
  - `AdminHideSecurity.php` - Uses SecurityHelper for path validation and responses

#### Development Guidelines Enhancement

- **📋 Helper Function Categories**: Established 6 mandatory function categories for future development
- **🚨 Critical Coding Standards**: Added SecurityHelper to mandatory compliance section
- **🔧 Integration Patterns**: Documented correct/incorrect usage examples for developers
- **♻️ Migration Process**: Created systematic approach for centralizing future utility functions
- **📝 Auto-Initialization**: SecurityHelper auto-initializes without manual setup requirements

#### Architecture Benefits

- **Code Quality**: Centralized security utilities ensure consistent behavior across all components
- **Maintainability**: Single source of truth for utility functions reduces maintenance overhead
- **Developer Experience**: Clear guidelines and patterns for future helper function development
- **Performance**: Optimized helper functions with intelligent caching and minimal overhead

## [1.1.8] - 2025-08-20

### 🔧 Code Architecture & Security Improvements

#### Configuration Centralization

- **Centralized Legitimate Actions**: Moved all WordPress action arrays (`logout`, `postpass`, `resetpass`, `lostpassword`, etc.) from duplicated implementations to centralized `DefaultConfig.php`
- **New Configuration Methods**: Added three new methods for action management:
  - `get_legitimate_actions(bool $include_logout)` - General method with logout toggle
  - `get_bot_protection_bypass_actions()` - Actions that bypass bot protection (includes logout)
  - `get_admin_hide_bypass_actions()` - Actions for admin hide URL filtering (excludes logout)

#### Bot Protection Refinements  

- **Improved Rate Limiting**: Increased threshold from 5 to 15 requests per minute to accommodate legitimate user flows (password changes, logout confirmations)
- **Enhanced User Flow Detection**: Added specific exclusions for logged-in users and legitimate WordPress actions
- **False Positive Reduction**: More lenient detection criteria to prevent blocking legitimate users during normal WordPress operations
- **Better Header Validation**: Improved browser header detection logic for more accurate bot identification

#### Code Quality Improvements

- **Eliminated Code Duplication**: Removed redundant action arrays from `LoginSecurity.php` and `AdminHideSecurity.php`
- **Single Source of Truth**: All legitimate action definitions now managed centrally for consistency
- **Maintainability Enhancement**: Future action updates only require changes in one location
- **Clear Method Documentation**: Comprehensive PHPDoc for all new configuration methods

#### Bug Fixes

- **404 Error Resolution**: Fixed issue where legitimate users received 404 responses during password changes and logout flows
- **Authentication Flow**: Improved handling of legitimate WordPress authentication actions
- **Session Management**: Better integration between bot protection and user session handling

## [1.1.7] - 2025-08-20

### 🚀 JavaScript Architecture Modernization

#### ES6+ Code Transformation

- **Comprehensive ES6+ Destructuring**: Complete implementation of object destructuring patterns across all JavaScript functions for cleaner, more maintainable code
- **Centralized Timing Constants**: New `TIMING` object with 7 centralized timeout values (AUTO_SAVE_DELAY: 2000ms, VALIDATION_DEBOUNCE: 500ms, ERROR_DISPLAY: 5000ms, etc.)
- **Validation Constants System**: New `VALIDATION_LIMITS` object with 7 form validation ranges (LOGIN_ATTEMPTS: {min: 1, max: 20}, etc.)
- **Local DOM Element Optimization**: Implemented local jQuery element constants with proper `$` prefix convention for improved performance
- **Template Literals**: Replaced string concatenation with modern template literals using `${variable}` interpolation

#### Code Quality & Performance Improvements

- **Arrow Function Standardization**: Converted all function declarations to ES6 arrow functions with `const functionName = () => {}` pattern
- **Destructuring Implementation**: Systematic destructuring in 20+ functions across admin.js and password-validation.js
- **jQuery Optimization**: Local DOM element constants reduce repeated jQuery selections for better performance
- **Function Documentation**: Complete JSDoc documentation for all JavaScript functions in English

#### Developer Experience Enhancements

- **Centralized Configuration**: All timing values and validation limits now managed from single objects for easy maintenance
- **Clean Object Access**: `const { strings = {}, ajaxurl, nonce } = silverAssistSecurity || {}` pattern throughout codebase
- **Consistent Patterns**: Unified destructuring and constant usage patterns across all JavaScript files
- **Improved Readability**: Eliminated repetitive object property access with clean destructuring syntax

### 🔧 Development Standards & Guidelines

#### Coding Standards Documentation

- **ES6+ Examples**: Added comprehensive before/after examples in copilot-instructions.md demonstrating destructuring patterns
- **Mandatory Patterns**: Updated coding guidelines to require destructuring and centralized constants for all new development
- **jQuery Best Practices**: Documented `$` prefix convention for jQuery elements and timing constant requirements
- **Local vs Global Strategy**: Established preference for local constants over global objects for better code organization

#### Code Modernization Benefits

- **Maintainability**: Centralized constants eliminate hardcoded values scattered throughout the codebase
- **Performance**: Local DOM element caching reduces jQuery selector overhead
- **Consistency**: Unified patterns across all JavaScript functionality
- **Future-Proof**: Modern ES6+ syntax prepared for future JavaScript development

## [1.1.6] - 2025-08-19

### 🚀 New Features

#### Enhanced Password Security System

- **Real-time Password Validation**: New JavaScript-based live password strength validation for WordPress user profiles
- **Password Validation UI**: Custom CSS styling with success/error indicators using centralized CSS variables
- **Weak Password Prevention**: Automatic hiding of WordPress "confirm weak password" checkbox when strength enforcement is enabled
- **Visual Feedback System**: Color-coded validation messages with accessibility support and responsive design

#### GraphQL Security Card UI Components

- **Headless Mode Indicator**: New visual component showing GraphQL headless vs standard mode status with color-coded badges
- **Mode Value Components**: Interactive status indicators with hover effects and responsive container queries
- **CSS Variables Integration**: Complete integration with existing design system using logical properties for RTL/LTR support

#### Emergency Access Recovery System

- **wp-config.php Override**: Added `SILVER_ASSIST_HIDE_ADMIN` constant to disable admin hiding in emergency situations
- **Emergency Disable Feature**: Users can regain admin access when locked out by adding a single line to wp-config.php
- **Recovery Documentation**: Comprehensive step-by-step instructions for emergency access recovery

### 🔧 Security Improvements

#### Login & Password Protection Enhancements

- **Password Reset Security**: Fixed login page errors during password reset flows - now properly allows password reset actions
- **Enhanced Action Filtering**: Improved handling of WordPress login actions (`resetpass`, `lostpassword`, `retrievepassword`, `checkemail`)
- **Smart URL Token Management**: Intelligent filtering that excludes password reset actions from admin hiding protection
- **Asset Loading Optimization**: Improved script and CSS loading with proper dependency management and cache busting

#### Admin Hide Security Enhancements

- **Emergency Override System**: Database settings can now be overridden via wp-config.php constant for emergency access
- **Improved Error Handling**: Better fallback mechanisms when custom admin paths are forgotten or misconfigured
- **Enhanced Documentation**: Clear recovery instructions displayed in admin panel with inline code examples

### 🐛 Bug Fixes

#### Login & Authentication Fixes

- **Password Reset Flow**: Fixed 404 errors and access issues during password reset process
- **Admin Hide Compatibility**: Resolved conflicts between admin hiding and legitimate password reset operations
- **Action Parameter Handling**: Fixed handling of WordPress action parameters in login security validation
- **URL Generation**: Improved URL filtering to properly exclude password reset and recovery actions

### 📝 User Experience & Interface

#### CSS Design System Updates

- **GraphQL Component Styles**: New headless mode indicator with hover effects and smooth transitions
- **Spacing Variable Updates**: Consistent spacing scale from xs (2px) to 3xl (24px) for better design consistency
- **Logical Properties**: International support with RTL/LTR automatic layout adjustment
- **Container Queries**: Modern responsive design using container-based breakpoints instead of viewport-only queries
- **Layer-based Architecture**: Improved CSS organization with `@layer` for better cascade control

#### Admin Panel Improvements

- **Emergency Access Guidance**: Enhanced admin panel with clear wp-config.php recovery instructions
- **Inline Code Examples**: Visual code snippets showing exact constant syntax for emergency disable
- **Translation Updates**: Updated Spanish translations with emergency access terminology
- **Responsive Design**: Enhanced mobile and tablet support for all new UI components

### 🌍 Internationalization

#### Translation System Updates

- **Spanish Translation Updates**: Complete translation of emergency access recovery instructions
- **POT Template Regeneration**: Updated translation template with all new user-facing strings
- **Translator Comments**: Added proper context comments for complex placeholders and emergency instructions
- **Version Synchronization**: Updated Project-Id-Version to 1.1.6 across all translation files

### 🔒 Code Quality & Standards

#### Development Improvements

- **Version Synchronization**: All plugin files updated to version 1.1.6 with consistent `@version` tags
- **Asset Organization**: Better structure for CSS/JS files with modular approach and proper dependencies
- **Documentation Coverage**: Enhanced inline documentation for new password validation and GraphQL UI features
- **WordPress Integration**: Improved integration with WordPress native password strength meter

#### Testing Infrastructure

- **Emergency Access Testing**: New independent test script for verifying constant override functionality
- **Reflection-based Testing**: Advanced testing using PHP reflection to verify private property states
- **Database Override Verification**: Tests ensure wp-config.php constants properly override database settings

## [1.1.5] - 2025-08-11

### 🚀 New Features

#### GraphQL Security Testing Suite

- **Advanced Testing Script**: New `test-graphql-security.sh` script for comprehensive GraphQL security validation
- **CLI Parameter Support**: `--domain URL` parameter to specify GraphQL endpoint directly via command line
- **Automation Ready**: `--no-confirm` parameter for CI/CD workflows and automated testing
- **Complete Help System**: Comprehensive `--help/-h` documentation with usage examples
- **Multi-Configuration Support**: Three configuration methods (CLI param, environment variable, default fallback)
- **URL Validation**: Robust URL format validation with security warnings for suspicious endpoints
- **7 Security Scenarios**: Tests introspection protection, query depth limits, alias abuse prevention, directive limitations, field duplication limits, query complexity & timeout, and rate limiting

### 🐛 Bug Fixes

#### WordPress Security Hardening

- **Version Parameter Removal**: Fixed `remove_version_query_string()` in GeneralSecurity.php to handle multiple 'ver' parameters in URLs (e.g., `/file.css?ver=123?ver=456`)
- **Regex Pattern Enhancement**: Improved regex pattern to comprehensively remove all version query parameters for better security
- **Query String Cleanup**: Enhanced URL cleanup to properly handle malformed query strings with duplicate parameters

### 🔧 Development Tools Improvements

#### Script Reliability & Robustness

- **Enhanced Error Handling**: Removed `set -e` from update scripts to allow graceful continuation on non-critical errors
- **Version Script Robustness**: Improved `update-version-simple.sh` with better error recovery and user messaging
- **Version Checking Accuracy**: Fixed `check-versions.sh` to search only file headers (first 20 lines) preventing false positives
- **macOS Compatibility**: Enhanced perl-based substitution patterns for better macOS sed compatibility
- **Deferred Modifications**: Improved self-modifying script handling with deferred command execution

#### Development Workflow

- **CI/CD Ready Scripts**: All scripts now support non-interactive execution with proper exit codes
- **Better User Guidance**: Enhanced error messages with clear examples and suggested solutions
- **Graceful Error Recovery**: Scripts continue processing even when encountering non-critical issues
- **Version Consistency**: Automated validation ensures all 17 plugin files maintain version synchronization

### 📝 Documentation Updates

#### Version Management

- **Header Standards**: Updated HEADER-STANDARDS.md with version 1.1.5 references and examples
- **Script Documentation**: Enhanced inline documentation for all development scripts
- **Usage Examples**: Added comprehensive examples for new GraphQL testing functionality
- **Error Handling Docs**: Documented improved error handling patterns and best practices

### 🔄 Version Updates

- **Plugin Core**: Updated main plugin file to version 1.1.5
- **PHP Components**: All src/ PHP files updated with `@version 1.1.5` tags
- **Asset Files**: CSS and JavaScript files synchronized to version 1.1.5
- **Documentation**: All version references updated across documentation files
- **Build Scripts**: Version management scripts updated to 1.1.5

### 🛠️ Technical Improvements

#### Code Quality

- **Error Handling**: Enhanced error handling across all security components
- **Code Consistency**: Improved code consistency following project standards
- **Performance**: Maintained performance optimizations while adding new features
- **Backward Compatibility**: All changes maintain full backward compatibility

#### Security

- **URL Processing**: Improved URL parameter processing for better security
- **Input Validation**: Enhanced validation patterns for security-critical functions
- **Testing Coverage**: New comprehensive testing tools for GraphQL security validation
- **Production Ready**: All new features built with production-ready standards

## [1.1.4] - 2025-08-08

### 🔒 Major Security Features

#### Admin URL Hide Security

- **WordPress Admin Protection**: Hide `/wp-admin` and `/wp-login.php` from unauthorized users with custom URLs
- **404 Redirect Protection**: Direct access to standard admin URLs returns 404 errors for enhanced security
- **Custom Path Configuration**: User-configurable admin access paths (e.g., `/my-secret-admin`)
- **Security Keyword Filtering**: Prevents use of common, easily guessable paths like 'admin', 'login', 'dashboard'
- **Rewrite Rules Integration**: Seamless WordPress rewrite rules for custom admin access

#### Real-Time Path Validation

- **Live Input Validation**: Instant feedback while typing custom admin paths without form submission
- **AJAX Validation System**: Server-side validation with immediate user feedback
- **Visual Indicators**: Color-coded validation states (validating, valid, invalid) with animations
- **Smart Error Messages**: Specific error messages for different validation failures
- **Preview URL Generation**: Real-time preview of custom admin URL as user types

### 🔧 Technical Enhancements

#### Code Optimization & Architecture

- **Unified Query Parameter Handling**: Implements `build_query_with_token()` method for consistent URL manipulation across admin hiding features
- **DRY Principle Implementation**: Clean architecture with `do_redirect_with_token()` and `add_token_to_url()` using shared parameter handling logic
- **Production-Ready Code**: Built with clean, production-optimized code without debug logging for optimal performance
- **Reusable Forbidden Paths**: Centralized `$forbidden_admin_paths` class property for consistent validation
- **Public API**: Getter method `get_forbidden_admin_paths()` for external access
- **Performance Optimization**: Cached validation results and efficient AJAX responses

#### User Experience Improvements

- **Interactive Form Validation**: Enhanced form validation with admin path checks before submission
- **Responsive Design**: Mobile-optimized validation indicators and error messages
- **Progressive Enhancement**: Graceful degradation for users with JavaScript disabled
- **Auto-Save Integration**: Admin path validation integrated with existing auto-save functionality

#### Code Quality & Architecture

- **Method Design**: Implements reusable `build_query_with_token()` method for query parameter handling
- **Parameter Deduplication**: Built-in automatic removal of duplicate auth tokens in URL parameters
- **Flexible Input Handling**: Unified method supports both array (`$_GET`) and string query parameter sources
- **Clean Implementation**: Efficient codebase design following DRY principles from inception
- **Production Standards**: Built with production-ready code standards and no debug statements

### 🌍 Internationalization Updates

#### Spanish Translation Expansion

- **Complete Admin Hide Interface**: All new admin hiding features fully translated to Spanish
- **Real-Time Validation Messages**: Localized error messages and validation feedback
- **Security Notices**: Important security warnings translated for Spanish-speaking users
- **Updated Translation Files**: Version 1.1.4 with 15+ new translated strings

#### Translation System Enhancement

- **WP-CLI Integration**: Automated translation file generation and compilation
- **Binary Compilation**: Updated `.mo` files for WordPress production use
- **Version Consistency**: All translation files updated to match plugin version 1.1.4
- **Clean File Structure**: Removed backup files for optimized distribution

### 🛡️ Security Considerations

#### Admin Hide Security Warnings

- **User Education**: Clear security notices about proper usage and limitations
- **Recovery Instructions**: Guidance for users who forget custom admin paths
- **Database Recovery**: Instructions for FTP-based feature disabling if needed
- **Layered Security Reminder**: Emphasis on using with strong passwords and other security measures

#### Validation Security

- **Input Sanitization**: All user inputs properly sanitized using WordPress functions
- **Nonce Verification**: CSRF protection for all AJAX validation requests
- **Permission Checks**: Administrative capability verification for security operations
- **Error Handling**: Comprehensive error handling with secure fallback responses
- **Production Security**: Complete removal of debug statements prevents information disclosure
- **URL Parameter Security**: Enhanced auth token handling prevents parameter manipulation

## [1.1.3] - 2025-08-07

### 🔧 Minor Improvements

#### Updated Dependencies

- **silverassist/wp-github-updater**: Updated to v1.0.1 with improved changelog formatting
- **Enhanced Changelog Display**: Better HTML rendering of markdown in WordPress plugin update modal
- **Improved User Experience**: More readable release notes during automatic updates

#### Project Configuration

- **Git Attributes**: Added comprehensive `.gitattributes` file for better release management
- **Cross-platform Compatibility**: Consistent line endings (LF) across all platforms
- **Cleaner Archives**: GitHub automatic releases now exclude development files
- **Binary File Handling**: Proper Git configuration for images and compiled files

## [1.1.2] - 2025-08-07

### 🚀 Major Features

#### GitHub Updater Package Integration

- **External Package**: Migrated to reusable `silverassist/wp-github-updater` Composer package
- **Code Reusability**: Centralized update logic for use across multiple Silver Assist plugins
- **Optimized Distribution**: Smart vendor directory inclusion with production-only dependencies
- **Automatic Updates**: Seamless GitHub-based plugin updates with no breaking changes

#### WordPress 6.7+ Translation Compatibility

- **Multi-location Loading**: Robust translation system supporting global and local language directories
- **Proper Hook Timing**: Fixed "translation loading too early" warnings with `init` hook integration
- **Fallback System**: Three-tier translation loading (global → local → fallback) for maximum compatibility
- **User Locale Support**: Enhanced user experience with `get_user_locale()` integration

### 🔧 Technical Improvements

#### Build System Optimization

- **Smart Vendor Copying**: Only essential files included in distribution ZIP (excludes tests, docs, .git)
- **Production Dependencies**: Automated `composer install --no-dev` during build process
- **Size Optimization**: Reduced ZIP size while maintaining full functionality (~98KB optimized)
- **Autoloader Integration**: Seamless Composer autoloader integration with custom PSR-4 loader

#### Code Architecture

- **Updater Class Refactoring**: Simplified to extend external package with minimal configuration
- **Dependency Management**: Clean separation between development and production dependencies
- **Package Configuration**: Centralized updater configuration with plugin-specific settings

### 📦 Distribution & Installation

#### Enhanced ZIP Generation

- **Automatic Vendor Inclusion**: Build script intelligently includes only necessary Composer dependencies
- **Self-contained Installation**: Plugin ZIP includes all required external packages
- **WordPress Compatibility**: No manual Composer installation required by end users
- **Clean Architecture**: Maintains plugin folder structure without version suffixes

### 🛠️ Developer Experience

#### Package Management

- **Composer Integration**: Full support for external packages in WordPress plugin context
- **Development Workflow**: Maintained separate dev/production dependency management
- **Build Automation**: One-command release generation with optimized output

### 🌍 Internationalization

#### Translation System Enhancements

- **WordPress 6.7+ Ready**: Resolved all translation loading warnings
- **Filter Integration**: Customizable translation directory and locale detection
- **Performance Optimized**: Efficient translation file loading with proper caching

### 🔒 Security & Stability

#### Code Quality

- **Type Safety**: Maintained strict PHP 8+ type declarations throughout refactoring
- **Error Handling**: Robust error handling for Composer autoloader integration
- **WordPress Standards**: Full compliance maintained with coding standards

### 💫 Backward Compatibility

- **Zero Breaking Changes**: All existing functionality preserved
- **API Consistency**: No changes to public plugin interfaces
- **Configuration Preservation**: All user settings maintained during updates

---

## [1.1.1] - 2025-08-06

### Overview

Silver Assist Security Essentials v1.1.1 is the first stable and fully functional release of our comprehensive WordPress security plugin. This plugin addresses three critical security vulnerabilities commonly found in WordPress security audits with modern PHP 8+ architecture, centralized configuration management, and robust GraphQL protection.

### Architecture & Configuration

#### Centralized Configuration System

- **DefaultConfig Class**: Single source of truth for all plugin settings with two-tier configuration approach
- **GraphQLConfigManager**: Singleton pattern for centralized GraphQL configuration management with intelligent caching
- **Performance Optimization**: Reduced configuration overhead through centralized caching and unified option handling
- **Configuration Consistency**: Eliminated duplicate configuration logic across all components

#### Modern PHP 8+ Implementation

- **PSR-4 Autoloading**: Organized namespace structure (`SilverAssist\Security\{ComponentType}\{ClassName}`)
- **Strict Type Declarations**: Full PHP 8+ type safety with union types and match expressions
- **WordPress Function Integration**: Proper `\` prefixes for all WordPress functions in namespaced contexts
- **Use Statement Standards**: Alphabetical sorting and same-namespace exclusion rules across all PHP files
- **String Consistency**: Modern string interpolation patterns and double quote consistency throughout codebase
- **Singleton Patterns**: Efficient resource management and configuration centralization

### Core Security Features

#### WordPress Admin Login Protection

- **Brute Force Protection**: Configurable IP-based login attempt limiting (1-20 attempts)
- **Session Management**: Advanced session timeout control (5-120 minutes)  
- **User Enumeration Protection**: Standardized error messages prevent user discovery
- **Strong Password Enforcement**: Mandatory complex password requirements (12+ chars, mixed case, numbers, symbols)
- **Bot and Crawler Blocking**: Advanced detection and blocking of automated reconnaissance tools
- **Security Scanner Defense**: Protection against Nmap, Nikto, WPScan, and similar security scanners
- **404 Response System**: Returns "Not Found" responses to suspicious requests to hide admin interface

#### HTTPOnly Cookie Security

- **Automatic HTTPOnly Flags**: Applied to all WordPress authentication cookies
- **Secure Cookie Configuration**: Automatic secure flags for HTTPS sites
- **SameSite Protection**: CSRF attack prevention through SameSite cookie attributes
- **Domain Validation**: Proper cookie scoping and security

#### Advanced GraphQL Security System

- **Hybrid GraphQL Protection**: Complete integration with WPGraphQL plugin
- **Centralized Configuration Management**: Single source of truth for all GraphQL settings through GraphQLConfigManager
- **Intelligent Query Analysis**: Enhanced complexity estimation with field counting, connection analysis, and nesting detection
- **Introspection Control**: Production-safe introspection blocking with WPGraphQL coordination
- **Query Depth Limits**: Configurable depth validation (1-20 levels, default: 8) with WPGraphQL native integration
- **Query Complexity Control**: Advanced complexity scoring system (10-1000 points, default: 100)
- **Query Timeout Protection**: Execution timeout enforcement (1-30 seconds, default: 5)
- **Adaptive Rate Limiting**: Intelligent rate limiting (30 requests/minute per IP) with headless CMS support
- **Alias Abuse Protection**: Prevention of query alias multiplication attacks
- **Field Duplication Blocking**: Protection against field duplication DoS attempts
- **Directive Limitation**: Control over GraphQL directive usage
- **Headless CMS Mode**: Specialized configuration for headless WordPress implementations
- **WPGraphQL Native Integration**: Seamless coordination with WPGraphQL's built-in security features

### Technical Architecture

#### Modern PHP 8+ Implementation

- **PSR-4 Autoloading**: Organized namespace structure (`SilverAssist\Security\{ComponentType}\{ClassName}`)
- **Strict Type Declarations**: Full PHP 8+ type safety with union types and match expressions
- **Singleton Patterns**: Efficient resource management and configuration centralization
- **Component-based Architecture**: Modular design with clear separation of concerns

#### GraphQL Configuration Management

- **GraphQLConfigManager**: Centralized configuration system for all GraphQL settings
- **Intelligent Caching**: Performance optimization through transient-based caching
- **WPGraphQL Detection**: Automatic plugin detection and compatibility checking
- **Security Evaluation**: Real-time security assessment and recommendations
- **Configuration HTML Generation**: Formatted display for admin interface integration

#### WordPress Integration Standards

- **WordPress Coding Standards**: Full compliance with WordPress PHP coding standards
- **Hook System Integration**: Proper use of WordPress actions and filters with appropriate priorities
- **Database Operations**: WordPress options API and transients (no custom tables)
- **Admin Interface**: Native WordPress admin UI patterns and styling
- **Internationalization**: Complete i18n support with Spanish translation included
- **Security Best Practices**: Input sanitization, output escaping, nonce verification, and capability checks

### User Interface

#### Real-time Admin Dashboard

- **Live Security Monitoring**: AJAX-powered dashboard updates every 5 seconds
- **Visual Compliance Indicators**: Clear status display for each security vulnerability
- **Interactive Controls**: Toggle switches and sliders for configuration
- **Statistics Display**: Real-time metrics for failed logins, blocked IPs, and GraphQL queries
- **Multi-language Support**: Full English and Spanish interface support

### System Requirements & Compatibility

- **WordPress**: 6.5+ (tested up to latest)
- **PHP**: 8.0+ (optimized for PHP 8.3)
- **WPGraphQL**: Optional but recommended for GraphQL features
- **Browser Support**: Modern browsers with JavaScript enabled for admin interface

### Development Features

- **Composer Support**: Complete development environment with PHPCS, PHPUnit
- **GitHub Integration**: Direct updates from SilverAssist/silver-assist-security repository
- **Automatic Updates**: Version checking and notification system
- **Debug Logging**: Comprehensive debug information for troubleshooting
- **Translation Support**: Complete i18n implementation with WP-CLI integration

This release represents a complete, production-ready WordPress security solution that addresses critical vulnerabilities while maintaining high performance and WordPress compatibility standards.
