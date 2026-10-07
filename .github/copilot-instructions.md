# Silver Assist Security Essentials — Project Context

Silver Assist Security Essentials is a WordPress plugin that resolves critical security vulnerabilities found in WordPress security audits. It provides login protection with brute force prevention and bot blocking, HTTPOnly cookie enforcement with SameSite/Secure flags, and comprehensive GraphQL endpoint security including introspection blocking, query limits, and rate limiting.

| Field | Value |
|-------|-------|
| **Namespace** | `SilverAssist\Security` |
| **Text Domain** | `silver-assist-security` |
| **Version** | See `SILVER_ASSIST_SECURITY_VERSION` constant |
| **PHP** | 8.2+ |
| **WordPress** | 6.5+ |

## Documentation Rule

All project documentation lives in **README.md**, **CHANGELOG.md**, and this file only.
Never create standalone `.md` files (`docs/`, `CONTRIBUTING.md`, `API.md`, etc.).

**Exceptions** — Copilot AI configuration files may be created freely:

- `.github/skills/<topic>/SKILL.md` — domain knowledge for Copilot
- `.github/prompts/<task>.prompt.md` — reusable prompt templates
- `.github/instructions/<scope>.instructions.md` — scoped coding context
- `.github/pull_request_template.md` — GitHub pull request checklist (configuration, not documentation)

## Security Modules

### Login Protection (`Security\LoginSecurity`)
- IP-based login attempt limiting (1–20 configurable) with transient-based blocking
- Session timeout management (5–120 minutes), user enumeration protection
- Strong password enforcement (8+ chars, mixed case, numbers, symbols)
- Bot/crawler detection and blocking (Nmap, Nikto, WPScan, etc.)
- 404 responses to automated reconnaissance tools; the 16th login-page request per minute from one IP also gets a 404, and the 5-attempt lockout is per IP (people behind one IP share both; see the README section on shared IPs)
- Never construct a component with `new` when a shared `::instance()` exists (the admin data provider did, and every failed login counted twice)

### Cookie Security (`Security\GeneralSecurity`)
- Automatic HTTPOnly flag for all WordPress authentication cookies
- Secure flag (HTTPS), SameSite attribute (CSRF protection)
- Security headers (nosniff, X-Frame-Options SAMEORIGIN, X-XSS-Protection, Referrer-Policy, Permissions-Policy, HSTS on SSL; no CSP), WordPress hardening (XML-RPC blocking, version hiding)

### GraphQL Security (`GraphQL\GraphQLSecurity` + `GraphQL\GraphQLConfigManager`)
- WPGraphQL detection and conditional loading
- Introspection blocking in production
- Query depth (1–20, default 8), complexity (10–1000, default 100), timeout (1–30s, default 5)
- Rate limiting (30 req/min per IP) with intelligent adaptive limits
- Alias abuse, field duplication, and directive limitation protection
- Headless CMS mode configuration
- **All GraphQL settings MUST go through `GraphQLConfigManager` singleton**

### Two separate IP protections (#146)
- **Login lockout by IP** (`Security\LoginSecurity`): the original block, applied to the login only; own counters, own dashboard figure ("Locked-out IPs"), configured in the Login Security tab.
- **Form flood blacklist** (`Security\IPBlacklist` + `ContactForm7Integration` + `FormProtection`): added after an attack on one site that sent CF7 submits within seconds; `ContactForm7Integration::validate_cf7_submission()` is the only caller of `IPBlacklist::is_blacklisted()`. **Protecting only Contact Form 7 is by design**: do not wire the blacklist into login, REST, GraphQL or the front end, and do not label it "IP Blacklist" or "Blocked IPs" in a UI string without the form scope.
- Decision: keep them as separate implementations, no shared limiter class. Shared on purpose and only through `SecurityHelper`: `get_client_ip()`, the IPv6 `/64` grouping in `generate_ip_transient_key()` and, for the login and REST/GraphQL limiters, `increment_rate_window()`. Known follow-up: `FormProtection::allow_form_submission()` still uses a plain transient counter.
- README "Two IP Protections" has the comparison table; `IPProtectionScopeTest` pins that neither protection affects the other.

### Contact Form 7 Integration (`Security\ContactForm7Integration`)
- Automatic CF7 plugin detection via `SecurityHelper::is_contact_form_7_active()`
- Form submission rate limiting with IP tracking (options `silver_assist_cf7_rate_limit` / `silver_assist_cf7_rate_window`, the only ones enforcement, dashboard and settings use; legacy `silver_assist_form_rate_*` are migrated by `DefaultConfig::migrate_legacy_options()`; counted with `SecurityHelper::increment_rate_window()`)
- Honeypot, minimum submission time (ms, signed hidden `silver_form_ts` field, unchecked when absent or forged) and manual block duration are registry options with fields on the Form Protection tab (#178); the obsolete browser, SQL injection and spam pattern checks are always on, and their former options live in `DefaultConfig::LEGACY_OPTIONS_DROPPED` so uninstall still removes them. Do not re-add a default nothing reads
- Conditional "Form Protection" admin tab (appears only when CF7 detected)

## Bootstrap Architecture

Built on `silverassist/wp-plugin-kernel`'s `AbstractPlugin`/`LoadableInterface` pattern
(singleton `instance()`, priority-ordered `get_components()`, per-component error
isolation). Every security/admin component implements `LoadableInterface`
(`init()`, `get_priority()`, `should_load()`) and exposes its own `instance()`.

Split across **three loading tiers**, each its own `AbstractPlugin` subclass, because
components have genuinely different WordPress hook-timing requirements — a single
bootstrap hook can't serve all of them:

| Tier | Class | Hook | Components | Why this timing |
|------|-------|------|------------|------------------|
| 1 | `Core\SecurityLoader` | `plugins_loaded` @ 1 | LoginSecurity, GeneralSecurity, RestAPISecurity, LoginBranding, AdminHideSecurity | Auth/login hooks wp-login.php can act on before `init` fires |
| 2 | `GraphQL\GraphQLLoader` | `plugins_loaded` @ 5 | GraphQLSecurity | Must register `determine_current_user` before WP resolves the current user, but late enough for WPGraphQL to define its class |
| 3 | `Core\Plugin` (root) | `init` | AdminPanel, ContactForm7Integration | Everything else — matches the default kernel bootstrap timing |

`Core\Activator` holds the static `activate()`/`deactivate()`/`uninstall()` handlers,
registered directly against `register_activation_hook()` etc. from the main file
(extracted from the pre-1.5.1 `SilverAssistSecurityBootstrap` class).

## Key Classes

| Class | Purpose |
|-------|---------|
| `Core\Plugin` | Root plugin singleton (`init` tier) — see Bootstrap Architecture above |
| `Core\SecurityLoader` | `plugins_loaded`@1 tier loader |
| `GraphQL\GraphQLLoader` | `plugins_loaded`@5 tier loader |
| `Core\Activator` | Activation/deactivation/uninstall handlers |
| `Core\DefaultConfig` | Centralized defaults for all plugin settings (single source of truth) |
| `Core\SecurityHelper` | Static utilities: asset URLs, IP detection, bot detection, logging, AJAX validation, password checks |
| `Core\Updater` | GitHub-based automatic update system |
| `Core\PathValidator` | The one validator of the custom admin path: length, characters, forbidden keywords, reserved core slugs (`wp-json`, `feed`, `wp-cron`, `xmlrpc`, `sitemap`, rewrite bases and the REST prefix of the site) and collisions with existing pages, posts and specific rewrite rules |
| `Admin\AdminPanel` | Admin orchestration — registers with Settings Hub or standalone menu |
| `Admin\Renderer\AdminPageRenderer` | 5-tab navigation with `.silver-nav-tab` namespace separation |
| `Admin\Renderer\SettingsRenderer` | Settings tab content rendering; one `<form>` and one Save per tab (`{tab}-form`, `{tab}-submit`) ending in a sticky save bar (`.silver-save-bar`, a `role="status"` region and Discard); every form posts the gate field, a `settings_tab` and `_wpnonce` |
| `Admin\Settings\SettingsRegistry` | Every option the settings screen saves, declared once: section, type, range, UI field; `TABS` maps each tab to the sections its form saves |
| `Admin\Settings\SettingsSaver` | The only code that unslashes and writes those options from the screen (`save_tab( $input, $tab )` and `save( $input, $section )` return a `SaveResult`; a value that cannot be stored lands in `errors` with what was typed in `submitted`, nothing is written). The Admin Hide section is safe: a bad path never enables it, turning it on or changing the path while on needs the `silver_assist_admin_hide_confirm` checkbox, turning it off is never blocked, and the rewrite rules are flushed when the toggle or path changes |
| `Admin\Settings\SettingsSanitizer` | The one place that sanitizes and clamps a value per registry type; the saver uses it and `register()` attaches it as the `sanitize_callback` of every registry option, so `options.php`, REST `/wp/v2/settings`, WP-CLI and imports are sanitized too |
| `Admin\Settings\SettingsHandler` | Authorizes a Save button post (gate field, `manage_options`, nonce), delegates to the saver and keeps the result (`last_result()`) so the renderer shows each message next to its field |
| `Admin\Renderer\DashboardRenderer` | Real-time security monitoring dashboard |
| `Security\LoginSecurity` | Brute force protection and bot blocking |
| `Security\GeneralSecurity` | HTTPOnly cookies and WordPress hardening |
| `Security\AdminHideSecurity` | Admin login page protection |
| `Security\ContactForm7Integration` | CF7 form protection |
| `Security\FormProtection` | Generic form protection base |
| `GraphQL\GraphQLSecurity` | GraphQL endpoint protection |
| `GraphQL\GraphQLConfigManager` | Centralized GraphQL configuration singleton |

## File Structure

```
silver-assist-security/
├── silver-assist-security.php     # Thin bootstrap: constants, Composer autoload, 3-tier hook wiring
├── src/
│   ├── Admin/AdminPanel.php + Renderer/ (AdminPageRenderer, SettingsRenderer, DashboardRenderer)
│   ├── Admin/Settings/ (SettingsRegistry, SettingsSaver, SettingsSanitizer, SaveResult, SettingsHandler), Admin/Ajax/ (SecurityAjaxHandler, ...)
│   ├── Core/ (Plugin, SecurityLoader, Activator, DefaultConfig, SecurityHelper, PathValidator, Updater)
│   ├── Security/ (LoginSecurity, GeneralSecurity, AdminHideSecurity, ContactForm7Integration, FormProtection)
│   └── GraphQL/ (GraphQLSecurity, GraphQLLoader, GraphQLConfigManager)
├── assets/css/ (variables.css, admin.css, password-validation.css)
├── assets/js/ (admin.js, password-validation.js, escape-html.js)
├── languages/ (.pot, .po, .mo files)
└── tests/ (Unit/, Security/, WordPress/, Helpers/)
```

## Plugin-Specific Patterns

### SecurityHelper — Mandatory Usage
All utility functions are centralized in `SecurityHelper`. **Never duplicate this logic in other classes:**
- `get_asset_url($path)` — asset URLs with SCRIPT_DEBUG-aware minification
- `get_client_ip()` — client IP from `REMOTE_ADDR`; `X-Forwarded-For` is read only from trusted proxies (see README, "Proxies, Load Balancers and CDNs")
- `is_bot_request()` — bot and crawler detection
- `send_404_response()` — security 404 responses
- `log_security_event($type, $message, $context)` — structured JSON security logging
- `validate_ajax_request($nonce_action)` — AJAX security validation
- `is_strong_password($password)` — password strength validation
- `is_contact_form_7_active()` — CF7 plugin detection
- `generate_ip_transient_key($ip)` — rate limiting keys
- `format_time_duration($seconds)` — human-readable durations

### Settings Hub Integration
AdminPanel registers with the Silver Assist Settings Hub when available, with standalone fallback. Uses `SettingsHub::get_instance()->register_plugin(...)` with `get_hub_actions()` for the "Check Updates" button.

### Admin Tab Navigation
Uses `.silver-nav-tab` / `.silver-tab-content` classes (not `.nav-tab`) to avoid conflicts with Settings Hub:
`dashboard-tab` | `login-security-tab` | `graphql-security-tab` | `cf7-security-tab` (conditional) | `ip-management-tab`

### DefaultConfig Pattern
Always use `DefaultConfig::get_option("silver_assist_login_attempts")` instead of raw `get_option()` with hardcoded defaults.

### GraphQLConfigManager Pattern
All GraphQL config MUST use the singleton — never duplicate WPGraphQL detection or config logic. Key methods: `get_rate_limit()`, `get_query_depth()`, `get_query_complexity()`, `is_headless_mode()`, `is_wpgraphql_active()`, `evaluate_security_level()`, `get_all_configurations()`.

### CSS Design System
All styles use CSS custom properties from `variables.css` (prefix `--silver-*`). Never hardcode colors, spacing, or typography values. Build: PostCSS + cssnano for CSS; Grunt + uglify for JS (`npm run build`).

### Admin JavaScript Escaping
Never concatenate a string into `.html()`, `.append()`, `.after()` or a template literal that builds markup. Use `escapeHtml()` from `assets/js/escape-html.js` (`window.SilverAssistSecurityUtils`, a dependency of `admin.js` and `password-validation.js`), `.text()` or `.attr()`; use `safeUrl()` for an `href`. Only HTML escaped on the server (the CF7 panel's `data.html`) is inserted as is. Covered by `tests/e2e/admin-js-escaping.spec.ts`.

### WordPress Options
All options use `silver_assist_` prefix (e.g., `silver_assist_login_attempts`, `silver_assist_graphql_query_depth`, `silver_assist_session_timeout`, `silver_assist_bot_protection`, `silver_assist_graphql_headless_mode`).

`Activator::uninstall()` must remove everything the plugin writes: a new option goes in `DefaultConfig` (or `Activator::LEGACY_OPTIONS` if retired), a new transient family needs its prefix in `Activator::TRANSIENT_PREFIXES`, and `UninstallCleanupTest` seeds each key. Build transient keys with `SecurityHelper::generate_ip_transient_key( $prefix, $ip )` (prefix first).

**Multisite is not supported or tested.** The plugin targets single-site installs only (the maintainer's decision, #151): do not add multisite code paths, and do not claim multisite compatibility.

## TDD Requirement

This is a security plugin — **all features must be developed test-first** (Red → Green → Refactor). Security classes require 100% test coverage.

**Behavior-test policy** (see README "Behavior-Test Policy (TDD)"): a bug fix starts with a test that reproduces it and fails; a new hardening feature is tested twice, that the protection works and that the core features it could break still work (block editor, REST, assets, login, embeds), including ones with no obvious link. Prefer real WordPress flows over mocks and assert user-visible behavior, never only that a hook is registered. Prove every new test fails without the fix. Examples to copy: `tests/Integration/EditorCompatibilityTest.php` and `OEmbedSanitizationTest.php` (integration), `tests/e2e/editor.spec.ts` (E2E). Pull requests use `.github/pull_request_template.md`. Tests use WordPress Test Suite (`WP_UnitTestCase`) with real database. Plugin-specific test layout:

- `tests/Unit/` — DefaultConfigTest, SecurityHelperTest, GraphQLConfigManagerTest, LoginSecurityTest
- `tests/Security/` — SecurityTest (overall security validation)
- `tests/WordPress/` — AdminPanelTest (integration examples)
- `tests/Helpers/` — TestHelper (shared utilities)
- `tests/Helpers/HeadlessTestSupport.php` — trait for tests that run real REST and GraphQL requests: `require_wpgraphql()` (fails instead of skipping when `CI` is set), `set_environment_type()` (never `define( 'WP_ENVIRONMENT_TYPE' )` in a test, it leaks into every later test), `resolve_current_user()`, `restore_headless_state()`
- Headless behavior tests (`RestAPIHeadlessBehaviorTest`, `GraphQLHeadlessBehaviorTest`) send requests through `rest_do_request()` and WPGraphQL's `graphql()` and assert what a client receives; do not assert only that a hook is registered
- Login and admin hiding behavior: `LoginLockoutBehaviorTest`, `AdminHideRoutingTest`, plus Playwright specs in `tests/e2e/admin-hide/` (`npm run test:e2e:admin-hide`, own config `playwright.admin-hide.config.ts`; `tests/e2e/utils/wp-cli.ts` arranges state through `wp-env run cli`; give each describe block its own `X-Forwarded-For` so per-IP limits do not collide)

## Quick References

| Item | Value |
|------|-------|
| Main file | `silver-assist-security.php` |
| Namespace | `SilverAssist\Security` |
| Text domain | `silver-assist-security` |
| Options prefix | `silver_assist_` |
| CSS variable prefix | `--silver-*` |
| Nav tab class | `.silver-nav-tab` / `.silver-tab-content` |
| Build command | `npm run build` |
| Quality checks | `bash scripts/run-quality-checks.sh` |
| WP test install | `scripts/install-wp-tests.sh wordpress_test root '' localhost latest` |
| GitHub repo | `SilverAssist/silver-assist-security` |
| Constants | `SILVER_ASSIST_SECURITY_VERSION`, `SILVER_ASSIST_SECURITY_PATH`, `SILVER_ASSIST_SECURITY_URL`, `SILVER_ASSIST_SECURITY_BASENAME` |

## Behavior Audit Matrix

Audit of every WordPress hook the plugin registers or removes under `src/` (plus the bootstrap in `silver-assist-security.php`), written for sub-issue #130 of epic #124. It answers, per hook: which core behavior changes, for whom, how risky a regression is, and which test proves it. Re-audited against WordPress 7.1.2 and WPGraphQL 2.23.1 core source.

How to read it:

- **Test** cells name a real test as `<path under tests/>::<method>`; `E2E` entries are Playwright titles in `tests/e2e/`. **Reg** means the test only asserts the hook is registered (`has_action`/`has_filter`), not what a user sees. **GAP Gn** points to the Gaps list at the end.
- **Risk**: high = a regression locks users out, breaks the editor or REST, or removes a protection silently; medium = visible breakage for one role or context; low = cosmetic or admin-only.
- **Context** values: front end (FE), wp-admin (ADM), block editor (ED), REST, AJAX, login (LOG), cron, WP-CLI, headless (GraphQL or REST clients).
- Keep this section current: a PR that adds, removes or re-prioritises a `add_action`/`add_filter`/`remove_action`/`remove_filter` in `src/` must add or update its row and name the test. A hook with only a **Reg** test is a gap, not coverage.

Tests added by the epic: #127 (suite completes), #128 (`ClientIpResolutionTest`), #129 (`OEmbedSanitizationTest`), #131 (`LoginLockoutBehaviorTest`, `AdminHideRoutingTest`, `tests/e2e/admin-hide/`), #132 (`RestAPIHeadlessBehaviorTest`, `GraphQLHeadlessBehaviorTest`), #133 (`GeneralHardeningBehaviorTest`, `FormSubmissionBehaviorTest`), WEB-1222 (`AssetVersioningTest`, `RestUsersEndpointTest`, `EditorCompatibilityTest`, `tests/e2e/editor.spec.ts`).

### 1. Bootstrap, lifecycle and cron

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `plugins_loaded` (p1) | main file closure: `SecurityHelper::init`, `SecurityLoader` | Loads login, general, REST, admin-hide and IP components before `init`, so `wp-login.php` can act early | all, including cron and WP-CLI | high | Reg: `Integration/WordPressHooksIntegrationTest::test_wordpress_init_hooks_registration`; every E2E spec boots the plugin this way; tier order is recorded at boot and asserted by `Integration/PluginLoadingTiersTest::test_tiers_register_in_their_own_priority_order` |
| `plugins_loaded` (p5) | main file closure: `GraphQLLoader` | Registers GraphQL API-key auth before WP resolves the user, after WPGraphQL defines its class | headless | high | `Integration/GraphQLSecurityIntegrationTest::test_graphql_security_initializes_with_wpgraphql`; timing: `Integration/PluginLoadingTiersTest::test_api_key_auth_is_registered_before_the_user_is_resolved` (probes in `tests/bootstrap.php` record the state before the first user resolution), `::test_api_key_request_authenticates` |
| `init` (p1) | `SettingsSanitizer::register` | `register_setting` with a registry-driven `sanitize_callback` for every plugin option (group `silver_assist_security_<section>`, not exposed to REST), so a value written outside the saver (`options.php`, REST settings route for a site that exposes an option, WP-CLI, import) is clamped, normalized and, for the admin path, validated; a refused path keeps the stored one and queues a settings error | all, including REST and WP-CLI | high | `Integration/RegisteredSettingsSanitizeTest::test_every_registry_option_has_a_sanitize_callback`, `::test_update_option_clamps_integers`, `::test_update_option_normalizes_booleans`, `::test_update_option_sanitizes_url_color_and_user`, `::test_update_option_refuses_bad_admin_path`, `::test_bad_admin_path_without_previous_value_uses_default`, `::test_rest_settings_route_clamps`, `::test_options_are_allowed_in_a_group` |
| `init` | main file closure: `Plugin::init` | Loads admin panel, CF7 integration, updater, textdomain, cron, action links | all | medium | `Integration/WordPressHooksIntegrationTest::test_wordpress_init_hooks_registration` (Reg) |
| activation hook | `register_activation_hook` to `Activator::activate` | Creates default options, flushes rewrite rules | ADM, WP-CLI | medium | `Functional/PluginInstallationTest::test_plugin_activation_creates_required_options`; `Integration/WordPressHooksIntegrationTest::test_plugin_lifecycle_hooks` (call `activate()` directly) |
| deactivation hook | `register_deactivation_hook` to `Activator::deactivate` | Deletes GraphQL rate-limit transients (`graphql_rate_*`), unschedules the `silver_assist_security_cleanup` cron event, flushes rewrites | ADM, WP-CLI | low | `Functional/PluginInstallationTest::test_plugin_deactivation_preserves_settings` (options only); `Integration/UninstallCleanupTest::test_deactivate_clears_cron_event` |
| uninstall hook | `register_uninstall_hook` to `Activator::uninstall` | Deletes every plugin option (defaults plus legacy names), every plugin transient family (value and timeout rows), the blacklist index option, the `last_activity` user meta and the cleanup cron event; single-site only | ADM, WP-CLI | low | `Functional/PluginInstallationTest::test_plugin_uninstall_removes_options`; `Integration/UninstallCleanupTest::test_uninstall_leaves_nothing_behind`, `::test_uninstall_keeps_unrelated_data` |
| `admin_notices` (main file) | closure | PHP below 8.2 notice, plugin does not load | ADM | low | none, not worth testing: it only runs when PHP is below 8.2, which no supported runner provides, and the `PHP_VERSION` constant cannot be changed (G8 closed as intentionally untested) |
| `plugin_action_links_` + basename | `Plugin::add_action_links` | Adds links on the Plugins screen | ADM | low | `Integration/AuditResidualsBehaviorTest::test_plugins_screen_shows_a_settings_link` |
| `silver_assist_security_cleanup` (cron) | `IPBlacklist::run_scheduled_cleanup`, scheduled by `IPBlacklist::init_cron_cleanup` (daily 3 AM) and `schedule_next_cleanup` | Daily purge of expired IP violation records and of expired entries in the blacklist index (`silver_assist_ip_blacklist_index`); the options-table scans are skipped with a persistent object cache, which expires its own entries | cron | medium | `Unit/IPBlacklistDataTest::test_clean_expired_violations_removes_old_entries` covers the purge only; `Integration/SecurityFeaturesIntegrationTest::test_security_cron_integration` and `Integration/WordPressHooksIntegrationTest::test_wordpress_cron_integration` exercise core scheduling; `Integration/AuditResidualsBehaviorTest::test_cleanup_cron_is_scheduled_once_and_purges_expired_rows` covers the plugin's wiring and a real purge |

### 2. Response headers and information disclosure (`GeneralSecurity`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `send_headers`, `admin_init`, `login_init` | `add_security_headers` | Sends nosniff, Referrer-Policy, Permissions-Policy, HSTS (https only, not in development), no `X-Frame-Options: DENY` so same-origin framing (editor preview, customizer) keeps working | FE, ADM, LOG, ED | high | `Integration/GeneralHardeningBehaviorTest::test_baseline_headers_are_sent_in_every_context`, `::test_headers_do_not_forbid_same_origin_framing`, `::test_headers_can_be_adjusted_with_a_filter`, `::test_hsts_only_on_ssl_outside_development`, `::test_hsts_not_sent_in_development`; E2E `assets-and-headers.spec.ts` "security headers are present @smoke" |
| `rest_pre_serve_request` | `add_rest_security_headers` | Same headers on REST responses; must not change the served flag | REST, ED, headless | medium | `Integration/GeneralHardeningBehaviorTest::test_rest_header_hook_does_not_change_served_flag`, `::test_baseline_headers_are_sent_in_every_context` |
| `the_generator` | `remove_version` | Empty generator string in feeds and head | FE | low | `Security/GeneralSecurityTest::test_wordpress_version_removed`; `Integration/EditorCompatibilityTest::test_generator_tag_is_not_printed`; E2E "front end does not print the generator tag or WP version @smoke" |
| `init` | `remove_unnecessary_headers` (adds the `wp_head` removals below and the oEmbed route filter) | Cleans `<head>` | FE, REST | medium | see the two rows below |
| `wp_head` (remove) | `rsd_link`, `wp_shortlink_wp_head`, `wp_generator`, `wp_oembed_add_host_js`, plus no-ops on current core: `wlwmanifest_link`, `index_rel_link`, `parent_post_rel_link`, `start_post_rel_link`, `adjacent_posts_rel_link_wp_head` | Removes RSD, shortlink, generator and legacy relation links from `<head>` | FE | low | `Integration/GeneralHardeningBehaviorTest::test_wp_head_drops_generator_rsd_shortlink_and_oembed_discovery`, `::test_wp_head_keeps_rest_discovery`; `Security/GeneralSecurityTest::test_unnecessary_headers_removed` (Reg). `Integration/AuditResidualsBehaviorTest::test_head_has_no_adjacent_post_relation_links` (prev and next links; the other legacy relation functions are no longer hooked by core) |
| `wp_head` (remove) | `wp_oembed_add_discovery_links` (default priority) | Hides oEmbed discovery tags. Core 6.9+ hooks it at priority 4 and 10, but the priority 4 copy returns early once the priority 10 hook is gone (back-compat check in `embed.php`), so removing the default priority is enough | FE | low | `Integration/GeneralHardeningBehaviorTest::test_wp_head_has_no_oembed_discovery_with_core_hooks` (loads core's own `default-filters.php`), `::test_wp_head_drops_generator_rsd_shortlink_and_oembed_discovery` |
| `wp_head` (remove) | `feed_links` (p2), `feed_links_extra` (p3), behind `silver_assist_security_remove_feed_links` | Removes feed autodiscovery tags, feeds keep working | FE | medium | `Integration/GeneralHardeningBehaviorTest::test_feed_discovery_removed_but_feed_urls_still_exist`, `::test_feed_discovery_can_be_kept_with_a_filter` |
| `rest_endpoints` (added inside `remove_unnecessary_headers`) | closure | Hides `/oembed/1.0/embed` from visitors who cannot `edit_posts`; keeps `/oembed/1.0/proxy` for the Embed block | REST, ED | high | `Integration/EditorCompatibilityTest::test_anonymous_oembed_provider_route_is_hidden`, `::test_editor_has_required_route`; `Integration/OEmbedSanitizationTest::test_editor_proxy_still_serves_the_embed`; E2E "anonymous oEmbed provider route is hidden", "Embed block can be inserted and resolves through the oEmbed proxy @smoke" |
| `script_loader_src`, `style_loader_src` | `remove_version_query_string` (p10, 2 args) | Strips `?ver=` on public front-end assets; keeps it in wp-admin, AJAX and core bundles | FE, ADM, ED | high | `Integration/AssetVersioningTest::test_front_end_theme_asset_version_is_removed`, `::test_core_dist_asset_keeps_version_on_front_end`, `::test_editor_bundles_keep_version_in_admin`, `::test_third_party_admin_asset_keeps_version`, `::test_version_kept_during_ajax`, `::test_filter_can_keep_version`, `::test_other_query_args_preserved`; `Security/GeneralSecurityTest::test_version_query_string_removed`; E2E "front end hides plugin asset versions but keeps core versions", "editor bundles keep their cache-buster in wp-admin @smoke", "wp-admin core scripts load without 404s" |
| `xmlrpc_enabled`, `xmlrpc_methods` | `filter_xmlrpc_enabled`, `remove_xmlrpc_methods` | Disables XML-RPC unless the `silver_assist_security_disable_xmlrpc` filter returns false | FE (xmlrpc.php), mobile apps, Jetpack | medium | `Integration/GeneralHardeningBehaviorTest::test_xmlrpc_is_disabled`, `::test_xmlrpc_can_be_reenabled_with_a_filter`, `::test_plugin_has_no_first_party_xmlrpc_client`; `Security/GeneralSecurityTest::test_xmlrpc_disabled` |
| `after_setup_theme` | `remove_admin_bar_for_non_admins` | Admin bar hidden on the front end for everyone without `manage_options` (editors and authors lose the "Edit" shortcut) | FE | medium | `Integration/GeneralHardeningBehaviorTest::test_admin_bar_front_end_visibility_by_role`; `Security/GeneralSecurityTest::test_admin_bar_removed_for_non_admins` |
| `wp_before_admin_bar_render` | `remove_wp_logo` | Removes the W menu from the admin bar | ADM, FE (admins) | low | `Integration/AuditResidualsBehaviorTest::test_admin_bar_has_no_wordpress_logo_menu`; `Security/GeneralSecurityTest::test_wordpress_branding_removed` |
| `admin_footer_text` | `change_admin_footer` | Replaces the footer credit | ADM | low | `Integration/GeneralHardeningBehaviorTest::test_file_editing_is_disallowed_and_footer_branded`; `Security/GeneralSecurityTest::test_wordpress_branding_removed` |
| constant `DISALLOW_FILE_EDIT` | `disable_file_editing` (defined at hook registration) | Theme and plugin file editors disappear | ADM | medium | `Integration/GeneralHardeningBehaviorTest::test_file_editing_is_disallowed_and_footer_branded`; `Security/GeneralSecurityTest::test_file_editing_disabled` |

### 3. Cookies, sessions and login messages

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `secure_auth_cookie` | `force_secure_cookies` | Auth cookie Secure only over TLS (honours TLS-terminating proxies) | LOG, ADM | high | `Integration/GeneralHardeningBehaviorTest::test_auth_cookies_are_secure_only_over_https`, `::test_auth_cookies_behind_tls_terminating_proxy`; `Security/GeneralSecurityTest::test_secure_cookies_configuration` |
| `secure_logged_in_cookie` | `force_secure_logged_in_cookie` | Follows core's home-URL scheme rule, never Secure over HTTP | LOG, FE | high | `Integration/GeneralHardeningBehaviorTest::test_logged_in_cookie_follows_core_home_scheme_rule` |
| `init` | `configure_secure_cookies` | `session_set_cookie_params` for PHP sessions (WordPress core does not use them) | FE | low | `Integration/AuditResidualsBehaviorTest::test_session_cookies_are_httponly_and_samesite_lax` (runs the method in a clean PHP process: it does nothing once output has started) |
| `auth_cookie_expiration` | `enforce_session_cookie_lifetime` (p10, 3 args) | Cookie lifetime equals the session timeout, ignoring Remember Me | LOG | medium | `Integration/GeneralHardeningBehaviorTest::test_auth_cookie_expiration_is_the_session_timeout`; E2E "the login form offers no Remember Me, and the session cookie follows the session timeout @smoke" |
| `login_enqueue_scripts` | `LoginSecurity::hide_remember_me` | Hides the Remember Me checkbox | LOG | low | E2E "the login form offers no Remember Me, and the session cookie follows the session timeout @smoke" |
| `login_errors` | `hide_login_errors` | One generic message on the login and lost-password screens; lockout notice and reset errors stay readable | LOG | high | `Integration/GeneralHardeningBehaviorTest::test_wrong_credentials_get_the_generic_message`, `::test_lost_password_lookup_gets_the_generic_message`, `::test_lockout_message_is_not_replaced_by_the_generic_one`, `::test_password_reset_errors_stay_actionable`; `Integration/LoginLockoutBehaviorTest::test_the_attempt_that_triggers_the_lockout_stays_generic`; `Security/GeneralSecurityTest::test_login_errors_hidden`; E2E "bad credentials show a generic message @smoke", "wrong credentials show one generic message, for real and unknown users alike @smoke" |

### 4. User enumeration (`GeneralSecurity::disable_user_enumeration`, on `init`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `rest_endpoints` | closure | Removes `/wp/v2/users` and `/wp/v2/users/<id>` unless the user can `edit_posts` (the editor author selector needs them) | REST, ED, headless | high | `Integration/RestUsersEndpointTest::test_anonymous_cannot_enumerate_users`, `::test_subscriber_cannot_enumerate_users`, `::test_editing_roles_keep_users_endpoint`, `::test_editor_can_query_authors_via_rest`, `::test_anonymous_rest_request_to_users_is_not_found`; E2E "anonymous visitors cannot enumerate users @smoke", "editor can load users and use the oEmbed proxy @smoke" |
| `template_redirect` | closure | Redirects author archives and any `?author=` request to the home page | FE | medium | `Security/GeneralSecurityTest::test_user_enumeration_disabled`; E2E "?author=1 does not reveal the author archive @smoke" ; `Integration/AuditResidualsBehaviorTest::test_pretty_author_archive_redirects_home` |
| `author_link` | closure | Every author link points to the home URL, in the front end and in wp-admin lists | FE, ADM | medium | `Integration/EditorCompatibilityTest::test_author_link_does_not_disclose_user_archive` |

### 5. REST API (`RestAPISecurity`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `rest_pre_dispatch` (p10) | `restrict_batch_endpoint` | `/batch/v1` is forbidden to anonymous clients | REST, headless | medium | `Integration/RestAPIHeadlessBehaviorTest::test_batch_endpoint_is_forbidden_for_anonymous_clients`, `::test_other_routes_are_not_caught_by_the_batch_restriction`, `::test_batch_endpoint_works_for_an_editor`; `Integration/RestAPISecurityIntegrationTest::test_batch_endpoint_blocked_unauthenticated`; `Unit/Security/RestAPISecurityTest::test_batch_endpoint_restricted_for_unauthenticated`, `::test_batch_endpoint_protection_can_be_disabled` |
| `rest_pre_dispatch` (p11) | `rate_limit_rest_api` | Per-IP fixed window for anonymous REST requests, 429 when exceeded; logged-in and application-password clients exempt | REST, headless, FE (fetches) | high | `Integration/RestAPIHeadlessBehaviorTest::test_anonymous_requests_pass_up_to_the_limit_and_the_next_one_gets_429`, `::test_throttled_response_is_a_429_rest_error`, `::test_limit_and_window_follow_the_settings`, `::test_rate_limiting_can_be_disabled`, `::test_client_is_served_again_after_the_window_expires`, `::test_logged_in_users_are_not_throttled`, `::test_application_password_client_is_not_throttled`, `::test_visitors_behind_one_ip_share_the_budget_and_other_ips_are_unaffected`, `::test_graphql_requests_do_not_consume_the_rest_budget`; `Unit/Security/RestAPISecurityTest::test_atomic_increment_resets_after_window_expires`; client IP: `Integration/ClientIpResolutionTest::test_forged_headers_are_ignored_when_peer_is_public` |

### 6. Login protection (`LoginSecurity`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `login_init` (p5) | `block_suspicious_bots` | 404 for bot user agents (whole-word matching, see `SecurityHelper::matches_bot_user_agent`) and more than 15 login page requests per minute per IP (fixed window from the first request, atomic counter, IPv6 grouped by /64); reset links are exempt | LOG | high | `Integration/LoginSecurityTest::test_bot_detection_blocks_bots`, `::test_legitimate_browsers_not_blocked`, `::test_legitimate_actions_bypass_bot_protection`, `::test_password_reset_with_key_bypasses_bot_protection`, `::test_rate_limiting_blocks_excessive_requests`, `::test_repeated_bot_activity_is_logged_without_extended_block`; `Integration/LimiterRobustnessTest::test_spaced_requests_never_reach_the_limit`, `::test_real_user_agents_are_not_bots`, `::test_bot_user_agents_are_bots`; `Integration/LoginLockoutBehaviorTest::test_login_page_rate_limit_is_per_ip`, `::test_login_page_rate_limit_threshold_is_fifteen_per_minute`; E2E "the login page answers 404 from the 16th request in a minute, per IP" |
| `login_init` | `setup_login_protection` | Per-request lockout and rate setup on `wp-login.php` | LOG | medium | `Integration/LoginSecurityTest::test_wordpress_hooks_registered` (Reg); exercised by the lockout tests below |
| `login_form` | `add_login_form_security` | Adds nonce and honeypot fields to the login form (once). A failed `secure_login_nonce` check is only logged, on purpose: login pages are often page-cached, so enforcing it would lock out real users (the lockout stops guessing) | LOG | medium | `Integration/LoginSecurityTest::test_honeypot_field_in_login_form`, `::test_nonce_field_in_login_form`; `Integration/LoginLockoutBehaviorTest::test_a_failed_login_counts_once_even_with_the_admin_data_provider_loaded` |
| (called by `block_suspicious_bots`, no longer hooked to `wp_login_failed`) | `track_bot_behavior` | Logs a request turned away as bot traffic (last 10 per IP, 1 hour); no block flag (the unread `extended_bot_block_*` was removed) | LOG | low | `Integration/LoginSecurityTest::test_bot_tracking_records_activity`; `Integration/LimiterRobustnessTest::test_failed_logins_are_not_bot_activity`, `::test_bot_activity_does_not_write_an_unread_block_flag` |
| `wp_login_failed` | `handle_failed_login` | Counts failures per IP with the atomic fixed-window counter, locks out at the limit (a companion `lockout_until` transient holds its end time, read through the transient API so it works with a persistent object cache), does not extend a running lockout; IPv6 clients are grouped by /64 (`silver_assist_security_ipv6_prefix_length`) | LOG | high | `Integration/LoginSecurityTest::test_complete_login_failure_and_lockout_flow`, `::test_lockout_cannot_be_bypassed_by_rotating_forged_headers`, `::test_ip_tracking_across_multiple_attempts`, `::test_configurable_lockout_duration`; `Integration/LimiterRobustnessTest::test_lockout_does_not_depend_on_reading_the_previous_count`, `::test_lockout_message_shows_remaining_time_with_persistent_object_cache`, `::test_lockout_covers_the_whole_ipv6_prefix`; `Integration/LoginLockoutBehaviorTest::test_users_behind_one_ip_share_the_lockout`, `::test_attempts_during_lockout_do_not_extend_it`, `::test_lockout_expires_and_the_ip_can_log_in_again`; E2E "five failed logins lock the IP out, even for the right password @smoke", "the lockout ends on time even when the locked-out person keeps trying", "colleagues behind one IP share the failed-login budget, other IPs are unaffected" |
| `authenticate` (p30) | `check_login_lockout` | Rejects authentication while the IP is locked out | LOG, REST (basic auth) | high | `Integration/LoginSecurityTest::test_complete_login_failure_and_lockout_flow`; E2E "five failed logins lock the IP out, even for the right password @smoke" |
| `wp_login` | `handle_successful_login` | Clears the IP's failure count | LOG | medium | `Integration/LoginSecurityTest::test_successful_login_clears_lockout`; `Unit/LoginSecurityTest::test_successful_login_clears_attempts`; E2E "a successful login before the limit resets the count" |
| `init` | `setup_session_timeout` | Logs out idle sessions on the front end and in wp-admin, administrators included (wp-admin page views redirect to login; AJAX, REST and front end requests are only logged out). Idle means no foreground activity: Heartbeat, REST reads and admin-ajax GET do not refresh `last_activity`, and the write is throttled to once a minute. The auth cookie (absolute, equal to the timeout, never renewed) also ends the session that long after login, so the idle check is the sliding bound only when another plugin lengthens the cookie | FE, ADM, LOG, AJAX, REST | high | `Integration/SessionAndPasswordPolicyTest` (admin idle 2 hours, Heartbeat, REST read, throttle), `Integration/LoginSecurityTest::test_session_timeout_in_admin_area`, `::test_session_timeout_updates_last_activity`, `::test_session_timeout_skips_during_plugin_activation`; `Unit/LoginSecurityTest::test_session_timeout`; E2E "an idle session ends with a login screen, not a 404, even without the admin access cookie @smoke", "an active session is not logged out" |
| `wp_logout` | `clear_login_attempts` | Clears the IP's counters on logout | LOG | low | `Integration/LoginSecurityTest::test_successful_login_clears_lockout` (shares the clear path; `Integration/AuditResidualsBehaviorTest::test_logout_clears_the_login_counters` runs the real `wp_logout()`) |
| `password_reset` | `clear_login_attempts_on_password_change` | Reset password clears lockout | LOG | medium | `Integration/LoginSecurityTest::test_login_attempts_cleared_on_password_reset` |
| `profile_update` | `clear_login_attempts_on_profile_update` | Clears lockout only when the password changed | ADM | low | `Integration/LoginSecurityTest::test_login_attempts_cleared_on_profile_password_change`, `::test_profile_update_without_password_change_keeps_attempts` |
| `user_profile_update_errors` | `validate_password_strength` | Rejects weak passwords in the profile form (when enforcement is on); checks the raw value WordPress stores, not a sanitized copy | ADM | medium | `Integration/SessionAndPasswordPolicyTest::test_profile_check_validates_the_raw_password`, `::test_profile_check_rejects_what_is_weak_as_stored`; `Integration/LoginSecurityTest::test_password_strength_validation_integration`; `Integration/LoginLockoutBehaviorTest::test_password_strength_rules`; E2E "the profile form enforces the password rules @smoke" |
| `validate_password_reset` | `validate_password_strength_reset` | Rejects weak passwords on the reset screen (raw value) | LOG | medium | `Integration/SessionAndPasswordPolicyTest::test_reset_check_validates_the_raw_password`; `Integration/LoginSecurityTest::test_password_validation_on_reset`; E2E "the emailed link opens for a visitor with no admin access cookie, refuses weak passwords with the rules, and accepts a strong one @smoke" |
| `rest_request_before_callbacks` | `validate_rest_password_strength` (p10, 3 args) | Rejects a weak `password` on POST, PUT and PATCH of `/wp/v2/users`, `/wp/v2/users/{id}` and `/wp/v2/users/me` with a 400 `weak_password` (when enforcement is on). `rest_pre_insert_user` is not used because the users controller ignores a WP_Error returned from it. Not covered, by design: WP-CLI, `wp_insert_user()` and `wp_set_password()` (the plain password is not visible to any hook there) | REST, ED, headless | medium | `Integration/SessionAndPasswordPolicyTest::test_rest_users_me_rejects_a_weak_password`, `::test_rest_users_me_accepts_a_strong_password`, `::test_rest_user_create_rejects_a_weak_password` |
| `admin_enqueue_scripts` | `enqueue_password_scripts` | Live strength meter script on profile screens | ADM | low | `Integration/AuditResidualsBehaviorTest::test_password_scripts_load_on_profile_screens_only` |
| `login_enqueue_scripts`, `login_head`, `login_footer`, `login_headerurl`, `login_headertext`, `login_body_class`, `login_title` | `LoginBranding` callbacks (only when branding is enabled) | Restyles `wp-login.php`: logo link, text, layout markup, body classes, title | LOG | medium | `Unit/LoginBrandingTest::test_hooks_registered_when_enabled`, `::test_hooks_not_registered_when_disabled`, `::test_custom_login_url_returns_home_url`, `::test_custom_login_text_returns_site_name`, `::test_add_body_classes_includes_branded_class`, `::test_custom_login_title`, `::test_inject_login_head_empty_without_custom_logo`, `::test_inject_login_footer_outputs_illustration`; rendered `wp-login.php`: `Integration/LoginPageRenderTest::test_login_page_is_branded_by_default`, `::test_custom_logo_and_color_are_applied`, `::test_login_page_is_stock_when_branding_is_off` |

### 7. Admin hiding (`AdminHideSecurity`, all hooks only when enabled; constant `SILVER_ASSIST_HIDE_ADMIN === false` disables it; a stored path that is forbidden or a reserved core slug falls back to `silver-admin` at runtime, `Integration/AdminPathValidationTest::test_runtime_check_refuses_reserved_slug`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `setup_theme` | `handle_specific_page_requests` | 404 on `wp-login.php` and `/wp-admin` without the access cookie; custom path serves the login; skips cron and AJAX | FE, LOG, ADM, cron | high | `Integration/AdminHideRoutingTest::test_default_admin_and_login_paths_are_hidden`, `::test_public_slug_starting_with_wp_admin_is_not_hidden`, `::test_admin_post_endpoint_is_not_hidden`, `::test_front_end_pages_are_not_hidden`; `Integration/AdminHideSecurityTest::test_request_to_default_admin_when_enabled`, `::test_request_to_custom_path_when_enabled`, `::test_ajax_requests_not_blocked`, `::test_cron_requests_not_blocked`, `::test_emergency_disable_constant_override`; E2E `admin-hide/hidden-admin.spec.ts` "wp-login.php and wp-admin answer 404 without a session @smoke", "the secret path leads to the login form, and a login lands on the dashboard @smoke", "public pages, REST, cron and AJAX keep working @smoke", "a front-end form posting to admin-post.php still reaches its handler" |
| `site_url` (p100) | `filter_generated_url` | Appends the access token to login URLs | LOG, ADM | high | `Integration/AdminHideSecurityTest::test_url_filtering_when_enabled`, `::test_url_filtering_when_disabled`; `Security/AdminHideSecurityTest::test_site_url_filter_registered` (Reg) |
| `admin_url` (p100) | `filter_admin_url` | Same for admin URLs | ADM | high | `Integration/AdminHideSecurityTest::test_url_filtering_when_enabled`; `Security/AdminHideSecurityTest::test_admin_url_filter_registered` (Reg); E2E "update screens and the update AJAX endpoint are reachable" |
| `wp_mail` | `fix_token_separator_in_email` | Repairs the `&#038;` before the token in plain text mail (email change link) | LOG (email) | medium | `Integration/AdminHideRoutingTest::test_email_change_link_in_the_email_keeps_a_working_token`; E2E "the email change confirmation link works for someone who has to log in first", "the emailed link opens for a visitor with no admin access cookie, refuses weak passwords with the rules, and accepts a strong one @smoke" |
| `wp_redirect` | `filter_redirect` | Rewrites redirects to hidden locations, keeps a clean token query | LOG, ADM | high | `Integration/LoginLockoutBehaviorTest::test_session_expired_redirect_keeps_the_admin_hiding_token_intact`; `Security/AdminHideSecurityTest::test_wp_redirect_filter_registered` (Reg); E2E "an idle session ends with a login screen, not a 404, even without the admin access cookie @smoke" |
| `logout_redirect` | `handle_logout_redirect` | Logout lands on the hidden login form | LOG | medium | `Integration/AdminHideSecurityTest::test_logout_redirect_when_enabled`; E2E "logging out lands on the login form, and the session is gone" |
| `template_redirect` (remove, p1000) | `wp_redirect_admin_locations` | Short URLs `/admin`, `/login`, `/dashboard` stop redirecting to the real admin | FE | medium | `Security/AdminHideSecurityTest::test_wordpress_admin_redirect_removed`; `Integration/AuditResidualsBehaviorTest::test_short_urls_do_not_reveal_the_admin_when_hiding_is_on` |

### 8. Contact Form 7 and form protection (`ContactForm7Integration`, `FormProtection`, `IPBlacklist`)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `wpcf7_validate` | `validate_cf7_form` (runs `FormProtection` rate limit, honeypot, user agent, SQL injection and spam patterns) | Blocks bot, flood, injection and spam submissions; real enquiries must pass | FE, AJAX (CF7 submit) | high | `Integration/FormSubmissionBehaviorTest::test_real_visitor_submit_succeeds`, `::test_bot_filling_honeypot_is_blocked`, `::test_bot_without_browser_identity_is_blocked`, `::test_flooding_is_rate_limited`, `::test_rapid_fire_submits_hit_rate_limit_then_blacklist_and_the_block_expires` (submits within seconds from one IP reach the rate limit, then the blacklist, then the block expires), `Integration/IPProtectionScopeTest` (a blacklisted IP still logs in and reaches REST, a login lockout does not block forms, labels name the protection), `::test_sql_injection_payload_is_blocked`, `::test_legitimate_message_is_not_blocked`, `::test_checkbox_array_values_are_accepted`, `::test_spam_phrase_is_still_blocked`, `::test_spam_patterns_are_filterable`, `::test_excessive_capitals_are_detected`; `Security/FormProtectionTest::test_form_rate_limiting_blocks_excessive_submissions`, `::test_sql_injection_detection_in_post_data`; real CF7 through its REST endpoint: `Integration/ContactForm7SubmitTest::test_legitimate_submission_is_sent`, `::test_honeypot_submission_is_blocked`, `::test_rapid_fire_from_one_ip_is_rate_limited`, `::test_sql_injection_payload_is_blocked`, `::test_blacklisted_ip_is_blocked` (E2E mu-plugin `e2e-mail-and-forms.php` only serves the admin-post form) |
| `wpcf7_form_elements` (only with honeypot enabled) | `inject_honeypot_field` | Adds a hidden field before the submit button; with the honeypot off the field is neither added nor enforced | FE | medium | `Integration/FormSubmissionBehaviorTest::test_honeypot_is_injected_hidden_before_submit`; `Integration/ContactForm7IntegrationTest::test_cf7_honeypot_protection`; `Integration/CF7ProtectionOptionsTest::test_honeypot_on_blocks_a_filled_honeypot`, `::test_honeypot_off_lets_the_field_pass_and_is_not_injected` |
| `wpcf7_form_elements` | `inject_timing_field` | Adds a hidden signed render time; `validate_cf7_form` rejects a submission sooner than `silver_assist_cf7_submission_delay` ms after it, and ignores a missing or forged value | FE | medium | `Integration/CF7ProtectionOptionsTest::test_submission_delay_is_honored_in_milliseconds`, `::test_zero_delay_disables_the_timing_check`, `::test_unsigned_or_missing_timing_field_is_ignored` |
| Manual CF7 IP block (`add_to_cf7_blacklist`) | `IPBlacklist::add_to_cf7_blacklist` | Lasts `silver_assist_cf7_ip_block_duration` seconds | AJAX, ADM | low | `Integration/CF7ProtectionOptionsTest::test_manual_block_uses_the_configured_duration` |
| Uninstall, legacy options | `DefaultConfig::migrate_legacy_options`, `Activator::uninstall` | Remove the four options that nothing read (`obsolete_browser_detection`, `sql_injection_detection`, `cf7_spam_threshold`, `cf7_auto_block_bots`) | ADM | low | `Integration/UninstallCleanupTest::test_uninstall_leaves_nothing_behind`, `Integration/CF7ProtectionOptionsTest::test_migration_drops_the_dead_options` |
| `wpcf7_before_send_mail` | `process_cf7_submission` | Logs successful submissions | FE | low | `Integration/ContactForm7SubmitTest::test_legitimate_submission_is_sent` (real CF7, `before_send_mail` runs and logs) |
| `wpcf7_spam` | `handle_cf7_spam` | Records an IP violation, which can lead to a blacklist entry | FE | medium | `Integration/ContactForm7SubmitTest::test_spam_verdict_is_kept_and_recorded` (a spam verdict stays spam and counts one violation, a legitimate submit counts none); blacklist logic itself: `Security/IPBlacklistTest::test_automatic_blacklist_after_threshold`, `::test_ip_blacklist_blocks_malicious_ip`, `::test_violation_window_expiration` |

### 9. GraphQL (`GraphQLSecurity`, only when WPGraphQL is active)

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `init` | `init_graphql_security` (registers the rate limiter) | Sets up per-request GraphQL protections | headless | medium | `Integration/GraphQLHeadlessBehaviorTest::test_anonymous_requests_are_rate_limited` |
| `do_graphql_request` | `check_rate_limit` | Fixed-window per-IP limit for anonymous GraphQL (60, 120 in headless mode, plus batch slots); authenticated requests exempt | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_anonymous_requests_are_rate_limited`, `::test_rate_limit_counter_is_keyed_by_hashed_ip`, `::test_rate_limit_window_is_fixed_and_resets_when_it_ends`, `::test_api_key_requests_are_not_rate_limited`; `Integration/GraphQLSecurityIntegrationTest::test_rate_limiting_standard_mode`, `::test_rate_limiting_headless_mode` |
| `graphql_request_data` (p1) | `validate_query_before_execution` | Rejects introspection (production), excessive aliases, depth, directives, length for single and batched queries | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_too_many_aliases_are_rejected`, `::test_limits_apply_to_batched_queries`, `::test_excessive_depth_is_rejected_single_and_batched`, `::test_introspection_forms_are_rejected_in_production`, `::test_introspection_is_rejected_in_production_even_for_administrators`, `::test_introspection_words_inside_string_literals_are_allowed_in_production`, `::test_typename_is_allowed_in_production`, `::test_legitimate_page_query_is_accepted_in_standard_and_headless_mode` |
| `graphql_request_data` (p0, via `enforce_authentication_requirement`) | `validate_authentication` | Requires authentication when configured (session, application password, API key) | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_anonymous_request_is_rejected_when_endpoint_requires_authentication`, `::test_application_password_authenticates_graphql_request`, `::test_local_environment_does_not_downgrade_wpgraphql_authentication`; `Integration/GraphQLSecurityIntegrationTest::test_validate_auth_blocks_unauthenticated`, `::test_enforce_auth_registers_filter_when_required` |
| `graphql_validation_rules` | `add_custom_validation_rules` (registered on `graphql_init`) | Complexity limit as a graphql-php validation rule; `first:` and `last:` page sizes both count (one point per ten) | headless | medium | `Integration/GraphQLHeadlessBehaviorTest::test_complex_query_is_rejected`, `::test_full_page_listings_are_within_the_standard_complexity_limit`; `Integration/GraphQLLimitsBehaviorTest::test_last_is_rejected_over_the_complexity_budget_like_first`, `::test_last_100_returns_every_node_up_to_the_ceiling` |
| `determine_current_user` (p30) | `authenticate_api_key` | `X-API-Key` or Bearer key logs the client in as the service user, only on the GraphQL endpoint | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_api_key_request_succeeds_when_endpoint_requires_authentication`, `::test_wrong_api_key_is_rejected_when_endpoint_requires_authentication`, `::test_api_key_does_not_authenticate_other_endpoints`, `::test_api_key_works_on_custom_graphql_endpoint`; `Integration/GraphQLSecurityIntegrationTest::test_api_key_auth_succeeds_with_valid_key`, `::test_api_key_auth_supports_bearer_token` |
| `graphql_authentication_errors` | `preserve_api_key_authentication` | Stops WPGraphQL downgrading an API-key user to guest, without bypassing CSRF for cookie users | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_graphql_authentication_errors_filter_only_bypasses_for_real_api_key_login`; `Integration/GraphQLSecurityIntegrationTest::test_preserve_auth_returns_false_after_api_key_success`, `::test_preserve_auth_does_not_bypass_csrf_for_invalid_key` |
| `graphql_validation_rules` (WPGraphQL's own `DisableIntrospection` rule) and `graphql_request_data` (`validate_single_operation`) | no hook of the plugin: the earlier `graphql_introspection_enabled` and `graphql_show_in_graphiql` filters and the `register_introspection_fields` removal were deleted (#152), WPGraphQL 2.23.1 has no such extension points | Introspection is rejected in production by `validate_single_operation` (every client) and for anonymous clients by WPGraphQL's rule when its public introspection setting is off | headless | high | `Integration/GraphQLHeadlessBehaviorTest::test_anonymous_introspection_is_rejected_in_production_with_the_public_setting_on`, `::test_production_does_not_register_hooks_wpgraphql_never_fires` |
| `graphql_init` | `set_execution_timeout`, which adds `graphql_request_results` (p1) `enforce_query_timeout` | `set_time_limit` plus a QUERY_TIMEOUT error when a query overruns | headless | medium | `Integration/GraphQLLimitsBehaviorTest::test_slow_request_gets_a_query_timeout_error`, `::test_execution_limit_is_set_to_the_configured_timeout` |
| `graphql_request_results` (p10) | `log_graphql_requests` | Security log of suspicious queries: a very long query, aliases, directives or repeated fields from the thresholds `is_suspicious_query` derives from the limits (10 aliases and 7 directives in standard mode, 50 repeats), or three selection sets below `__schema`/`__type`; all by the linear counters validation uses, no backtracking patterns. The log entry has a 200 character `query_preview`; the `silver_assist_security_event` action (any plugin or theme can hook it) gets the context without `query_preview`, stripped in `SecurityHelper::log_security_event()` | headless | low | `Integration/GraphQLLimitsBehaviorTest::test_many_alias_query_is_flagged_in_the_security_log`, `::test_alias_flag_threshold_follows_the_headless_limit`, `::test_alias_flag_boundary_in_standard_and_headless_mode`, `::test_many_directives_are_flagged_on_a_multiline_query`, `::test_deep_introspection_is_flagged_on_a_multiline_query`, `::test_repeated_fields_are_flagged_and_wide_selections_are_not`, `::test_classifying_a_crafted_query_is_fast_and_correct`, `::test_event_action_does_not_receive_the_query_preview`, `::test_ordinary_and_few_alias_queries_are_not_flagged`, `::test_request_logging_does_not_change_the_response` |
| `graphql_response_headers_to_send` | `add_response_security_headers` | Adds the baseline headers of `GeneralSecurity::get_security_headers()` (including the `silver_assist_security_headers` filter) to the GraphQL HTTP response, on any endpoint path; headers already set are kept. WPGraphQL answers on `parse_request` and exits before `send_headers`, so the `send_headers` hooks never reach it (#152) | headless | medium | `Integration/GraphQLHeadlessBehaviorTest::test_graphql_response_carries_the_baseline_security_headers`, `::test_graphql_response_headers_follow_the_site_filter_and_keep_earlier_values`, `::test_custom_endpoint_response_carries_the_baseline_security_headers`, `::test_no_send_headers_hook_matches_graphql_by_substring` |

### 10. Admin panel, settings and AJAX

| Hook | Callback | Core behavior touched | Context | Risk | Test |
|------|----------|-----------------------|---------|------|------|
| `admin_menu` (p4) | `AdminPanel::register_with_hub` | Registers the settings page under the Silver Assist hub or standalone | ADM | low | `Integration/AdminPanelTest::test_wordpress_admin_hooks_registered`, `::test_admin_menu_registration_with_hub_fallback`; `Integration/SettingsHubTest::test_hub_registration_metadata`; `Integration/AdminAccessTest::test_editor_cannot_access_admin_page` |
| `init` (p1) | `SettingsSanitizer::register` (replaced `AdminPanel::register_settings` on `admin_init`) | see the bootstrap table | all | high | `Integration/AdminPanelTest::test_settings_registered_properly`, `Integration/RegisteredSettingsSanitizeTest` |
| `admin_init` | `AdminPanel::save_security_settings` (and `SettingsHandler`) | Gate field, capability and `_wpnonce`, then `SettingsSaver` saves the posted tab (`settings_tab`, one form per tab; a single `settings_section` still works; a missing or unknown tab or section writes nothing); admin-hide path validation through `PathValidator` (reserved core slugs, existing pages and rewrite rules): a rejected path is not written, never enables Admin Hide and is reported next to its field; enabling Admin Hide, or changing the path while it is on, needs the confirmation checkbox or nothing of the section is written; disabling is never blocked; `flush_rewrite_rules()` runs when the toggle or the path changes | ADM | high | `Integration/AdminPanelTest::test_security_settings_save_with_valid_data`, `::test_security_settings_validation_rejects_invalid`, `::test_settings_post_without_gate_field_saves_nothing`, `::test_non_admin_cannot_save_settings`; `Integration/SettingsFormsTest::test_each_form_persists_every_field_and_only_its_own_tab`, `::test_every_form_carries_gate_section_and_nonce`, `Integration/ExplicitSaveTest::test_tab_form_persists_every_section_of_the_tab`, `::test_enabling_admin_hide_needs_confirmation`, `::test_confirmed_enable_saves_flushes_and_shows_the_url`, `::test_invalid_path_never_enables_admin_hide`, `::test_path_change_while_enabled_needs_confirmation_and_flushes`, `::test_disabling_admin_hide_always_works`, `::test_unrelated_save_does_not_flush`, `::test_bad_nonce_writes_nothing`, `::test_non_admin_post_writes_nothing`, `::test_missing_or_unknown_section_writes_nothing`; `Integration/SettingsSaverTest::test_invalid_admin_path_is_rejected_and_reported`; `Integration/AdminPathValidationTest::test_reserved_core_slugs_are_rejected`, `::test_existing_page_slug_is_rejected`, `::test_post_and_custom_post_type_slugs_are_rejected`, `::test_rewrite_rule_collision_is_rejected`, `::test_saver_rejects_instead_of_resetting`, `::test_saver_rejects_existing_page_slug`; `Functional/SettingsFormTest::test_settings_form_submission`, `::test_form_nonce_validation`; E2E `Explicit save per tab` |
| `admin_notices` (inside `SettingsHandler`) | closure | Success, warning (adjusted values, or the admin URL when Admin Hide changed) or error (no section, or an option that was rejected such as an admin path that shadows a route) notice after a save; the success notice is not shown when something was rejected; the same messages are shown next to the field (`role="alert"` for an error, `role="status"` for an adjusted value) and the field keeps what was typed | ADM | low | `Functional/SettingsFormTest::test_success_message_after_save`, `Integration/AdminPathValidationTest::test_handler_shows_error_notice_for_rejected_path`, `Integration/ExplicitSaveTest::test_rejected_value_is_shown_next_to_the_field`, `::test_adjusted_value_is_shown_next_to_the_field` |
| `admin_enqueue_scripts` | `AdminPanel::enqueue_admin_scripts`, `AssetManager::enqueue_admin_scripts` | Loads plugin assets on its own screen only | ADM | low | `Integration/AdminPanelTest::test_admin_scripts_enqueued_on_plugin_page`, `::test_admin_scripts_not_enqueued_on_other_pages` |
| `wp_ajax_silver_assist_get_security_status`, `wp_ajax_silver_assist_get_login_stats`, `wp_ajax_silver_assist_get_blocked_ips`, `wp_ajax_silver_assist_get_security_logs`, `wp_ajax_silver_assist_validate_admin_path`, `wp_ajax_silver_assist_add_manual_ip`, `wp_ajax_silver_assist_unblock_ip` | `SecurityAjaxHandler` | Admin-only dashboard, IP management and live admin-path validation endpoints (no `nopriv`). The `silver_assist_auto_save` endpoint was removed (#160): settings are saved only with the tab Save button | AJAX, ADM | medium | `Integration/AjaxEndpointsTest::test_all_security_ajax_actions_registered`, `::test_ajax_nonce_validation_rejects_invalid`, `::test_ajax_subscriber_cannot_access_admin_endpoints`; `Unit/SecurityAjaxHandlerTest::test_get_security_status_with_admin_user`, `::test_get_login_stats_with_admin_user`, `::test_get_blocked_ips_with_admin_user`, `::test_get_security_logs_with_admin_user`, `::test_validate_admin_path_with_valid_path`, `Integration/ExplicitSaveTest::test_autosave_endpoint_is_removed`, `::test_admin_script_has_no_autosave`, `::test_add_manual_ip_blocks_valid_ip`, `::test_unblock_ip_removes_blocked_ip`; `Integration/IPBlockUnblockFlowTest::test_block_unblock_via_ajax_roundtrip`; `Integration/DashboardFiguresTest` (blocked IP expiry and violations, event counts, admin hide status; the 24h, 7d and 30d figures come from `Core\SecurityEventCounter`, hourly buckets capped at 30 days, not from logs) |
| `wp_ajax_silver_assist_get_cf7_blocked_ips`, `wp_ajax_silver_assist_block_cf7_ip`, `wp_ajax_silver_assist_unblock_cf7_ip`, `wp_ajax_silver_assist_clear_cf7_blocked_ips`, `wp_ajax_silver_assist_export_cf7_blocked_ips` (only when CF7 is active) | `ContactForm7AjaxHandler` | Admin-only CF7 blocklist management and CSV export | AJAX, ADM | low | `Integration/AjaxEndpointsTest::test_cf7_ajax_only_when_cf7_active`; `Unit/ContactForm7AjaxHandlerTest::test_get_blocked_ips_with_admin_user`, `::test_block_ip_with_admin_user`, `::test_unblock_ip_with_admin_user`, `::test_clear_blocked_ips_with_admin_user`, `::test_export_returns_csv_with_headers`; `Integration/CF7AdminPanelTest::test_manual_cf7_ip_blocking` |
| `wp_ajax_silver_assist_generate_graphql_api_key`, `wp_ajax_silver_assist_revoke_graphql_api_key` | `GraphQLApiKeyAjaxHandler` | Admin-only API key lifecycle | AJAX, ADM | medium | `Unit/GraphQLApiKeyAjaxHandlerTest::test_generate_api_key_success`, `::test_generate_api_key_fails_for_subscriber`, `::test_revoke_api_key_success`, `::test_revoke_api_key_fails_without_nonce` |

### 11. Constants and extension points that change behavior

| Name | Where | Effect | Risk | Test |
|------|-------|--------|------|------|
| `SILVER_ASSIST_HIDE_ADMIN` (false) | `AdminHideSecurity` | Emergency off switch for admin hiding | high | `Integration/AdminHideSecurityTest::test_emergency_disable_constant_override`; `Security/AdminHideSecurityTest::test_emergency_disable_constant` |
| `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` constant | `SecurityHelper::get_client_ip` | Declares trusted proxies for `X-Forwarded-For` | high | `Integration/ConstantsBehaviorTest::test_trusted_proxy_cidrs_constant_as_string`, `::test_trusted_proxy_cidrs_constant_as_array` (separate processes) |
| `silver_assist_trusted_proxy_cidrs` filter | `SecurityHelper::get_client_ip` | Same list, set from code | high | `Integration/ClientIpResolutionTest::test_configured_cidrs_discard_trusted_hops`, `::test_configured_cidrs_do_not_trust_other_private_peers` |
| `silver_assist_trust_private_proxies` filter | `SecurityHelper` | Opt out of private-peer proxy trust | high | `Integration/ClientIpResolutionTest::test_opting_out_of_private_proxy_trust_uses_the_peer` |
| `silver_assist_security_headers` filter | `GeneralSecurity` | Adjust headers | medium | `Integration/GeneralHardeningBehaviorTest::test_headers_can_be_adjusted_with_a_filter` |
| `silver_assist_security_strip_asset_version` filter | `GeneralSecurity` | Keep `ver=` per asset | medium | `Integration/AssetVersioningTest::test_filter_can_keep_version` |
| `silver_assist_security_disable_xmlrpc` filter | `GeneralSecurity` | Re-enable XML-RPC | medium | `Integration/GeneralHardeningBehaviorTest::test_xmlrpc_can_be_reenabled_with_a_filter` |
| `silver_assist_security_remove_feed_links` filter | `GeneralSecurity` | Keep feed discovery | low | `Integration/GeneralHardeningBehaviorTest::test_feed_discovery_can_be_kept_with_a_filter` |
| `silver_assist_security_is_background_request` filter | `LoginSecurity` | Reclassify a request as background polling (not session activity) or as activity | medium | `Integration/SessionAndPasswordPolicyTest::test_background_classification_can_be_filtered` |
| `silver_assist_security_is_development_environment` filter | `GeneralSecurity` | Force or deny the development check for HSTS | medium | `Integration/GeneralHardeningBehaviorTest::test_hsts_only_on_ssl_outside_development`, `::test_hsts_not_sent_in_development` |
| `silver_assist_security_cf7_spam_patterns` filter | `ContactForm7Integration` | Tune spam patterns | medium | `Integration/FormSubmissionBehaviorTest::test_spam_patterns_are_filterable` |
| `silver_assist_security_sql_injection_patterns` filter | `FormProtection` | Tune SQL injection patterns | medium | `Integration/AuditResidualsBehaviorTest::test_sql_pattern_filter_adds_a_signature`, `::test_sql_pattern_filter_removes_a_signature` |
| `silver_assist_security_ipv6_prefix_length` filter | `SecurityHelper::normalize_ip_for_limits` | IPv6 prefix the limiters group addresses by (default 64, 128 disables) | high | `Integration/LimiterRobustnessTest::test_ipv6_prefix_length_filter`, `::test_ip_normalization`, `::test_blacklist_covers_the_whole_ipv6_prefix` |
| `silver_assist_security_environment_type` filter | `GraphQLSecurity` | Override the environment the GraphQL protections use | medium | used by the GraphQL tests through `Helpers/HeadlessTestSupport.php`, e.g. `Integration/GraphQLHeadlessBehaviorTest::test_introspection_is_not_blocked_by_the_plugin_outside_production` |
| `silver_assist_security_languages_directory` filter | `Plugin::load_textdomain` | Move the translations folder | low | `Integration/AuditResidualsBehaviorTest::test_languages_directory_filter_moves_the_translations` |
| `DISALLOW_FILE_EDIT` constant | `GeneralSecurity` | File editor off | medium | `Integration/GeneralHardeningBehaviorTest::test_file_editing_is_disallowed_and_footer_branded`; `Security/GeneralSecurityTest::test_file_editing_disabled` |
| `WP_DEBUG` constant | `GeneralSecurity`, `GraphQLSecurity` | HSTS skipped in development; debug logging | low | `Integration/ConstantsBehaviorTest::test_wp_debug_constant_disables_hsts` (the test installation defines `WP_DEBUG` as true, so the false half is the filter test in `GeneralHardeningBehaviorTest`) |
| `WP_ENVIRONMENT_TYPE` constant | `GraphQLSecurity` via `wp_get_environment_type()` | Introspection and authentication bypass per environment | high | `Integration/ConstantsBehaviorTest::test_environment_type_constant_decides_introspection`, `::test_unset_environment_type_rejects_introspection` (separate processes, constant defined before WordPress boots through `SILVER_ASSIST_TEST_DEFINES` in `tests/bootstrap.php`) |
| `SCRIPT_DEBUG` constant | `SecurityHelper::get_asset_url` | Non-minified plugin assets | low | `Integration/ConstantsBehaviorTest::test_script_debug_constant_serves_unminified_assets`, `::test_minified_assets_without_script_debug` |

### Gaps

Each gap lists the missing behavior test; filed issues are linked by the maintainers. G1 to G14 were closed by #154 (G8's PHP version notice is intentionally untested, see its row in section 1); no gap is open.

Suspected bugs (recorded, not fixed):


- **S2 (fixed in #152), three GraphQL "disable introspection" hooks do nothing on WPGraphQL 2.23.1.** `graphql_introspection_enabled`, `graphql_show_in_graphiql` and `WPGraphQL\Type\Introspection::register_introspection_fields` do not exist in the plugin source (grep of `src/` finds only the settings screen). Introspection is still blocked in production by the plugin's own query validation (#132), so the impact is the dead code and a test that asserts only the registration. The dead hooks were deleted.
- **S3, the cleanup cron is never unscheduled** (fixed in #151). `Activator::deactivate()` and `::uninstall()` now call `wp_clear_scheduled_hook( 'silver_assist_security_cleanup' )`.
- **S4 (fixed in #152), `add_graphql_security_headers` never ran for real GraphQL requests.** WPGraphQL handles the HTTP request on `parse_request` and ends with `wp_send_json` (`src/Router.php`), before `WP::send_headers()` fires `send_headers`; the check is also a substring match on `/graphql`, which would add `X-Frame-Options: DENY` and no-store headers to a front-end page such as `/graphql-guide/`, and it misses a custom endpoint path. The same applies to `GeneralSecurity::add_security_headers`: GraphQL responses carry none of the plugin's baseline headers. Confirmed by reading code, not by a request. The baseline headers now go through `graphql_response_headers_to_send`.
