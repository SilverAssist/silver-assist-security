# Silver Assist Security Essentials — Project Context

Silver Assist Security Essentials is a WordPress plugin that resolves critical security vulnerabilities found in WordPress security audits. It provides login protection with brute force prevention and bot blocking, HTTPOnly cookie enforcement with SameSite/Secure flags, and comprehensive GraphQL endpoint security including introspection blocking, query limits, and rate limiting.

| Field | Value |
|-------|-------|
| **Namespace** | `SilverAssist\Security` |
| **Text Domain** | `silver-assist-security` |
| **Version** | See `SILVER_ASSIST_SECURITY_VERSION` constant |
| **PHP** | 8.3+ |
| **WordPress** | 6.5+ |

## Documentation Rule

All project documentation lives in **README.md**, **CHANGELOG.md**, and this file only.
Never create standalone `.md` files (`docs/`, `CONTRIBUTING.md`, `API.md`, etc.).

**Exceptions** — Copilot AI configuration files may be created freely:

- `.github/skills/<topic>/SKILL.md` — domain knowledge for Copilot
- `.github/prompts/<task>.prompt.md` — reusable prompt templates
- `.github/instructions/<scope>.instructions.md` — scoped coding context

## Security Modules

### Login Protection (`Security\LoginSecurity`)
- IP-based login attempt limiting (1–20 configurable) with transient-based blocking
- Session timeout management (5–120 minutes), user enumeration protection
- Strong password enforcement (12+ chars, mixed case, numbers, symbols)
- Bot/crawler detection and blocking (Nmap, Nikto, WPScan, etc.)
- 404 responses to automated reconnaissance tools

### Cookie Security (`Security\GeneralSecurity`)
- Automatic HTTPOnly flag for all WordPress authentication cookies
- Secure flag (HTTPS), SameSite attribute (CSRF protection)
- Security headers (X-Frame-Options, X-XSS-Protection, CSP), WordPress hardening (XML-RPC blocking, version hiding)

### GraphQL Security (`GraphQL\GraphQLSecurity` + `GraphQL\GraphQLConfigManager`)
- WPGraphQL detection and conditional loading
- Introspection blocking in production
- Query depth (1–20, default 8), complexity (10–1000, default 100), timeout (1–30s, default 5)
- Rate limiting (30 req/min per IP) with intelligent adaptive limits
- Alias abuse, field duplication, and directive limitation protection
- Headless CMS mode configuration
- **All GraphQL settings MUST go through `GraphQLConfigManager` singleton**

### Contact Form 7 Integration (`Security\ContactForm7Integration`)
- Automatic CF7 plugin detection via `SecurityHelper::is_contact_form_7_active()`
- Form submission rate limiting with IP tracking
- Conditional "Form Protection" admin tab (appears only when CF7 detected)

## Key Classes

| Class | Purpose |
|-------|---------|
| `Core\Plugin` | Main singleton — initializes all security components |
| `Core\DefaultConfig` | Centralized defaults for all plugin settings (single source of truth) |
| `Core\SecurityHelper` | Static utilities: asset URLs, IP detection, bot detection, logging, AJAX validation, password checks |
| `Core\Updater` | GitHub-based automatic update system |
| `Core\PathValidator` | Path validation and sanitization |
| `Admin\AdminPanel` | Admin orchestration — registers with Settings Hub or standalone menu |
| `Admin\Renderer\AdminPageRenderer` | 5-tab navigation with `.silver-nav-tab` namespace separation |
| `Admin\Renderer\SettingsRenderer` | Settings tab content rendering |
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
├── silver-assist-security.php     # Bootstrap with PSR-4 autoloader
├── src/
│   ├── Admin/AdminPanel.php + Renderer/ (AdminPageRenderer, SettingsRenderer, DashboardRenderer)
│   ├── Core/ (Plugin, DefaultConfig, SecurityHelper, PathValidator, Updater)
│   ├── Security/ (LoginSecurity, GeneralSecurity, AdminHideSecurity, ContactForm7Integration, FormProtection)
│   └── GraphQL/ (GraphQLSecurity, GraphQLConfigManager)
├── assets/css/ (variables.css, admin.css, password-validation.css)
├── assets/js/ (admin.js, password-validation.js)
├── languages/ (.pot, .po, .mo files)
└── tests/ (Unit/, Security/, WordPress/, Helpers/)
```

## Plugin-Specific Patterns

### SecurityHelper — Mandatory Usage
All utility functions are centralized in `SecurityHelper`. **Never duplicate this logic in other classes:**
- `get_asset_url($path)` — asset URLs with SCRIPT_DEBUG-aware minification
- `get_client_ip()` — IP detection with proxy/CDN support
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

### WordPress Options
All options use `silver_assist_` prefix (e.g., `silver_assist_login_attempts`, `silver_assist_graphql_query_depth`, `silver_assist_session_timeout`, `silver_assist_bot_protection`, `silver_assist_graphql_headless_mode`).

## TDD Requirement

This is a security plugin — **all features must be developed test-first** (Red → Green → Refactor). Security classes require 100% test coverage. Tests use WordPress Test Suite (`WP_UnitTestCase`) with real database. Plugin-specific test layout:

- `tests/Unit/` — DefaultConfigTest, SecurityHelperTest, GraphQLConfigManagerTest, LoginSecurityTest
- `tests/Security/` — SecurityTest (overall security validation)
- `tests/WordPress/` — AdminPanelTest (integration examples)
- `tests/Helpers/` — TestHelper (shared utilities)

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
