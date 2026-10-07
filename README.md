# Silver Assist Security Essentials

A comprehensive WordPress security plugin designed to resolve critical security vulnerabilities identified in security assessments, specifically targeting admin protection (login security & URL hiding), HTTPOnly cookie implementation, and GraphQL security misconfigurations.

## 🛡️ Overview

**Silver Assist Security Essentials** addresses three critical security vulnerabilities commonly found in WordPress security audits:

1. **WordPress Admin Protection & Access Control** - Comprehensive protection against brute force attacks, unauthorized access, and admin discovery
2. **Missing HTTPOnly Flag on Cookies** - Prevents XSS attacks from accessing authentication cookies  
3. **GraphQL Security Misconfigurations** - Comprehensive protection against DoS attacks, introspection abuse, and resource exhaustion

This plugin automatically implements enterprise-level security measures without requiring technical knowledge, making it perfect for WordPress sites that need to pass security audits and compliance requirements.

## 🎯 Security Issues Resolved

### 🔐 WordPress Admin Protection & Access Control

**Problem**: Publicly accessible admin area vulnerable to brute force attacks, user enumeration, bot crawling, and automated discovery
**Solution**:

- **Login Protection**: IP-based login attempt limiting (configurable 1-20 attempts)
- **Session Management**: Session timeout management (5-120 minutes) with enforced session cookie lifetime
- **CAPTCHA Security Challenge**: Math-based CAPTCHA on login page during Under Attack Mode to block automated login attempts
- **Remember Me Removal**: "Remember Me" checkbox removed from login form to enforce strict session timeout policies
- **User Enumeration Protection**: Login error standardization prevents user discovery
- **Strong Password Enforcement**: Mandatory complex passwords (8+ characters, mixed case, numbers, symbols)
- **Bot and Crawler Protection**: Automatic blocking of suspicious crawlers, scanners, and automated tools
- **Anti-Reconnaissance**: Blocks security scanning tools (Nmap, Nikto, WPScan, Nuclei, etc.)
- **Rate Limiting**: Prevents rapid-fire login attempts from automated scripts
- **Custom Admin URLs**: Configure personalized admin access paths (e.g., `/my-secure-admin`)
- **404 Redirect Protection**: Direct access to standard admin URLs returns 404 errors to hide admin existence
- **Real-Time Path Validation**: Live feedback while typing custom paths with security keyword filtering
- **Intelligent Path Blocking**: Prevents use of obvious paths like 'admin', 'login', 'dashboard', 'wp-admin'

### 🍪 HTTPOnly Cookie Flag Missing

**Problem**: Cookies accessible to client-side JavaScript, vulnerable to XSS attacks  
**Solution**:

- Automatic HTTPOnly flag implementation for all WordPress authentication cookies
- Secure cookie configuration for HTTPS sites
- SameSite protection against CSRF attacks
- Session cookie security enhancement

### 🛡️ GraphQL Security Misconfigurations

**Problem**: Multiple GraphQL vulnerabilities including introspection exposure, unlimited aliases, field duplication, and circular queries  
**Solution**:

- **Introspection Blocking**: Disabled in production environments
- **Query Depth Limits**: Configurable limits (1-20 levels, default: 8)
- **Query Complexity Control**: Prevents resource exhaustion (10-1000 points, default: 100)
- **Query Timeout Protection**: Configurable timeouts (1-30 seconds, default: 5)
- **Rate Limiting**: 60 anonymous requests per minute per IP (120 in headless mode), see "Headless Clients: REST and GraphQL"
- **Alias & Field Duplication Protection**: Prevents excessive aliases and field repetition

### 📧 Contact Form 7 Integration & Form Protection

**Problem**: Contact forms vulnerable to spam, bot abuse, and resource exhaustion attacks  
**Solution**:

- **Automatic Integration**: Seamless integration with Contact Form 7 when plugin is active
- **CAPTCHA on Forms**: Math-based CAPTCHA challenge injected into CF7 forms during Under Attack Mode
- **Form Submission Rate Limiting**: Prevents rapid-fire spam submissions per IP
- **Bot Protection**: Advanced detection of automated form submission attempts
- **IP-based Blocking**: Temporary blocks for IPs exceeding submission limits
- **CSRF Protection**: Enhanced nonce validation for form security
- **Real-time Monitoring**: Track blocked form submissions and suspicious IPs
- **Conditional Interface**: Form Protection tab appears automatically when CF7 is detected
- **Tunable Detection**: Spam phrases and SQL signatures can be adjusted with the `silver_assist_security_cf7_spam_patterns` and `silver_assist_security_sql_injection_patterns` filters. The default limit is 2 submissions per minute per IP, and an attempt counts once it reaches the rate-limit check, including one that CF7's own validation later rejects (blacklisted IPs, a filled honeypot and too-fast submissions are rejected before it)

## ✨ Additional Security Features

### 🚫 Two IP Protections: Login Lockout and Form Flood Blacklist

The plugin has two separate per-IP protections. They have their own settings, their own state and their own figures on the dashboard, and neither one reads the other's data.

| | Login lockout | Form flood blacklist |
|---|---|---|
| Protects | the login (`wp-login.php`, `LoginSecurity`) | Contact Form 7 submissions (`IPBlacklist`, `ContactForm7Integration`, `FormProtection`) |
| Trigger | failed logins from one IP (5 by default, `silver_assist_login_attempts`) | more submits than the rate limit (2 per minute by default) from one IP, repeated until the violation threshold is reached (5 by default, `silver_assist_ip_blacklist_threshold`); spam, SQL injection and obsolete browser rejections count as violations too |
| Block lasts | 15 minutes by default (`silver_assist_lockout_duration`), ends on its own | 24 hours for an automatic block (`silver_assist_ip_blacklist_duration`), 30 days for a block added from the IP Management tab |
| Admin settings | Login Security tab | IP Management tab (toggle "Form Flood Blacklist", violations before blocking) and Form Protection tab |
| Dashboard | "Locked-out IPs" in the Login Security card | "Form Flood Blocked IPs" in the Form Protection card, the statistics and the activity tab; listed with unblock actions in IP Management |
| Origin | the original IP block of the plugin | added after an attack on one site that sent form submits within seconds of each other |

- **Scope, by design**: the form flood blacklist is checked only when Contact Form 7 validates a submit. An IP on it can still log in, browse the site and call REST and GraphQL (those have their own rate limits). It is not a site-wide block, and the class name `IPBlacklist` is kept only for backward compatibility. The manual "Block IP" action in IP Management blocks the form for 30 days, nothing else.
- **Toggle**: "Form Flood Blacklist" switches the automatic block off; manual blocks keep working. The login lockout is tuned with the attempts and lockout duration in the Login Security tab.
- **Shared logic, decision (#146)**: the two are kept as separate implementations on purpose, with no common limiter class. What is genuinely common already lives in `SecurityHelper` and both use it: client IP resolution (`get_client_ip()`, see "Proxies, Load Balancers and CDNs") and the IPv6 `/64` grouping in the transient keys (`generate_ip_transient_key()`). The login lockout, the login-page limit and the REST and GraphQL limiters also share the atomic fixed-window counter `SecurityHelper::increment_rate_window()`. The rest differs for good reasons: a lockout is a counter that locks and expires by itself, while the flood blacklist keeps a violation list, a block record and an index so an administrator can list, export and unblock IPs; they have different durations, options and messages. Merging them would couple a login change to the forms and the other way round. One known difference is left as a follow-up: `FormProtection::allow_form_submission()` still counts submits with a plain transient (the window slides and parallel submits can pass the limit) instead of `increment_rate_window()`.
- **Tested flood case**: `FormSubmissionBehaviorTest::test_rapid_fire_submits_hit_rate_limit_then_blacklist_and_the_block_expires` sends submits within a few seconds from one IP through the `wpcf7_validate` filter; the first two pass, the rest hit the rate limit, the fifth violation blacklists the IP, and the block ends after its configured duration. `IPProtectionScopeTest` pins that each protection leaves the other alone.

### 🔒 WordPress Hardening *(Automatic)*

- **Secure Headers**: Essential security headers (X-Frame-Options, X-XSS-Protection, etc.) on the front end, wp-admin, the login screen, REST responses and GraphQL responses (added through `graphql_response_headers_to_send`, since WPGraphQL replies before `send_headers`). `Permissions-Policy` disables geolocation, microphone and camera, which breaks a store locator or recorder; adjust any header with the `silver_assist_security_headers` filter (HSTS is sent only on SSL outside development, see `silver_assist_security_is_development_environment`)
- **File Editing Disabled**: Prevents unauthorized file modifications through admin panel
- **XML-RPC Disabled**: Blocks XML-RPC attacks and vulnerabilities, including pingbacks and apps that use it (Jetpack, the WordPress mobile apps); return `false` from `silver_assist_security_disable_xmlrpc` to keep it
- **Discovery Tags Removed**: RSS feed autodiscovery, oEmbed discovery, shortlink and RSD tags are removed from `wp_head` (feeds still work at their URLs; keep the autodiscovery tags with `silver_assist_security_remove_feed_links`). REST API discovery stays
- **Login Messages**: The login and lost-password screens show one generic message so they do not reveal whether an account exists; lockout and password-reset messages are shown as WordPress writes them
- **Version Hiding**: Conceals WordPress version information from potential attackers (generator tags and theme/plugin asset `?ver=` on the front end; WordPress core assets and wp-admin keep `?ver=` so the block editor and caches stay consistent, adjustable with the `silver_assist_security_strip_asset_version` filter)

### 🤖 Advanced Bot Protection *(Login Page)*

- **Crawler Detection**: Automatically identifies and blocks known bot user agents
- **Scanner Blocking**: Stops security scanners (Nmap, Nikto, WPScan, Nuclei, Dirb, etc.)
- **404 Responses**: Returns "Not Found" to suspicious automated requests
- **Rate Limiting**: Prevents rapid-fire access attempts from scripts
- **Header Analysis**: Detects missing browser headers typical of automated tools
- **Enhanced Security Headers**: X-Frame-Options, X-XSS-Protection, Content Security Policy
- **WordPress Hardening**: XML-RPC blocking, version hiding, file editing restrictions
- **User Enumeration Protection**: Prevents discovery of valid usernames
- **Behavioral Tracking**: Monitors and extends blocks for persistent bot activity

## 📊 Multi-Tab Security Dashboard

### 📱 Dashboard Structure

The plugin features a comprehensive 5-tab interface (4 tabs when Contact Form 7 is not active):

**🎯 Security Dashboard Tab**

- Real-time security status overview and compliance indicators
- Live statistics: failed login attempts, locked-out IPs (login lockout) and form flood blocked IPs (Contact Form 7), GraphQL queries
- **Under Attack Mode indicator**: Shows Active/Inactive status in General Security card
- **Form Flood Blacklist indicator**: Shows Enabled/Disabled status in the Admin Security card (this is the Contact Form 7 flood protection, not the login lockout)
- **Session Timeout stat**: Displays configured timeout in Admin Security card
- Security recommendations and quick actions
- Auto-refresh on tab switch: Dashboard data updates automatically when returning from settings tabs

**🔐 Login Protection Tab**  

- Brute force protection configuration and statistics
- Session timeout management and user activity
- Bot detection settings and blocked crawler reports
- Failed login tracking and IP lockout management

**🛡️ GraphQL Security Tab** *(When WPGraphQL is Active)*

- Query depth and complexity limit configuration
- Rate limiting settings and violation reports
- Introspection control and security recommendations
- GraphQL performance monitoring and optimization

**📧 Form Protection Tab** *(When Contact Form 7 is Active)*

- Contact Form 7 integration status and configuration
- Form submission rate limiting and spam protection
- Bot detection specifically for form submissions
- Real-time monitoring of blocked form attempts

**🛡️ IP Management Tab**

- Settings and lists of the Contact Form 7 form flood blacklist (see "Two IP Protections"); login lockouts are configured in the Login Security tab and are not listed here
- Blocked IPs of the form flood blacklist, with unblock actions
- Manual IP management (block an address from the forms for 30 days, or unblock it)

## 🌍 Enterprise Features

- **Easy Configuration**: Simple admin panel with toggle switches and sliders
- **Instant Updates**: All settings take effect immediately
- **Multi-Language Support**: Full Spanish translation included
- **No Technical Knowledge Required**: Works automatically after activation
- **Automatic Updates**: Built-in update system for latest security patches

## 📦 Installation & Setup

### Installation Methods

**WordPress Admin Dashboard** *(Recommended)*

1. Download the latest `silver-assist-security.zip` file
2. Go to **Plugins → Add New → Upload Plugin**
3. Choose the ZIP file and click **Install Now**
4. Click **Activate Plugin**

**Manual FTP Upload**

1. Extract the ZIP file to get the `silver-assist-security` folder
2. Upload the folder to `/wp-content/plugins/` via FTP
3. Activate from **WordPress Admin → Plugins**

**WP-CLI** *(Advanced)*

```bash
wp plugin install silver-assist-security.zip --activate
```

## 🚀 Quick Start & Configuration

### Immediate Protection *(No Configuration Required)*

The plugin starts protecting your website immediately after activation:

✅ **HTTPOnly cookies** are automatically enabled  
✅ **Login protection** blocks brute force attempts  
✅ **GraphQL security** prevents DoS attacks  
✅ **Security headers** are added to all pages  
✅ **File editing** is disabled in admin  
✅ **XML-RPC** is blocked  
✅ **User enumeration** is prevented  
✅ **Remember Me** checkbox is removed (session timeout enforced)  
✅ **Admin URL hiding** (optional - requires configuration)  
✅ **Under Attack Mode** CAPTCHA protection (optional - toggle in IP Management)  

### Configuration Dashboard

#### Settings Hub Integration (v1.1.13+)

**🎯 NEW**: Silver Assist Security now integrates with the centralized Settings Hub!

**With Settings Hub Installed**:

- Access via **Silver Assist → Security** (top-level menu)
- Professional plugin dashboard with cards and metadata
- One-click "Check Updates" button in plugin card
- Seamless navigation between Silver Assist plugins
- Enhanced user experience with unified interface

**Without Settings Hub** (Fallback):

- Access via **Settings → Security Essentials** (legacy menu)
- Full functionality maintained
- All security features work identically

**Install Settings Hub** (Optional but Recommended):

```bash
composer require silverassist/wp-settings-hub
```

### 🎛️ Tab Navigation System *(v1.1.15+)*

**🎯 NEW**: Advanced dual-level navigation system with namespace separation!

**Settings Hub Level** (Plugin Switching):

- Switch between Silver Assist plugins (Security, SEO, etc.)
- Top-level tabs for different plugin categories
- Professional dashboard with metadata cards

**Security Plugin Level** (Feature Navigation):

- Navigate between security feature areas within the plugin
- Independent tab system that works alongside Settings Hub
- Seamless coexistence without navigation conflicts
- Responsive design adapts to screen size and content

**Technical Implementation**:

- **CSS Namespace Separation**: `.nav-tab` (Hub) vs `.silver-nav-tab` (Security)
- **Dynamic Tab Detection**: Automatically handles conditional Contact Form 7 tab
- **Conflict Resolution**: Multiple navigation levels work independently
- **Accessibility**: Full keyboard navigation and screen reader support

**Login Security Configuration**

- 🔧 **Max Login Attempts**: 1-20 failed attempts before lockout (default: 5)
- 🔧 **Lockout Duration**: 60-3600 seconds blocking period (default: 900s/15min)
- 🔧 **Session Timeout**: 5-120 minutes user session duration (default: 30min)
- 🔧 **Bot Protection**: Enable/disable bot and crawler blocking (default: enabled)

**GraphQL Security Configuration** *(If WPGraphQL is Active)*

- 🔧 **Query Depth Limit**: 1-20 levels (default: 8)
- 🔧 **Query Complexity**: 10-1000 points (default: 100)
- 🔧 **Query Timeout**: 1-30 seconds (default: 5)
- ✅ **Rate Limiting**: 30 requests/minute per IP (automatic)
- ✅ **Introspection**: Disabled in production (automatic)

**Admin URL Hide Configuration** *(Optional Security Layer)*

- 🔧 **Enable Admin Hiding**: Toggle on/off admin URL protection
- 🔧 **Custom Admin Path**: Set your personalized admin access URL (e.g., 'my-secure-admin')
- ✅ **Real-Time Validation**: Live feedback prevents weak or forbidden paths
- ✅ **404 Protection**: Standard admin URLs automatically return "Not Found" errors
- 🆘 **Emergency Access**: Built-in recovery system for forgotten custom paths (see Emergency Access section below)

#### 🆘 Emergency Access Recovery

If you forget your custom admin path, you can regain access via FTP:

**Step 1**: Access your WordPress files via FTP or cPanel File Manager  
**Step 2**: Open the `wp-config.php` file in your website root  
**Step 3**: Add this line anywhere before `/* That's all, stop editing! */`:

```php
define('SILVER_ASSIST_HIDE_ADMIN', false);
```

**Step 4**: Save the file and refresh your website  
**Step 5**: You can now access admin at the standard `/wp-admin` URL  
**Step 6**: After regaining access, you can reconfigure the admin path and remove the constant

### Security Compliance Verification

After configuration, your website will be protected against the three critical security issues:

✅ **Admin Protection**: Complete admin area protection with login security, URL hiding, and access control  
✅ **HTTPOnly Cookies**: All cookies have HTTPOnly flags to prevent XSS exploitation  
✅ **GraphQL Secured**: GraphQL endpoint has comprehensive DoS protection and introspection disabled  

## 🔄 Automatic Updates

### Built-in Update System

✅ **Automatic Update Checks**: Daily checks for security patches  
✅ **One-Click Updates**: Update directly from WordPress admin  
✅ **Security Priority**: Critical security updates are prioritized  
✅ **Changelog Display**: Shows what's new in each version  

⚠️ **Always backup your website before applying updates**

## Composer authentication (private packages)

The SilverAssist packages this plugin uses (`wp-github-updater`, `wp-plugin-kernel`, `wp-settings-hub`, `coding-standards` and `wp-coding-standards`) are installed from their GitHub repositories through Composer `vcs` repositories declared in `composer.json` (with `"no-api": true`, so Composer reads tags with git and does not spend the GitHub API quota of the token), not from Packagist.org. Those repositories can require authentication, so configure a token before running `composer install`:

- **Locally:** `composer config --global github-oauth.github.com <token>`
- **CI:** store `{"github-oauth":{"github.com":"<token>"}}` as the repository secret `COMPOSER_AUTH`. The workflows already pass it to `composer install`.

Never commit a token or an `auth.json`.

**Updating from a private repository:** when the plugin's repository is private, the site needs a read-only token in the `SILVER_GITHUB_TOKEN` constant or environment variable so the updater can read the releases. A public repository needs no token.

## 🤖 Automated Dependency Management (Development)

### GitHub Actions + Dependabot System

**For developers and contributors**: This plugin uses an automated CI/CD system for dependency management.

**What it does:**

- ✅ **Weekly Checks**: Automatically verifies Composer, npm, and GitHub Actions updates every Monday
- ✅ **Auto-PRs**: Creates Pull Requests with dependency updates
- ✅ **Quality Gates**: Runs PHPStan, PHPCS, builds, and security audits
- ✅ **Auto-Merge**: Safe updates (minor/patch) merge automatically
- ✅ **Manual Review**: Major version updates require human approval
- ✅ **Security Audits**: Continuous vulnerability scanning (90-day reports)
- ✅ **Copilot Reviews**: All PRs automatically reviewed by GitHub Copilot

**Configuration files:**

- `.github/dependabot.yml` - Dependency scanning configuration
- `.github/workflows/dependency-updates.yml` - Validation and auto-merge workflow

**Critical packages** (separate PRs for major versions):

- `silverassist/wp-settings-hub` - Settings Hub integration
- `silverassist/wp-github-updater` - Update system

**Schedule:**

- **Monday 9:00 AM**: Composer packages check
- **Monday 9:30 AM**: npm packages check  
- **Monday 10:00 AM**: GitHub Actions check
- **24/7**: Security vulnerability alerts

**Workflow jobs:**

1. `check-composer-updates` - PHP dependencies validation
2. `check-npm-updates` - JavaScript dependencies validation
3. `security-audit` - CVE scanning and reports
4. `validate-pr` - Quality checks on Dependabot PRs
5. `auto-merge-dependabot` - Safe updates auto-merge

**For contributors:**

- All PRs include automated validation
- Quality checks must pass before merge
- GitHub Copilot reviews all changes
- Security is validated on every update

## 💡 Frequently Asked Questions

**Will this plugin slow down my website?**  
No. Silver Assist Security Essentials is optimized for performance and adds minimal overhead.

**Do I need technical knowledge to use this plugin?**  
No. The plugin works automatically after activation with simple toggle controls for customization.

**Is it compatible with other security plugins?**  
Yes, but we recommend using Silver Assist Security Essentials as your primary security solution to avoid conflicts.

**What happens to my login page after installation?**  
Your login page remains at the standard WordPress location but gains enhanced protection against brute force attacks, bot detection, and user enumeration.

**Can I customize the security settings?**  
Yes! Go to **Settings → Security Essentials** to configure login attempt limits, session timeouts, GraphQL security settings, and other features.

## ⚠️ System Requirements & Notes

**System Requirements**

- **WordPress**: 6.5 or higher
- **PHP**: 8.2 or higher
- **HTTPS**: Recommended for full security features

**Important Notes**

- Always backup your website before installing security plugins
- **Multisite is not supported or tested.** Single-site installs only: activation, deactivation and uninstall act on the current site, and network activation is not handled

### 🌐 Proxies, Load Balancers and CDNs

Login lockout, the IP blacklist, form protection and the REST and GraphQL rate limits identify a visitor
by IP address. A client must not be able to pick that address by sending headers, so the plugin resolves
it in one place (`SecurityHelper::get_client_ip()`):

- `REMOTE_ADDR` is used as is, unless it belongs to a proxy you trust.
- Only `X-Forwarded-For` is read, and only from a trusted proxy. `Client-IP`, `CF-Connecting-IP` and
  `X-Real-IP` are never read, because any client can send them.
- The chain is read right to left. With declared CIDRs, trusted proxies are skipped and the first
  remaining address is the visitor. With none declared, the last entry (the one your load balancer
  appended) is the visitor and nothing is skipped, so a visitor on a private network is still
  identified correctly. An entry that cannot be validated (a bare value, a port form other than
  `ip:port` and `[ipv6]:port`) makes the plugin fall back to the connecting address.
- Trusted proxies are the CIDRs you declare in `wp-config.php` (or with the filter of the same name):

```php
define( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS', '10.0.0.0/8,52.84.0.0/15' ); // VPC and CDN edge ranges.
```

- If you declare none, a connecting peer in a private or reserved range (an internal load balancer
  such as an AWS ALB) is trusted. Known limit: a client that can reach your origin directly from a
  private network (another host in the VPC, a VPN) can then choose its identity. Declare your CIDRs,
  or return `false` from the `silver_assist_trust_private_proxies` filter to ignore forwarded headers
  until you do (behind a load balancer every visitor then shares the balancer's address).
- Behind a CDN that sits in front of the load balancer, declare the CDN ranges too; otherwise the CDN
  edge address is taken as the visitor.
- IPv6: every limiter (login lockout, login-page limit, blacklist, form protection, REST and GraphQL
  rate limits) counts an IPv6 client by its `/64` network prefix, not by the exact address, because a
  subscriber normally controls a whole /64 and could otherwise rotate through billions of addresses.
  Blocking one IPv6 address blocks its /64 (the list still shows the address that was blocked). An
  IPv4-mapped address counts as its IPv4 address. Change the prefix with the
  `silver_assist_security_ipv6_prefix_length` filter (default 64; 128 keeps the exact address). IPv4 is
  unchanged.
- Persistent object cache (Redis, Memcached): limiter counters and blocks are transients, so they live
  in the cache and survive without touching the options table. The blocked-IP list reads a small index
  option (`silver_assist_ip_blacklist_index`, capped at 1000 entries and pruned by the daily cleanup),
  so it works the same with or without an object cache.
- Cookies: the auth and logged-in cookies are Secure only when WordPress sees an HTTPS request
  (`is_ssl()`, which reads `$_SERVER['HTTPS']` or port 443). The plugin does not trust
  `X-Forwarded-Proto` on its own, since any client can send it. If TLS ends at your proxy, set
  `$_SERVER['HTTPS'] = 'on'` in `wp-config.php` when the request comes from your trusted proxy and carries
  `X-Forwarded-Proto: https`; otherwise the cookies are issued without the Secure flag.

### 🔐 Login Protection and Admin Hiding Behind a Shared IP

Every login limit is per client IP (see "Proxies, Load Balancers and CDNs"), so people who share an
address (an office, a VPN, a mobile carrier) share the limits too. With the defaults:

| Limit | Default | Setting | Behavior |
|-------|---------|---------|----------|
| Failed logins | 5 | Login Attempts (1-20) | The IP is locked out; the right password is refused from that IP too. The page says "Too many failed login attempts. Try again in N minutes." |
| Lockout duration | 15 minutes | Lockout Duration (60-3600 s) | The 5 failures are counted in a fixed window that opens at the first failure and lasts as long as the lockout. The lockout is counted from the failure that triggered it. Trying again while locked out does not extend it. A successful login or password reset from that IP clears the count. |
| Login page requests | 15 per minute | not configurable | The 16th request within a minute from one IP gets a 404 (a fixed window: it opens at the first request and ends a minute later, so a monitor that checks the page once a minute is not blocked). A login costs two requests (the form and the submit), so about seven logins a minute from one address. Lost password, password reset and logout requests are not counted. Switch off Bot Protection to disable this counter. |
| Idle session | 30 minutes | Session Timeout (5-120) | No user activity for that long ends the session, administrators included; in wp-admin the visitor lands on the login screen with `session_expired=1`. Page views and form posts count as activity; Heartbeat, REST reads and admin-ajax reads do not, so an open tab still goes idle. The activity stamp is written at most once a minute. The auth cookie lasts as long as the timeout from the login, is not renewed by activity, and "Remember Me" is removed, so a session also ends that long after login. |

- Password policy (8+ characters with upper and lower case, a number and a symbol, when enabled) is enforced
  on the profile and new user forms, the password reset screen and the REST user routes
  (`POST /wp/v2/users`, `/wp/v2/users/{id}`, `/wp/v2/users/me`, answered with a 400 `weak_password`). The value
  checked is the one WordPress stores, not a sanitized copy. Limit: WP-CLI (`wp user create|update`),
  `wp_insert_user()`, `wp_update_user()` and `wp_set_password()` called from code or other plugins are not
  checked, because no hook sees the plain password there; code that sets passwords should call
  `SecurityHelper::is_strong_password()` itself.
- Wrong credentials, for an existing or an unknown username, show one message ("Invalid login
  credentials"), including on the attempt that triggers the lockout. The lockout notice and password
  reset messages are the only exceptions.
- There is no allowlist: if colleagues behind one IP lock each other out, raise the number of attempts
  (up to 20) and lower the lockout duration (down to 60 seconds).
- With admin hiding on, `wp-login.php` and `/wp-admin/` return 404 to visitors without a session. The
  secret path (default `/silver-admin`) sets a one-hour access cookie and leads to the login form.
  `admin-ajax.php`, `admin-post.php` (public form handlers), `wp-cron.php`, the REST API, password reset
  and lost-password links, and logout keep working for visitors. The email change confirmation link
  carries the access token itself. Add `define( 'SILVER_ASSIST_HIDE_ADMIN', false );` to `wp-config.php`
  to switch admin hiding off if the path is forgotten.
- Covered by `LoginLockoutBehaviorTest`, `AdminHideRoutingTest` and the Playwright specs in
  `tests/e2e/admin-hide/`.

### 🔌 Headless Clients: REST and GraphQL

Next.js and other headless front ends call WordPress through REST and WPGraphQL. This is what the plugin
does to those requests (all of it is covered by `RestAPIHeadlessBehaviorTest` and `GraphQLHeadlessBehaviorTest`).

**REST rate limit** (Settings → Security Essentials → REST API)

| Setting | Option | Default | Range |
|---------|--------|---------|-------|
| Enable Rate Limiting | `silver_assist_rest_rate_limiting_enabled` | on | on/off |
| Rate Limit (requests) | `silver_assist_rest_rate_limit_requests` | 100 | 10-1000 |
| Rate Limit Window (seconds) | `silver_assist_rest_rate_limit_window` | 60 | 30-300 |
| Batch Endpoint Protection | `silver_assist_rest_batch_endpoint_protection` | on | on/off |

- Only anonymous requests count, per client IP (see "Proxies, Load Balancers and CDNs"). Logged-in users,
  application password clients and the block editor are never throttled.
- Request number 100 in the window passes, number 101 gets HTTP `429` with the REST error
  `rest_rate_limit_exceeded`. The window is fixed: it starts with the first request of a client and the
  counter resets when it ends. There is no `Retry-After` header.
- Every anonymous REST call counts, including public form routes such as Contact Form 7 submissions and
  server-side calls from a Next.js server. Visitors behind one IP (an office, a school, a headless server
  that proxies visitors without a trusted forwarded address) share a single budget. Raise the requests
  and the window for such sites, declare your proxies, or turn the limiter off.
- `/batch/v1` returns `403` (`rest_batch_disabled`) to anonymous clients. Logged-in users (the block editor
  saves with it) can batch normally.
- GraphQL requests do not use the REST server and never consume this budget.

**GraphQL**

- The endpoint is public by default, like WPGraphQL. Enable "Restrict Endpoint to Logged In Users" in the
  WPGraphQL settings to require authentication; then session cookies, application passwords and the plugin API
  key are accepted. The plugin's own check is skipped in `local` and `development` environments, but WPGraphQL's
  setting still applies there, so an endpoint you restrict stays restricted.
- API key: create it in the GraphQL Security tab and send it as `X-API-Key: <key>` or
  `Authorization: Bearer <key>`. It only authenticates requests to the GraphQL endpoint (the default
  `/graphql` or the endpoint configured in WPGraphQL) as the configured service user.
- Introspection (`__schema`, `__type`) is rejected in the `production` environment for every client, API key
  included; `staging`, `development` and `local` allow it. The environment is the one WordPress reports
  (`WP_ENVIRONMENT_TYPE` constant or environment variable), and it is `production` when nothing is set, so
  set it on staging and local sites that need GraphiQL or code generation. `__typename`, which Apollo Client
  adds to every query, is not introspection and is always allowed.
- Limits apply to every query of a batched request: aliases (20, headless 50), query depth (10, headless 15),
  directives and length, and complexity (100, headless 200). Complexity adds one point per field with
  arguments or sub-fields, one per ten items of each `first:` argument, two per fragment and two per
  nesting level, so a page of 100 items costs about 10 on its own.
- Rate limit: anonymous operations are throttled per client IP, 60 per minute (120 in headless mode), plus
  10 for each batch slot WPGraphQL allows (at most 100 extra). Headless mode and build tools (user agents
  containing `next`, `node`, `fetch` and similar) get 1.5 times that. Authenticated requests, API key
  included, are not counted. Each operation of a batch counts once.

## 🧪 Development & Testing

### Quality Assurance Script

Run comprehensive quality checks matching CI/CD pipeline:

```bash
# Run all checks (PHPStan, PHPCS, PHPUnit)
./scripts/run-quality-checks.sh

# Run only WordPress tests (real environment)
./scripts/run-quality-checks.sh --skip-phpstan --skip-phpcs

# Run only type checking
./scripts/run-quality-checks.sh --skip-tests
```

### Behavior-Test Policy (TDD)

The plugin changes core WordPress behavior, so a feature that only registers its hook can pass review and still break a real user. WEB-1222 is the example: three regressions reached the block editor, none was caught by the suite, and one test asserted the bug. The policy:

- **Bug fix**: write the test that reproduces it, watch it fail, then fix. A test that passes without the fix proves nothing.
- **New hardening feature**: test (a) that the protection works and (b) that the core features it could break still work, including ones with no obvious link (block editor, REST, assets, login, embeds).
- **Real flows over mocks**: run real WordPress requests (`rest_do_request()`, WPGraphQL's `graphql()`, real login and redirects) and assert what a user or client receives, not that a hook exists. Fake only what is outside WordPress, such as an oEmbed provider (`pre_http_request`).
- **No vacuous assertions**: a test that cannot fail is worse than no test. Prove each new test fails against the previous code.
- Every pull request carries the checklist in `.github/pull_request_template.md`.

#### How to add a behavior test

1. **Integration (PHPUnit, `WP_UnitTestCase`)**: build the plugin class the way a request would, trigger the real WordPress path, and assert the result. Example: `tests/Integration/EditorCompatibilityTest.php` activates the hardening hooks, signs in as an editor, requests the REST routes the block editor calls and asserts they respond, while anonymous users still get nothing. `tests/Integration/OEmbedSanitizationTest.php` mocks only the oEmbed provider and asserts the rendered HTML.
2. **End to end (Playwright on `@wordpress/env`)**: use it when the behavior needs a browser, such as the block editor or the login screens. Example: `tests/e2e/editor.spec.ts` opens the editor as an administrator, inserts an Embed block and asserts there are no JS errors and the oEmbed proxy route exists. Run it with `npm run test:e2e:smoke` after `npm run wp-env:start`.
3. Run the new test against the code without your fix and confirm it fails, then run `bash scripts/run-phpunit-complete.sh` (a full run must complete) before opening the pull request.

### How to add a setting

Settings the screen saves go through one registry and one saver, so adding an option is three small steps and no new save code:

1. **Default**: add the option and its default to `DefaultConfig::get_defaults()`.
2. **Register it** in `src/Admin/Settings/SettingsRegistry.php` with its section (`login`, `rest_api`, `login_branding`, `admin_hide`, `graphql`, `graphql_auth`, `cf7`, `ip`), type (`bool`, `int`, `url`, `hex_color`, `admin_path`, `user_id`), `min` and `max` for integers, `ui` (the screen renders a field for it) and `autosave` (the auto-save endpoint may write it; leave it `false` unless the maintainers decide otherwise, see #160).
3. **Add the field** to the form of that section in `SettingsRenderer`, with the registered option name as the input `name`. The form already posts the gate field, its section and the nonce.

`SettingsSaver` clamps, sanitizes and writes it, and both the Save button and auto-save report what was saved, adjusted or ignored. `SettingsRegistryTest` and `SettingsFormsTest` fail if the default is missing, the field is not inside its own section's form, or the saved value does not persist.

### Behavior Audit

Every hook the plugin registers or removes is listed, with the core behavior it changes, who is affected, its risk
and the test that proves it (or a gap), in the "Behavior Audit Matrix" section of `.github/copilot-instructions.md`.
Update the matching row in the same PR whenever a hook in `src/` is added, removed or re-prioritised.

### Testing Strategy for Security Plugin

**🔒 CRITICAL**: This is a security plugin - testing requires real WordPress environment.

#### Two-Stage Testing Approach

**1. PHPStan (Static Analysis - Standalone)**

- Validates PHP type safety WITHOUT WordPress
- Fast static analysis (30 seconds)
- Catches type errors before running tests
- Configuration: `phpstan.neon` (Level 8)

**2. PHPUnit (Integration Testing - WordPress Environment)**

- Validates security features in REAL WordPress with MySQL
- Tests actual login protection, cookie security, GraphQL limits
- **CRITICAL** for security plugin validation
- Configuration: `phpunit.xml.dist`

#### Local Testing Setup

```bash
# One-time: Install WordPress Test Suite
./scripts/install-wp-tests.sh wordpress_test root '' localhost latest

# One-time: Install the same optional plugins CI uses (otherwise their tests are skipped)
./scripts/install-wpgraphql-for-tests.sh
./scripts/install-cf7-for-tests.sh

# Daily: Run quality checks before committing
./scripts/run-quality-checks.sh

# Or only the PHPUnit suite, failing if the run stops early (accepts PHPUnit arguments such as --filter)
bash scripts/run-phpunit-complete.sh
```

`install-wpgraphql-for-tests.sh` and `install-cf7-for-tests.sh` expect the WordPress core directory next to
`WP_TESTS_DIR` (`$(dirname "$WP_TESTS_DIR")/wordpress`). With WPGraphQL installed, the GraphQL tests run
instead of being skipped. Contact Form 7 is installed but deliberately not loaded by the shared test bootstrap:
loading it makes the CF7 admin tab appear, which several functional tests assume is hidden, so the CF7 tests
define what they need themselves and one real-environment test is skipped when the class is missing. The other
remaining skips (multisite, Settings Hub fallback) each state their reason. When the `CI` environment variable
is set, a missing WPGraphQL fails the GraphQL tests instead of skipping them.

#### End-to-End Tests (Playwright)

Browser tests in `tests/e2e/` run the real plugin inside `@wordpress/env` and check what a user
experiences: the block editor saves and publishes without JS errors, editor bundles keep `ver=`,
anonymous users cannot enumerate users while editors still can, security headers are present, and
login hardening works.

```bash
npm install && npx playwright install chromium
npm run wp-env:start        # http://localhost:8890 (admin / password), needs Docker
npm run test:e2e:smoke      # @smoke subset, runs on every PR
npm run test:e2e            # full suite, runs nightly
npm run test:e2e:admin-hide # the same site with admin hiding on (turns it on, restores it afterwards)
```

- Admin hiding specs live in `tests/e2e/admin-hide/` with their own config
  (`playwright.admin-hide.config.ts`) and `@smoke` subset (`npm run test:e2e:admin-hide:smoke`). They arrange
  state with WP-CLI through `wp-env run cli`, so run them from the checkout that started `wp-env`, and give
  each describe block its own `X-Forwarded-For` address so the per-IP limits do not collide.

- Specs log in once per role (`tests/e2e/global-setup.ts`). The plugin returns 404 for more than 15
  login-page requests per minute from one IP, so per-test logins would trip its own bot detection.
- Rule of thumb for new hardening features: add a test that exercises the *core feature it could
  break* (editor, REST, assets, login), not only the hook the feature registers.

#### Why Both Tests Are Required

**PHPStan alone ❌**: Cannot validate WordPress hooks, database operations, or security features  
**PHPUnit alone ❌**: Doesn't catch type errors early  
**Both together ✅**: Complete validation - type safety + real security testing

#### Test Coverage

- **Unit Tests**: 350+ tests across all security components
- **Integration Tests**: 50+ tests for WordPress environment
- **Security Tests**: Comprehensive coverage of login, cookies, GraphQL, CAPTCHA
- **CI/CD Matrix**: 12 environment combinations (PHP 8.0-8.2 × WordPress 6.5-latest)

## 🆘 Support & Troubleshooting

**Common Issues**

*GraphQL not working after activation?*

- Verify WPGraphQL plugin is installed and active
- Check GraphQL query complexity limits in settings

*Website seems slower?*

- Review rate limiting settings in Security Essentials
- Adjust GraphQL query limits if needed

*Tests failing locally?*

- Ensure WordPress Test Suite is installed: `./scripts/install-wp-tests.sh wordpress_test root '' localhost latest`
- Verify MySQL is running: `brew services start mysql` (macOS)
- Run quality checks: `./scripts/run-quality-checks.sh`

## 🌍 Multi-Language Support

- **English**: Default language
- **Spanish**: Complete translation included (`es_ES`)
- **Translation Ready**: `.pot` file included for additional languages

---

**Made with ❤️ by [Silver Assist](https://silverassist.com)**
