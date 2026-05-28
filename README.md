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
- **Strong Password Enforcement**: Mandatory complex passwords (12+ characters, mixed case, numbers, symbols)
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
- **Rate Limiting**: 30 requests per minute per IP to prevent DoS attacks
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

## ✨ Additional Security Features

### 🚫 IP Blacklisting *(v1.1.15+)*

- **Automatic Blacklisting**: Repeat offenders are automatically blacklisted after configurable threshold
- **Manual Management**: Block/unblock specific IP addresses from the admin panel
- **Dashboard Indicator**: Enabled/Disabled status shown on the Security Dashboard card
- **Cross-Component Protection**: Blacklisted IPs are blocked from login, admin, and form submissions

### 🔒 WordPress Hardening *(Automatic)*

- **Secure Headers**: Essential security headers (X-Frame-Options, X-XSS-Protection, etc.)
- **File Editing Disabled**: Prevents unauthorized file modifications through admin panel
- **XML-RPC Disabled**: Blocks XML-RPC attacks and vulnerabilities
- **Version Hiding**: Conceals WordPress version information from potential attackers

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
- Live statistics: login attempts, blocked IPs, GraphQL queries
- **Under Attack Mode indicator**: Shows Active/Inactive status in General Security card
- **IP Blacklisting indicator**: Shows Enabled/Disabled status in General Security card
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

- Comprehensive IP blocking and allowlist management
- Real-time blocked IPs monitoring across all protection layers
- Manual IP management (block/unblock specific addresses)
- Geographic and behavioral IP analysis reports

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
- Currently optimized for single WordPress installations
- Multisite compatibility coming in future versions

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

# Daily: Run quality checks before committing
./scripts/run-quality-checks.sh
```

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
