# Silver Assist Security Essentials - AI Coding Instructions

## 🚨 CRITICAL DOCUMENTATION RULE - READ FIRST

**⛔ NEVER CREATE SEPARATE .md DOCUMENTATION FILES ⛔**

**MANDATORY: All documentation MUST be maintained ONLY in these three files:**
1. **README.md** - User-facing documentation, features, installation, configuration
2. **CHANGELOG.md** - Version history, changes, updates, release notes
3. **.github/copilot-instructions.md** (this file) - Development guidelines, architecture, coding standards

**FORBIDDEN:**
- ❌ Creating files like `docs/FEATURE-GUIDE.md`
- ❌ Creating `CONTRIBUTING.md`, `ARCHITECTURE.md`, `API.md`, etc.
- ❌ Any separate documentation files in `docs/` directory
- ❌ Splitting documentation across multiple files

**REQUIRED:**
- ✅ Add all new documentation to appropriate section in README.md
- ✅ Document all changes in CHANGELOG.md under [Unreleased] section
- ✅ Update copilot-instructions.md for development guidelines
- ✅ Keep documentation consolidated in these three files ONLY

**Why this rule exists:**
- Prevents documentation fragmentation
- Reduces maintenance overhead
- Single source of truth for all information
- Easier to find and update documentation
- Consistent with project philosophy

**If you need to document something:**
1. **User features/guides** → Add to README.md
2. **Version changes/updates** → Add to CHANGELOG.md
3. **Development patterns/architecture** → Add to copilot-instructions.md

---

## Architecture Overview

This is a **WordPress security plugin** that resolves critical security vulnerabilities found in WordPress security audits. It uses **PSR-4 autoloading** with modern PHP 8+ patterns and follows a **modular component architecture** with strict separation of concerns.

### Security Vulnerabilities Addressed

The plugin specifically addresses three critical security issues commonly found in WordPress security assessments:

1. **WordPress Admin Login Page Exposure**: Implements comprehensive brute force protection with IP-based login attempt limiting, session timeout management, user enumeration protection, strong password enforcement, advanced bot/crawler blocking with 404 responses to automated reconnaissance tools, and security scanner blocking.

2. **HTTPOnly Cookie Flag Missing**: Automatically implements HTTPOnly flags for all WordPress cookies, secure cookies for HTTPS sites, SameSite protection against CSRF attacks, and enhanced session cookie security.

3. **GraphQL Security Misconfigurations**: Provides complete GraphQL security including introspection blocking in production, query depth and complexity limits, query timeout protection, rate limiting, alias abuse protection, field duplication blocking, and directive limitation.

## Core Technologies

- **PHP 8.3+**: Modern PHP with strict typing, union types, and match expressions
- **WordPress 6.5+**: Latest WordPress APIs and hooks
- **PSR-4 Autoloading**: Namespace-based class loading for better organization
- **Real-time Dashboard**: Live security monitoring with AJAX updates
- **Multi-language Support**: Complete i18n implementation (English/Spanish)
- **WP-CLI**: Required for translation file generation and management (install via `brew install wp-cli`)
- **WordPress Test Suite**: Real WordPress environment with WP_UnitTestCase for comprehensive testing

## 🚨 Test-Driven Development (TDD) - MANDATORY

**CRITICAL: This is a security plugin. ALL code MUST be test-driven. Write tests FIRST, then implement features.**

### TDD Workflow - The Red-Green-Refactor Cycle

**🚨 MANDATORY DEVELOPMENT SEQUENCE:**

#### **1. RED Phase - Write Failing Tests First**
```bash
# ALWAYS start here - write the test BEFORE any implementation
vendor/bin/phpunit tests/Security/NewFeatureTest.php
# Expected: Test fails (RED) because feature doesn't exist yet
```

**Rules:**
- ✅ Write test for the feature you want to implement
- ✅ Test MUST fail initially (proves test is valid)
- ✅ Test describes the expected behavior clearly
- ❌ NEVER write implementation code first
- ❌ NEVER skip the RED phase

**Example - New Security Feature:**
```php
// tests/Security/CSRFProtectionTest.php - WRITE THIS FIRST
class CSRFProtectionTest extends WP_UnitTestCase
{
    public function test_csrf_token_generation(): void
    {
        $csrf = new CSRFProtection();
        $token = $csrf->generate_token();
        
        $this->assertNotEmpty($token);
        $this->assertEquals(32, strlen($token));
    }
    
    public function test_csrf_token_validation(): void
    {
        $csrf = new CSRFProtection();
        $token = $csrf->generate_token();
        
        $this->assertTrue($csrf->validate_token($token));
        $this->assertFalse($csrf->validate_token("invalid_token"));
    }
}

// Run test - it MUST fail (class doesn't exist)
// vendor/bin/phpunit tests/Security/CSRFProtectionTest.php
// ❌ Error: Class 'CSRFProtection' not found - GOOD! Now we can implement.
```

#### **2. GREEN Phase - Minimal Implementation**
```php
// src/Security/CSRFProtection.php - NOW implement to make test pass
class CSRFProtection
{
    public function generate_token(): string
    {
        return bin2hex(random_bytes(16)); // Exactly 32 chars
    }
    
    public function validate_token(string $token): bool
    {
        // Minimal implementation to pass test
        return strlen($token) === 32 && ctype_xdigit($token);
    }
}

// Run test again
// vendor/bin/phpunit tests/Security/CSRFProtectionTest.php
// ✅ OK (2 tests, 4 assertions) - GREEN! Tests pass.
```

**Rules:**
- ✅ Write MINIMAL code to make test pass
- ✅ Don't add features not covered by tests
- ✅ Focus on making the RED test turn GREEN
- ❌ Don't over-engineer or add "nice to have" features
- ❌ Don't skip tests to "save time"

#### **3. REFACTOR Phase - Improve Code Quality**
```php
// Now refactor with confidence - tests ensure nothing breaks
class CSRFProtection
{
    private const TOKEN_LENGTH = 16; // bytes (32 hex chars)
    private const TOKEN_LIFETIME = 3600; // 1 hour
    
    public function generate_token(): string
    {
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        
        // Store with expiration (refactor - add session storage)
        \set_transient("csrf_token_{$token}", time(), self::TOKEN_LIFETIME);
        
        return $token;
    }
    
    public function validate_token(string $token): bool
    {
        // Refactor - add expiration check
        if (strlen($token) !== self::TOKEN_LENGTH * 2 || !ctype_xdigit($token)) {
            return false;
        }
        
        $stored_time = \get_transient("csrf_token_{$token}");
        return $stored_time !== false;
    }
}

// Run tests after refactor
// vendor/bin/phpunit tests/Security/CSRFProtectionTest.php
// ✅ Still passing - refactor successful!
```

**Rules:**
- ✅ Refactor ONLY when tests are passing
- ✅ Run tests after each refactor
- ✅ Improve code structure, readability, performance
- ✅ Extract constants, improve naming, reduce duplication
- ❌ NEVER refactor with failing tests
- ❌ Don't change behavior during refactor

### TDD Benefits for Security Plugin

**Why TDD is CRITICAL for security:**

1. **Security Validation**: Tests prove security features work BEFORE deployment
2. **Regression Prevention**: Changes can't break existing security measures
3. **Documentation**: Tests document expected security behavior
4. **Confidence**: Refactor security code without fear of breaking protections
5. **CI/CD Integration**: Automated testing catches issues before production

### TDD Test Organization

```
tests/
├── Unit/                          # Unit tests (isolated, fast)
│   ├── DefaultConfigTest.php     # Configuration management
│   ├── SecurityHelperTest.php    # Utility functions
│   └── GraphQLConfigManagerTest.php
├── Security/                      # Security feature tests
│   ├── GeneralSecurityTest.php   # Headers, cookies, hardening
│   ├── LoginSecurityTest.php     # Brute force, bot blocking
│   └── AdminHideSecurityTest.php # Admin path hiding
├── Core/                          # Core functionality tests
│   └── PathValidatorTest.php     # Path validation & security
├── Integration/                   # Integration tests
│   └── AdminPanelTest.php        # Admin interface integration
└── Helpers/                       # Test utilities
    └── TestHelper.php             # Shared test functions
```

### TDD Development Checklist

**Before starting ANY new feature:**

- [ ] **Write test file first** in appropriate `tests/` directory
- [ ] **Run test** - verify it fails (RED phase)
- [ ] **Implement minimal code** to pass test (GREEN phase)
- [ ] **Run test again** - verify it passes
- [ ] **Refactor if needed** - improve code quality
- [ ] **Run test after refactor** - ensure still passing
- [ ] **Commit** with test and implementation together
- [ ] **CI/CD validation** - verify in GitHub Actions

**Example commit message:**
```bash
git commit -m "✨ Add CSRF token protection with TDD

- Write tests first (RED): CSRFProtectionTest with 5 test cases
- Implement feature (GREEN): CSRFProtection class passes all tests
- Refactor: Add transient storage and expiration
- All tests passing: 5/5 ✅
- Security feature validated before deployment"
```

### TDD Anti-Patterns - AVOID THESE

**❌ Implementation-First Development:**
```php
// WRONG - Don't do this!
// 1. Write CSRFProtection class
// 2. Then write tests to match implementation
// Problem: Tests validate what you built, not what you need
```

**❌ Testing After Bugs:**
```php
// WRONG - Don't do this!
// 1. Deploy feature
// 2. Bug discovered in production
// 3. Write test to reproduce bug
// 4. Fix bug
// Problem: Security vulnerability was already deployed!
```

**❌ Skipping Tests for "Speed":**
```php
// WRONG - Don't do this!
// "I'll add tests later, need to ship this quickly"
// Problem: Technical debt, untested code, security risks
```

**✅ Correct TDD Approach:**
```php
// RIGHT - Always do this!
// 1. Write test describing desired behavior
// 2. Run test - verify it fails (RED)
// 3. Implement minimal code to pass test (GREEN)
// 4. Refactor for quality (REFACTOR)
// 5. Commit test + implementation together
// 6. Deploy with confidence - tests prove it works
```

### TDD Test Coverage Requirements

**MANDATORY coverage for security plugin:**

- **Unit Tests**: All utility functions, helpers, validators
- **Security Tests**: All security features (headers, cookies, auth, validation)
- **Integration Tests**: Admin panel, WordPress hooks, filters
- **Edge Cases**: Empty inputs, invalid data, malicious attempts
- **Failure Cases**: Test that security features block attacks

**Target Coverage:**
- Critical security classes: **100%** coverage required
- Utility classes: **90%+** coverage required
- Admin interface: **80%+** coverage required
- Overall project: **85%+** coverage required

**Generate coverage report:**
```bash
vendor/bin/phpunit --coverage-html coverage/
open coverage/index.html
```

### TDD Integration with GitHub Actions

**Automated TDD validation in CI/CD:**

```yaml
# .github/workflows/quality-checks.yml
wordpress-tests:
  strategy:
    matrix:
      php: ['8.0', '8.1', '8.2', '8.3']
      wordpress: ['6.5', '6.6', 'latest']
  steps:
    - name: Run WordPress Test Suite
      run: vendor/bin/phpunit --testdox
    - name: Fail if tests don't pass
      run: exit 1 if any test fails
```

**Benefits:**
- Every push runs full test suite
- 12 environment combinations tested (PHP × WordPress versions)
- Immediate feedback on test failures
- Prevents merging code with failing tests

### Real-World TDD Example - Login Rate Limiting

**Step 1: Write Test First (RED Phase)**
```php
// tests/Security/RateLimitTest.php
class RateLimitTest extends WP_UnitTestCase
{
    public function test_rate_limit_blocks_excessive_requests(): void
    {
        $rate_limiter = new RateLimiter();
        $ip = "192.168.1.100";
        
        // Allow first 5 requests
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($rate_limiter->allow_request($ip));
        }
        
        // Block 6th request
        $this->assertFalse($rate_limiter->allow_request($ip));
    }
}

// Run: vendor/bin/phpunit tests/Security/RateLimitTest.php
// ❌ FAILS - RateLimiter class doesn't exist (RED phase complete)
```

**Step 2: Implement Feature (GREEN Phase)**
```php
// src/Security/RateLimiter.php
class RateLimiter
{
    private const MAX_REQUESTS = 5;
    private const TIME_WINDOW = 60; // seconds
    
    public function allow_request(string $ip): bool
    {
        $key = "rate_limit_{$ip}";
        $requests = (int) \get_transient($key);
        
        if ($requests >= self::MAX_REQUESTS) {
            return false;
        }
        
        \set_transient($key, $requests + 1, self::TIME_WINDOW);
        return true;
    }
}

// Run: vendor/bin/phpunit tests/Security/RateLimitTest.php
// ✅ PASSES - Feature works (GREEN phase complete)
```

**Step 3: Refactor (REFACTOR Phase)**
```php
// Add more sophisticated features while maintaining passing tests
class RateLimiter
{
    private const MAX_REQUESTS = 5;
    private const TIME_WINDOW = 60;
    private const LOCKOUT_DURATION = 900; // 15 minutes after limit
    
    public function allow_request(string $ip): bool
    {
        // Check if IP is in lockout
        if ($this->is_locked_out($ip)) {
            SecurityHelper::log_security_event(
                "RATE_LIMIT_LOCKOUT",
                "IP in lockout period: {$ip}",
                ["ip" => $ip]
            );
            return false;
        }
        
        $key = "rate_limit_{$ip}";
        $requests = (int) \get_transient($key);
        
        if ($requests >= self::MAX_REQUESTS) {
            $this->initiate_lockout($ip);
            return false;
        }
        
        \set_transient($key, $requests + 1, self::TIME_WINDOW);
        return true;
    }
    
    private function is_locked_out(string $ip): bool
    {
        return \get_transient("rate_limit_lockout_{$ip}") !== false;
    }
    
    private function initiate_lockout(string $ip): void
    {
        \set_transient("rate_limit_lockout_{$ip}", time(), self::LOCKOUT_DURATION);
    }
}

// Run: vendor/bin/phpunit tests/Security/RateLimitTest.php
// ✅ STILL PASSES - Refactor successful, behavior unchanged
```

### TDD Summary - Critical Rules

**🚨 MANDATORY RULES FOR ALL DEVELOPMENT:**

1. **Write tests FIRST** - Never write implementation before tests
2. **Test MUST fail initially** - Proves test is valid (RED phase)
3. **Minimal implementation** - Just enough to pass test (GREEN phase)
4. **Refactor with confidence** - Tests ensure nothing breaks (REFACTOR phase)
5. **Commit tests + code together** - Never commit untested code
6. **Run tests before every commit** - Ensure all tests pass
7. **CI/CD validates everything** - GitHub Actions runs full test suite
8. **100% coverage for security** - Critical security code must be fully tested

**TDD mantra: "Red, Green, Refactor, Repeat"**

## Project Structure

```
silver-assist-security/
├── src/                           # PSR-4 source code
│   ├── Admin/AdminPanel.php       # WordPress admin interface
│   ├── Core/
│   │   ├── Plugin.php            # Main plugin initialization
│   │   ├── DefaultConfig.php     # Centralized configuration defaults
│   │   ├── PathValidator.php     # Path validation utilities
│   │   └── Updater.php           # Automatic GitHub updates
│   ├── Security/
│   │   ├── GeneralSecurity.php   # HTTPOnly cookies & headers
│   │   ├── LoginSecurity.php     # Brute force protection & bot blocking
│   │   └── AdminHideSecurity.php # Admin login page protection
│   └── GraphQL/
│       ├── GraphQLConfigManager.php # Centralized GraphQL configuration
│       └── GraphQLSecurity.php   # GraphQL protection
├── assets/                        # Frontend resources
│   ├── css/
│   │   ├── variables.css         # CSS custom properties system
│   │   ├── admin.css             # Admin panel styling
│   │   └── password-validation.css # Password strength validation styles
│   └── js/
│       ├── admin.js              # Real-time dashboard functionality
│       └── password-validation.js # Password strength validation
├── languages/                     # Internationalization
│   ├── silver-assist-security.pot # Translation template
│   ├── silver-assist-security-es_ES.po # Spanish translations
│   └── silver-assist-security-es_ES.mo # Compiled Spanish
├── tests/                         # Unit and integration tests
│   ├── Unit/                     # Unit tests
│   ├── Integration/              # Integration tests
│   ├── Security/                 # Security tests
│   └── Helpers/                  # Test helper classes
├── vendor/                        # Composer dependencies
│   └── silverassist/wp-github-updater/ # GitHub update system
└── silver-assist-security.php    # Main plugin file
```

## Component Architecture

### 1. Core\Plugin.php
**Purpose**: Main plugin initialization and orchestration
**Key Responsibilities**:
- Initialize security components in correct order
- Handle WordPress hooks and filters
- Manage plugin lifecycle (activation/deactivation)
- Coordinate between security modules

### 2. Core\DefaultConfig.php
**Purpose**: Centralized configuration management for all plugin settings
**Key Responsibilities**:
- Single source of truth for all plugin default values
- Eliminates configuration redundancy across components
- Provides consistent fallback values for all security features
- Simplifies maintenance and updates to default configurations

### 3. Core\Updater.php
**Purpose**: Automatic GitHub-based update system
**Key Responsibilities**:
- Check for updates from SilverAssist/silver-assist-security repository
- Download and install plugin updates
- Version comparison and update notifications
- Backup recommendations and update management

### 4. Core\SecurityHelper.php
**Purpose**: Centralized security utility functions and helper methods
**Key Responsibilities**:
- Asset URL generation with automatic minification support
- Client IP detection with proxy/CDN/load balancer support
- Password strength validation with comprehensive security requirements
- Standardized 404 response handling for security endpoints
- Structured security event logging with JSON format
- AJAX request validation with nonce and capability checks
- IP-based transient key generation for rate limiting
- Bot and crawler detection with advanced pattern matching
- Time duration formatting for user-friendly displays
- Centralized nonce and capability validation helpers
- Contact Form 7 plugin detection and status checking

**🚨 MANDATORY USAGE PATTERNS**:
- **Asset Loading**: ALWAYS use `SecurityHelper::get_asset_url($path)` instead of duplicating minification logic
- **IP Detection**: ALWAYS use `SecurityHelper::get_client_ip()` for consistent IP detection across components
- **CF7 Detection**: ALWAYS use `SecurityHelper::is_contact_form_7_active()` for CF7 integration checks
- **Security Logging**: ALWAYS use `SecurityHelper::log_security_event($type, $message, $context)` instead of raw `error_log()`
- **AJAX Validation**: ALWAYS use `SecurityHelper::validate_ajax_request($nonce_action)` for AJAX endpoints
- **404 Responses**: ALWAYS use `SecurityHelper::send_404_response()` for security-related 404s
- **Password Validation**: ALWAYS use `SecurityHelper::is_strong_password($password)` for consistency

**Helper Function Categories**:
- **Asset Management**: `get_asset_url()` with SCRIPT_DEBUG-aware minification
- **Network Security**: `get_client_ip()`, `is_bot_request()`, `send_404_response()`
- **Authentication**: `is_strong_password()`, `verify_nonce()`, `check_user_capability()`
- **Data Management**: `generate_ip_transient_key()`, `sanitize_admin_path()`
- **Logging & Monitoring**: `log_security_event()`, `format_time_duration()`
- **AJAX Utilities**: `validate_ajax_request()` with comprehensive security checks

### 5. Admin\AdminPanel.php
**Purpose**: WordPress admin interface for security configuration
**Key Responsibilities**:
- Register with Settings Hub or fallback to standalone menu
- Render Security Essentials dashboard page
- Handle AJAX requests for real-time updates
- Process security configuration form submissions
- Display security statistics and compliance status
- Integrate "Check Updates" button via Settings Hub actions
- Use GraphQLConfigManager for centralized GraphQL configuration
- Use DefaultConfig for consistent configuration handling

**🎯 Settings Hub Integration (v1.1.13+)**:
- **Primary Mode**: Registers plugin under centralized "Silver Assist" menu
- **Fallback Mode**: Standalone menu in Settings when hub unavailable
- **Update Button**: One-click update checking via Settings Hub actions
- **Automatic Detection**: Class existence check for seamless integration
- **Exception Handling**: Graceful degradation with error logging

**Settings Hub Registration Pattern**:
```php
// In AdminPanel::register_with_hub()
if (!class_exists(SettingsHub::class)) {
    // Fallback to standalone menu
    $this->add_admin_menu();
    return;
}

$hub = SettingsHub::get_instance();
$hub->register_plugin(
    'silver-assist-security',
    __('Security', 'silver-assist-security'),
    [$this, 'render_admin_page'],
    [
        'description' => __('Security configuration for WordPress', 'silver-assist-security'),
        'version' => SILVER_ASSIST_SECURITY_VERSION,
        'tab_title' => __('Security', 'silver-assist-security'),
        'actions' => $this->get_hub_actions()
    ]
);
```

**Hub Actions Integration**:
- `get_hub_actions()`: Returns array of action button configurations
- `render_update_check_script()`: JavaScript callback for update button
- `ajax_check_updates()`: AJAX handler for update verification
- Security validation with nonce and capability checks
- Integration with wp-github-updater for version checking

**Integration Pattern**:
```php
// ✅ CORRECT - Use SecurityHelper for all utility functions
use SilverAssist\Security\Core\SecurityHelper;

class YourSecurityClass {
    public function __construct() {
        // SecurityHelper auto-initializes, no manual setup needed
    }
    
    private function load_assets(): void {
        $css_url = SecurityHelper::get_asset_url("assets/css/component.css");
        wp_enqueue_style("component-style", $css_url, [], "1.0.0");
    }
    
    public function ajax_handler(): void {
        if (!SecurityHelper::validate_ajax_request("your_nonce_action")) {
            wp_send_json_error(["error" => "Security validation failed"]);
            return;
        }
        
        SecurityHelper::log_security_event(
            "AJAX_SUCCESS", 
            "Component AJAX request processed",
            ["function" => __FUNCTION__]
        );
    }
    
    private function handle_suspicious_request(): void {
        if (SecurityHelper::is_bot_request()) {
            SecurityHelper::send_404_response();
        }
    }
}

// ❌ INCORRECT - Don't duplicate helper logic
class BadSecurityClass {
    private function get_asset_url($path): string {
        // Don't duplicate this logic - use SecurityHelper::get_asset_url()
        $min_suffix = (defined("SCRIPT_DEBUG") && SCRIPT_DEBUG) ? "" : ".min";
        // ... duplicated code
    }
}
```

### 5. Admin\AdminPanel.php (v1.1.15+ Enhanced Architecture)
**Purpose**: Main admin interface orchestration with modular component architecture
**Key Responsibilities**:
- Register with Settings Hub or fallback to standalone menu
- Coordinate AdminPageRenderer, SettingsRenderer, and DashboardRenderer components
- Handle AJAX requests for real-time updates with security validation
- Process security configuration form submissions with proper sanitization
- Settings Hub Integration (v1.1.13+) with "Check Updates" button
- Use GraphQLConfigManager and DefaultConfig for centralized configuration

**🎯 Settings Hub Integration (v1.1.13+)**:
- **Primary Mode**: Registers plugin under centralized "Silver Assist" menu
- **Fallback Mode**: Standalone menu in Settings when hub unavailable
- **Update Button**: One-click update checking via Settings Hub actions
- **Automatic Detection**: Class existence check for seamless integration
- **Exception Handling**: Graceful degradation with error logging

**Settings Hub Registration Pattern**:
```php
// In AdminPanel::register_with_hub()
if (!class_exists(SettingsHub::class)) {
    // Fallback to standalone menu
    $this->add_admin_menu();
    return;
}

$hub = SettingsHub::get_instance();
$hub->register_plugin(
    'silver-assist-security',
    __('Security', 'silver-assist-security'),
    [$this, 'render_admin_page'],
    [
        'description' => __('Security configuration for WordPress', 'silver-assist-security'),
        'version' => SILVER_ASSIST_SECURITY_VERSION,
        'tab_title' => __('Security', 'silver-assist-security'),
        'actions' => $this->get_hub_actions()
    ]
);
```

### 5.1. Admin\Renderer\AdminPageRenderer.php (v1.1.15+)
**Purpose**: Main page structure rendering with namespace-separated navigation
**Key Responsibilities**:
- Render 5-tab navigation structure with `.silver-nav-tab` classes for namespace separation
- Coordinate DashboardRenderer and SettingsRenderer components
- Handle conditional Contact Form 7 tab visibility based on plugin detection
- Implement dual navigation system compatible with Settings Hub
- Security permissions validation and admin page structure

**🎛️ Tab Namespace Separation (v1.1.15+)**:
- **Hub Level Navigation**: `.nav-tab` classes for Settings Hub plugin switching
- **Security Internal Navigation**: `.silver-nav-tab` classes for feature navigation
- **Zero Conflicts**: Both navigation systems coexist independently
- **Dynamic Tab Detection**: Automatic handling of conditional CF7 tab

**Tab Structure**:
```php
// 5-tab structure (4 when CF7 inactive)
'dashboard-tab'      => 'Security Dashboard'
'login-security-tab' => 'Login Protection'
'graphql-security-tab' => 'GraphQL Security'
'cf7-security-tab'   => 'Form Protection' (conditional)
'ip-management-tab'  => 'IP Management'
```

### 5.2. Admin\Renderer\SettingsRenderer.php (v1.1.15+)
**Purpose**: All settings tabs content rendering with centralized configuration
**Key Responsibilities**:
- Render all non-dashboard tab content using `.silver-tab-content` classes
- Use GraphQLConfigManager for GraphQL settings and status
- Use DefaultConfig for consistent configuration defaults
- Handle Contact Form 7 integration status and configuration
- Real-time validation and user feedback

### 5.3. Admin\Renderer\DashboardRenderer.php (v1.1.15+)
**Purpose**: Security dashboard tab with real-time monitoring and statistics
**Key Responsibilities**:
- Real-time security status overview and compliance indicators
- Live statistics display (login attempts, blocked IPs, GraphQL queries)
- Security recommendations and quick action buttons
- Integration status for all security components
- Performance monitoring and system health checks

### 6. Security\LoginSecurity.php
**Purpose**: Brute force protection, bot blocking, and login security
**Key Responsibilities**:
- IP-based login attempt limiting (1-20 attempts configurable)
- Session timeout management (5-120 minutes)
- User enumeration protection
- Strong password enforcement
- Failed login tracking and blocking
- Bot and crawler detection and blocking
- 404 responses to automated reconnaissance tools
- Security scanner blocking (Nmap, Nikto, WPScan, etc.)

### 7. Security\GeneralSecurity.php
**Purpose**: HTTPOnly cookies and general WordPress hardening
**Key Responsibilities**:
- Automatic HTTPOnly flag implementation for all cookies
- Secure cookie configuration for HTTPS sites
- SameSite protection against CSRF
- Security headers (X-Frame-Options, X-XSS-Protection, CSP)
- WordPress hardening (XML-RPC blocking, version hiding)

### 8. GraphQL\GraphQLConfigManager.php
**Purpose**: Centralized GraphQL configuration management
**Key Responsibilities**:
- Single source of truth for all GraphQL configurations
- WPGraphQL plugin detection and integration
- Headless CMS mode configuration management
- Intelligent rate limiting configuration
- Security evaluation and recommendations
- HTML display generation for admin interface
- Configuration caching for performance optimization

### 9. GraphQL\GraphQLSecurity.php
**Purpose**: Comprehensive GraphQL endpoint protection
**Key Responsibilities**:
- Introspection blocking in production environments
- Query depth limits (1-20 levels, default: 8)
- Query complexity control (10-1000 points, default: 100)
- Query timeout protection (1-30 seconds, default: 5)
- Rate limiting (30 requests/minute per IP)
- Alias abuse and field duplication protection

### 10. Security\ContactForm7Integration.php (v1.1.15+)
**Purpose**: Contact Form 7 plugin integration and form protection
**Key Responsibilities**:
- Automatic CF7 plugin detection and seamless integration
- Form submission rate limiting with IP-based tracking
- Advanced bot protection specifically for form submissions
- CSRF token enhancement for form security
- Real-time monitoring and logging of blocked form attempts
- Temporary IP blocking for excessive submission attempts
- Integration with main security dashboard for unified monitoring

**🎯 CF7 Integration Features**:
- **Dynamic Detection**: Automatic activation when Contact Form 7 is installed
- **Zero Configuration**: Works immediately after CF7 plugin detection
- **Rate Limiting**: Configurable submission limits per IP address
- **Bot Protection**: Advanced detection of automated form submission attempts
- **Security Headers**: Enhanced CSRF protection for form endpoints
- **Monitoring Integration**: Real-time statistics in IP Management tab
- **Conditional Interface**: Form Protection tab appears automatically when CF7 detected

**CF7 Integration Pattern**:
```php
// Automatic CF7 detection and integration
if (SecurityHelper::is_contact_form_7_active()) {
    $cf7_integration = new ContactForm7Integration();
    $cf7_integration->init();
    
    // Dynamic tab rendering
    add_action('admin_page_render_tabs', [$this, 'render_cf7_tab']);
}
```

### 11. Security\FormProtection.php (v1.1.15+) 
**Purpose**: Generic form protection system (foundation for CF7 integration)
**Key Responsibilities**:
- Base form protection mechanisms and rate limiting
- IP-based submission tracking and validation
- Generic bot detection patterns for any form type
- CSRF token validation and nonce management
- Extensible architecture for different form plugins
- Centralized form security event logging

## Security Implementation Details

### Login Protection Strategy
- **IP Tracking**: Uses WordPress transients for temporary IP blocking
- **Attempt Limiting**: Configurable failed login thresholds per IP
- **Session Management**: Custom session timeout with secure cookie handling
- **User Enumeration**: Standardizes login error messages to prevent user discovery
- **Password Strength**: Enforces complex passwords (12+ chars, mixed case, numbers, symbols)
- **Bot Detection**: Identifies and blocks known crawlers, scanners, and automated tools
- **404 Responses**: Returns "Not Found" to suspicious requests to hide login page
- **Rate Limiting**: Prevents rapid-fire access attempts from automated scripts

### Cookie Security Implementation
- **HTTPOnly Flag**: Automatically applied to all WordPress authentication cookies
- **Secure Flag**: Applied when HTTPS is detected
- **SameSite Attribute**: Prevents cross-site request forgery attacks
- **Domain Validation**: Ensures cookies are properly scoped

### GraphQL Protection Strategy
- **Detection**: Automatically detects WPGraphQL plugin installation
- **Centralized Configuration**: Uses GraphQLConfigManager for unified settings management
- **Introspection Control**: Disables schema introspection in production
- **Query Analysis**: Real-time analysis of query depth and complexity
- **Intelligent Rate Limiting**: Adaptive limits based on WPGraphQL configuration and headless mode
- **Native Integration**: Seamless integration with WPGraphQL native settings
- **Security Headers**: Custom headers for GraphQL-specific protection
- **Configuration Caching**: Performance optimization through centralized caching

## Configuration & Settings

### Centralized Configuration System

The plugin uses a **two-tier configuration approach** for maximum reliability:

1. **Bootstrap Configuration** (`silver-assist-security.php`): Sets initial database values during plugin activation
2. **Runtime Configuration** (`src/Core/DefaultConfig.php`): Provides centralized defaults for all classes

```php
// DefaultConfig.php - Single source of truth for all defaults
class DefaultConfig {
    public static function get_defaults(): array {
        return [
            "silver_assist_login_attempts" => 5,           // Failed logins before lockout
            "silver_assist_lockout_duration" => 900,       // 15 minutes lockout
            "silver_assist_session_timeout" => 30,         // 30 minutes session
            "silver_assist_password_strength_enforcement" => 1, // Strong passwords required
            "silver_assist_bot_protection" => 1,           // Bot and crawler blocking enabled
            "silver_assist_graphql_query_depth" => 8,      // Max query depth
            "silver_assist_graphql_query_complexity" => 100, // Max complexity points
            "silver_assist_graphql_query_timeout" => 5,    // 5 second timeout
            "silver_assist_graphql_headless_mode" => 0     // Headless CMS mode - DISABLED by default
        ];
    }
    
    public static function get_option(string $option_name) {
        return get_option($option_name, self::get_default($option_name));
    }
}
```

**Usage Pattern in Classes**:
```php
use SilverAssist\Security\Core\DefaultConfig;

// Instead of: get_option("silver_assist_login_attempts", 5)
// Use:       DefaultConfig::get_option("silver_assist_login_attempts")
```

### Security Essentials Dashboard
- **Real-time Monitoring**: Live updates via AJAX every 5 seconds
- **Compliance Indicators**: Visual status for each security vulnerability
- **Statistics Display**: Failed logins, blocked IPs, GraphQL queries
- **Configuration Controls**: Toggle switches and sliders for settings
- **Multi-language Support**: All text translatable

## Development Guidelines

### Coding Standards
- **WordPress Coding Standards**: Full compliance with WordPress PHP standards
- **PSR-4 Autoloading**: Proper namespace organization
- **Type Declarations**: Use PHP 8+ strict typing everywhere
- **Error Handling**: Comprehensive try-catch blocks with logging
- **Security First**: All user inputs sanitized and validated

### WordPress Integration
- **Hooks & Filters**: Use appropriate WordPress hooks for functionality
- **Database**: Use WordPress options API, avoid custom tables
- **Caching**: Leverage WordPress transients for performance
- **Admin Interface**: Follow WordPress admin UI patterns and styles
- **Internationalization**: All strings must be translatable

### Security Best Practices
- **Input Validation**: Sanitize all user inputs using WordPress functions
- **Output Escaping**: Escape all outputs using appropriate WordPress functions
- **Nonce Verification**: Use WordPress nonces for form security
- **Capability Checks**: Verify user permissions before sensitive operations
- **SQL Injection Prevention**: Use WordPress prepared statements

### Helper Function Development Guidelines

**🚨 MANDATORY: All utility functions MUST be centralized in SecurityHelper.php**

#### **When to Add Functions to SecurityHelper**
- **Code Duplication**: If the same logic appears in 2+ classes
- **Security Utilities**: Any security-related utility function
- **Common Operations**: Asset loading, IP detection, validation, logging
- **Cross-Component Usage**: Functions needed by multiple security components
- **WordPress Integration**: Wrappers for WordPress functions with enhanced security

#### **SecurityHelper Function Categories**
1. **Asset Management**: URL generation, minification handling
2. **Network Security**: IP detection, bot detection, 404 responses
3. **Authentication**: Password validation, nonce verification, capability checks
4. **Data Management**: Transient key generation, path sanitization
5. **Logging & Monitoring**: Structured security event logging, time formatting
6. **AJAX Utilities**: Request validation, response standardization

#### **Function Development Pattern**
```php
/**
 * [Function description]
 * 
 * [Detailed explanation of purpose and usage]
 * 
 * @since 1.1.10
 * @param [type] $param [description]
 * @return [type] [description]
 */
public static function function_name($param): return_type
{
    // Implementation with proper error handling
    // Use existing SecurityHelper functions when possible
    // Include security logging for important operations
    // Follow WordPress coding standards
}
```

#### **Integration Requirements**
- **Centralized Initialization**: SecurityHelper::init() called in Plugin constructor
- **Static Methods**: All helper functions must be static for easy access
- **Auto-initialization**: Functions should auto-initialize if needed
- **Consistent Naming**: Use clear, descriptive function names
- **Documentation**: Complete PHPDoc for all functions
- **Error Handling**: Proper exception handling and logging

#### **Examples of Functions to Centralize**
- **Duplicate Asset Loading**: Move to `SecurityHelper::get_asset_url()`
- **IP Detection Logic**: Move to `SecurityHelper::get_client_ip()`
- **Validation Functions**: Move to `SecurityHelper::validate_*()` functions
- **404 Response Logic**: Move to `SecurityHelper::send_404_response()`
- **Logging Functions**: Move to `SecurityHelper::log_security_event()`
- **Time Formatting**: Move to `SecurityHelper::format_time_duration()`

#### **Migration Process for Existing Functions**
1. **Identify Duplicated Code**: Look for similar functions across classes
2. **Create Centralized Version**: Add to SecurityHelper with enhanced features
3. **Update All References**: Replace old functions with SecurityHelper calls
4. **Remove Duplicated Code**: Delete old functions from individual classes
5. **Test Thoroughly**: Ensure all functionality works correctly
6. **Update Documentation**: Document new helper functions

#### **🚨 CRITICAL: SecurityHelper Usage Rules**
- **NEVER duplicate SecurityHelper logic** in other classes
- **ALWAYS use SecurityHelper functions** instead of implementing similar logic
- **PREFER SecurityHelper expansion** over creating new utility classes
- **MAINTAIN backwards compatibility** when updating helper functions
- **DOCUMENT breaking changes** clearly in helper function updates

## Testing & Quality Assurance

### 🚨 WordPress Test Suite Integration

**The plugin uses WordPress Test Suite (WP_UnitTestCase) for ALL tests - both local development and GitHub Actions CI/CD.**

**CRITICAL: This project follows Test-Driven Development (TDD). See the "Test-Driven Development (TDD) - MANDATORY" section above for complete TDD guidelines. ALL new features must be developed test-first.**

#### **Test Infrastructure**
- **Framework**: WordPress Test Suite with WP_UnitTestCase (extends PHPUnit\Framework\TestCase)
- **Local Setup**: `scripts/install-wp-tests.sh wordpress_test root '' localhost latest`
- **Database**: Real MySQL database for integration tests
- **WordPress**: Real WordPress installation in `/tmp/wordpress/`
- **Test Suite**: Located in `/tmp/wordpress-tests-lib/`
- **Configuration**: `phpunit.xml.dist` with WP_TESTS_DIR constant

#### **Test Directory Structure**

```
tests/
├── Unit/                          # Unit tests with WP_UnitTestCase
│   ├── DefaultConfigTest.php     # DefaultConfig class tests
│   ├── GraphQLConfigManagerTest.php # GraphQL configuration tests
│   ├── LoginSecurityTest.php     # Login security tests
│   └── SecurityHelperTest.php    # SecurityHelper utility tests
├── Security/                      # Security-specific tests
│   └── SecurityTest.php          # Overall security validation
├── WordPress/                     # WordPress integration examples
│   └── AdminPanelTest.php        # Example WP_UnitTestCase implementation
├── Helpers/                       # Test utilities
│   └── TestHelper.php            # Shared test helper functions
├── bootstrap.php                  # WordPress Test Suite bootstrap
└── results/                       # Test output (excluded from git)
```

#### **Running Tests Locally**

```bash
# First-time setup: Install WordPress Test Suite
scripts/install-wp-tests.sh wordpress_test root '' localhost latest

# Run all tests
vendor/bin/phpunit --testdox

# Run specific suite
vendor/bin/phpunit --testsuite "Unit Tests"

# Run specific file
vendor/bin/phpunit tests/Unit/DefaultConfigTest.php

# With coverage (requires Xdebug)
vendor/bin/phpunit --coverage-html coverage/
```

#### **GitHub Actions CI/CD**

**Workflow**: `.github/workflows/quality-checks.yml`

**Job: `wordpress-tests`** (3 test combinations)
- **Matrix**: PHP 8.3 × WordPress 6.5, 6.6, latest
- **Database**: MySQL 8.0 service container
- **Installation**: Automatic via `scripts/install-wp-tests.sh`
- **Execution**: Full PHPUnit test suite with real WordPress

**Job: `syntax-validation`** (4 PHP versions)
- **Purpose**: Fast syntax validation without WordPress
- **Checks**: PHP syntax, PSR-4 autoloading
- **Speed**: Completes in ~30 seconds per PHP version

#### **WordPress Test Suite Benefits**
- ✅ **Real WordPress Functions**: No mocks needed - use actual WordPress APIs
- ✅ **Real Database**: MySQL transactions with automatic rollback after each test
- ✅ **WordPress Factories**: Built-in factories for users, posts, terms, etc.
- ✅ **Hook System**: Test real WordPress hooks and filters
- ✅ **Auto-Cleanup**: Each test runs in isolation with automatic cleanup
- ✅ **Comprehensive**: Test complete WordPress functionality, not just PHP logic

#### **Test Writing Pattern**

```php
use WP_UnitTestCase;

class ExampleTest extends WP_UnitTestCase
{
    public function test_wordpress_option(): void
    {
        // Use real WordPress functions
        update_option("my_option", "value");
        $result = get_option("my_option");
        $this->assertEquals("value", $result);
    }
    
    public function test_user_creation(): void
    {
        // Use WordPress factories
        $user_id = $this->factory()->user->create(['role' => 'administrator']);
        $this->assertGreaterThan(0, $user_id);
    }
    
    public function test_wordpress_hooks(): void
    {
        // Test real hooks
        $called = false;
        add_action('my_hook', function() use (&$called) {
            $called = true;
        });
        do_action('my_hook');
        $this->assertTrue($called);
    }
}
```

### 🚨 MANDATORY Testing File Organization

**ALL test files MUST be created within the `/tests/` directory structure:**

- **Unit Tests**: `/tests/Unit/` - Individual class/method tests with WP_UnitTestCase
- **Security Tests**: `/tests/Security/` - Security-specific validation
- **WordPress Examples**: `/tests/WordPress/` - Integration test examples
- **Helper Classes**: `/tests/Helpers/` - Shared testing utilities
- **Test Results**: `/tests/results/` - Test output (git-ignored)

**NEVER create test files in the project root directory. Always use the proper `/tests/` subdirectory structure.**

### Security Testing Requirements

**🚨 ALL security features MUST be developed using TDD methodology:**

1. **Write test FIRST** describing security requirement
2. **Run test** to verify it fails (RED)
3. **Implement security feature** to make test pass (GREEN)
4. **Refactor** for code quality while maintaining passing tests
5. **Commit** test + implementation together

**Security test categories:**
- **Brute Force Testing**: Verify login attempt limiting works correctly
- **Cookie Security**: Confirm HTTPOnly flags are applied properly
- **GraphQL Protection**: Test query limits and rate limiting
- **User Enumeration**: Ensure login errors don't reveal valid usernames
- **Cross-site Scripting**: Verify XSS protection via HTTPOnly cookies
- **Path Validation**: Test forbidden path detection and sanitization
- **Bot Detection**: Verify crawler and scanner blocking
- **Session Management**: Test timeout and secure session handling

**Example TDD workflow for security feature:**
```bash
# 1. Write test for IP blocking feature
vendor/bin/phpunit tests/Security/IPBlockingTest.php
# ❌ Fails - IPBlocking class doesn't exist

# 2. Implement minimal IPBlocking class
vendor/bin/phpunit tests/Security/IPBlockingTest.php
# ✅ Passes - Feature works

# 3. Refactor and enhance
vendor/bin/phpunit tests/Security/IPBlockingTest.php
# ✅ Still passes - Security validated

# 4. Commit together
git commit -m "✨ Add IP blocking with TDD validation"
```

### Performance Testing
- **Page Load Impact**: Ensure minimal performance overhead
- **Memory Usage**: Monitor PHP memory consumption
- **Database Queries**: Optimize database interactions
- **AJAX Responsiveness**: Real-time dashboard should update smoothly

### Compatibility Testing
- **WordPress Versions**: Test with WordPress 6.5+ (automated in CI/CD)
- **PHP Versions**: Ensure compatibility with PHP 8.3+ (automated in CI/CD)
- **Plugin Conflicts**: Test with common security plugins
- **Theme Compatibility**: Verify admin interface renders correctly

## Deployment & Updates

### Automatic Update System
- **GitHub Integration**: Pull updates from SilverAssist/silver-assist-security
- **Version Checking**: Daily automatic update checks
- **Security Priority**: Prioritize security patches
- **Changelog Display**: Show release notes before updates

### Release Process
- **Version Bumping**: Update version in main plugin file and readme
- **Translation Updates**: Regenerate .pot files for new strings
- **Security Testing**: Full security audit before release
- **Documentation**: Update README and CHANGELOG
- **Backup Recommendations**: Always advise users to backup before updates

## 🤖 Automated Dependency Management (CI/CD)

### GitHub Actions + Dependabot System

**CRITICAL: This plugin uses a fully automated CI/CD system for dependency management. Never manually update dependencies without understanding this workflow.**

#### System Overview

**Configuration Files:**
- `.github/dependabot.yml` - Dependency scanning configuration for Composer, npm, and GitHub Actions
- `.github/workflows/dependency-updates.yml` - Automated validation and auto-merge workflow

**What It Does:**
- ✅ **Weekly Checks**: Automatically verifies all dependencies every Monday (9:00 AM, 9:30 AM, 10:00 AM Mexico City)
- ✅ **Auto-PRs**: Creates Pull Requests with dependency updates
- ✅ **Quality Gates**: Runs PHPStan, PHPCS, npm builds, and security audits
- ✅ **Auto-Merge**: Safe updates (minor/patch) merge automatically after validation
- ✅ **Manual Review**: Major version updates require human approval
- ✅ **Security Audits**: Continuous CVE scanning with 90-day report retention
- ✅ **Copilot Reviews**: All PRs automatically reviewed by GitHub Copilot

#### Workflow Jobs

**Job 1: `check-composer-updates`**
- Validates `composer.json` and `composer.lock`
- Executes `composer outdated --direct --format=json`
- Runs PHPStan (static analysis)
- Runs PHPCS (WordPress Coding Standards)
- Generates markdown table of outdated packages
- Saves report artifact (30-day retention)

**Job 2: `check-npm-updates`**
- Executes `npm outdated --json`
- Runs `npm run build` for asset validation
- Verifies all minified files exist
- Generates markdown table of outdated packages
- Saves report artifact (30-day retention)

**Job 3: `security-audit`**
- Executes `composer audit --format=json`
- Executes `npm audit --json`
- Detects CVEs and security advisories
- Saves security reports (90-day retention)
- Generates summary with vulnerability counts

**Job 4: `validate-pr`**
- Only runs on Dependabot PRs
- Validates PHP syntax across all files
- Runs PHPCS and PHPStan
- Builds all assets with `npm run build`
- Comments validation results on PR
- Blocks merge if critical checks fail

**Job 5: `auto-merge-dependabot`**
- Auto-approves PRs for `version-update:semver-patch` and `version-update:semver-minor`
- Enables auto-merge for safe updates
- Requires all checks to pass first
- Comments alert for major version updates
- Major versions require manual review

#### Critical Packages Configuration

**Always Create Separate PRs (Never Group):**
```yaml
ignore:
  - dependency-name: "silverassist/wp-settings-hub"
    update-types: ["version-update:semver-major"]
  - dependency-name: "silverassist/wp-github-updater"
    update-types: ["version-update:semver-major"]
```

**Why These Are Critical:**
- `silverassist/wp-settings-hub` - Breaking changes can break entire admin UI
- `silverassist/wp-github-updater` - Breaking changes can break update system

#### Schedule & Timing

| Time (Mexico City) | Action | Package Ecosystem |
|--------------------|--------|-------------------|
| Monday 9:00 AM | Composer Check | PHP dependencies |
| Monday 9:30 AM | npm Check | JavaScript dependencies |
| Monday 10:00 AM | GitHub Actions Check | Workflow dependencies |
| 24/7 | Security Alerts | All ecosystems |

#### Dependabot Configuration Patterns

**Grouping Strategy:**
```yaml
groups:
  composer-minor-patch:
    patterns: ["*"]
    update-types: ["minor", "patch"]
  npm-minor-patch:
    patterns: ["*"]
    update-types: ["minor", "patch"]
```

**Labels Applied:**
- `dependencies` - All dependency updates
- `composer` - Composer package updates
- `npm` - npm package updates
- `github-actions` - Workflow updates
- `automated` - Automated PRs

**Reviewers:**
- `copilot` - GitHub Copilot AI reviews all PRs
- Assignees: `SilverAssist` - Human oversight

#### Developer Workflow

**When Dependabot Creates a PR:**

**Minor/Patch Update (Automatic):**
1. Dependabot creates PR with grouped updates
2. Workflow runs all 5 jobs automatically
3. If all checks pass → Auto-approved
4. Auto-merge executes → PR merged to main
5. No human intervention needed

**Major Update (Manual Review Required):**
1. Dependabot creates separate PR for each major update
2. Workflow runs validation jobs
3. Comments alert: "Manual review required"
4. Developer must:
   - Review changelog of dependency
   - Check for breaking changes
   - Test locally if needed
   - Approve PR manually
   - Merge when ready

**Security Vulnerability (Priority):**
1. Dependabot creates immediate PR
2. Label: `security` added automatically
3. Workflow runs security-audit job
4. Team notified for urgent review
5. Fast-track merge after validation

#### Manual Execution

**Trigger Workflow Manually:**
```bash
# Via GitHub CLI
gh workflow run dependency-updates.yml

# Via GitHub web interface
Actions → Dependency Updates Check → Run workflow
```

**Check Dependabot Status:**
```bash
# View alerts
gh api /repos/SilverAssist/silver-assist-security/dependabot/alerts

# View security vulnerabilities
https://github.com/SilverAssist/silver-assist-security/security/dependabot
```

#### 🚨 CRITICAL: GitHub CLI Pager Management

**MANDATORY: Always disable pager for `gh` commands to prevent terminal blocking**

When using GitHub CLI (`gh`) commands, the output is sent to a pager by default (like `less`), which blocks the terminal and requires manual interaction to exit. This is problematic for automation and quick checks.

**✅ CORRECT - Use PAGER=cat prefix:**
```bash
# Disable pager with PAGER=cat environment variable
PAGER=cat gh run list --limit 3
PAGER=cat gh pr view 1
PAGER=cat gh run view 18422501653
PAGER=cat gh pr checks 1
PAGER=cat gh workflow list
```

**✅ CORRECT - Pipe to cat:**
```bash
# Alternative: pipe output to cat
gh run list --limit 3 | cat
gh pr view 1 | cat
gh run view 18422501653 | cat
```

**❌ INCORRECT - Without pager management:**
```bash
# These will block terminal waiting for user input
gh run list --limit 3          # ❌ Blocks terminal
gh pr view 1                   # ❌ Blocks terminal
gh run view 18422501653        # ❌ Blocks terminal
```

**Why This Matters:**
- Terminal remains blocked waiting for pager exit (q key)
- Breaks automation and scripting workflows
- Prevents rapid command execution
- Causes workflow interruptions

**Rule: ALL `gh` commands MUST use `PAGER=cat` prefix or `| cat` suffix**

#### Local Validation

**Before Pushing Dependency Changes:**
```bash
# Check outdated packages locally
composer outdated --direct
npm outdated

# Run security audits locally
composer audit
npm audit

# Validate everything works
composer install
npm ci
npm run build
composer phpcs
composer phpstan
```

#### Troubleshooting

**PR Not Auto-Merging:**
- Verify: Settings → Actions → General
- Enable: "Read and write permissions"
- Enable: "Allow GitHub Actions to create and approve pull requests"

**Checks Failing:**
- Run locally: `composer phpcs && composer phpstan`
- Fix issues before pushing
- Temporarily disable auto-merge if codebase has problems

**Dependabot Not Creating PRs:**
- Verify `.github/dependabot.yml` syntax
- Check: Settings → Security → Dependabot (must be enabled)
- Verify repository permissions

#### Best Practices

**DO:**
- ✅ Trust auto-merge for minor/patch updates
- ✅ Review major updates carefully
- ✅ Check Dependabot PRs weekly
- ✅ Keep critical packages up-to-date
- ✅ Monitor security alerts daily

**DON'T:**
- ❌ Manually update dependencies without checking Dependabot first
- ❌ Ignore major version PRs for long periods
- ❌ Disable Dependabot without understanding implications
- ❌ Skip reviewing security vulnerability PRs
- ❌ Bypass quality checks in workflow

### Production Dependencies & Version Management

#### wp-github-updater Composer Package

**🚨 CRITICAL: Before creating any new release version, ALWAYS verify that the `silverassist/wp-github-updater` package is updated to the latest available version.**

##### **Package Overview**
- **Repository**: `silverassist/wp-github-updater`
- **Purpose**: Provides automatic GitHub-based update functionality for WordPress plugins
- **Location**: `vendor/silverassist/wp-github-updater/`
- **Integration**: Used by `src/Core/Updater.php` for automatic plugin updates

##### **Pre-Release Validation Checklist**
```bash
# 1. Check current package version
composer show silverassist/wp-github-updater

# 2. Update to latest version
composer update silverassist/wp-github-updater

# 3. Verify package integrity
composer validate

# 4. Test update functionality
# Navigate to WordPress Admin > Updates to verify plugin update detection works
```

##### **Version Validation Commands**
```bash
# Check for available updates
composer outdated silverassist/wp-github-updater

# Update specific package
composer require silverassist/wp-github-updater:^1.0

# Verify update was successful
composer info silverassist/wp-github-updater
```

##### **Integration Requirements**
- **Core Dependency**: The `Updater.php` class depends on this package for GitHub API integration
- **Update Notifications**: Package handles WordPress admin update notifications
- **Version Comparison**: Manages semantic version comparison for update detection
- **Security**: Provides secure download and installation of plugin updates

##### **Troubleshooting Package Issues**
- **Update Failures**: Check GitHub API rate limits and repository access
- **Version Conflicts**: Ensure compatibility with WordPress and PHP versions
- **Autoloader Issues**: Run `composer dump-autoload` after package updates
- **Missing Package**: Reinstall with `composer install --no-dev` for production

##### **Release Workflow Integration**
1. **Pre-Release**: Update `silverassist/wp-github-updater` to latest version
2. **Testing**: Verify update detection works in WordPress admin
3. **Version Bump**: Update plugin version in main file and package
4. **Release**: Create GitHub release with proper tagging
5. **Validation**: Test automatic update process from previous version

## Troubleshooting Guide

### Common Issues
- **GraphQL Not Working**: Check WPGraphQL plugin activation
- **Login Issues**: Verify IP not blocked, check session timeouts
- **Performance Issues**: Review rate limiting settings and query limits
- **Admin Access**: Ensure proper WordPress capabilities
- **Translation Loading Warning (WordPress 6.7+)**: Use proper `init` hook timing and multi-location translation loading system (see Translation Support section for complete implementation)

### Debug Information
- **Error Logging**: Use WordPress debug logging for troubleshooting
- **Security Events**: Log security-related events for audit trails
- **Performance Monitoring**: Track plugin impact on site performance
- **Configuration Validation**: Verify all settings are within valid ranges

## Future Development

### Planned Features
- **Advanced Rate Limiting**: More sophisticated rate limiting algorithms
- **Security Reports**: Weekly/monthly security summary emails
- **Multi-site Support**: WordPress multisite network compatibility
- **Advanced GraphQL**: Additional GraphQL security features
- **Integration APIs**: REST API for external security monitoring

### Security Enhancements
- **Machine Learning**: Adaptive brute force detection
- **Geolocation**: Country-based access controls
- **Two-Factor Authentication**: Integration with 2FA plugins
- **Security Scanning**: Basic vulnerability scanning capabilities
- **Threat Intelligence**: Integration with security threat feeds

### Core Structure
- **Main Plugin File**: `silver-assist-security.php` - Contains PSR-4 autoloader and bootstrap class with WordPress hooks
- **Bootstrap Class**: `SilverAssistSecurityBootstrap` - Singleton pattern handling plugin lifecycle (activation, deactivation, uninstall)
- **Core Controller**: `src/Core/Plugin.php` - Singleton pattern orchestrating all components
- **Security Helper**: `src/Core/SecurityHelper.php` - Centralized utility functions for all security operations
- **Components**: Organized by domain (`Admin/`, `Security/`, `GraphQL/`)
- **Namespace**: `SilverAssist\Security\{ComponentType}\{ClassName}`

### Component Initialization Pattern
```php
// In main plugin file - Bootstrap class with lifecycle management
class SilverAssistSecurityBootstrap {
    private function init_hooks(): void {
        register_activation_hook(__FILE__, [$this, "activate"]);
        register_deactivation_hook(__FILE__, [$this, "deactivate"]);
        register_uninstall_hook(__FILE__, [__CLASS__, "uninstall"]);
        add_action("plugins_loaded", [$this, "init_plugin"]);
    }
}

// In Plugin.php - conditional initialization based on context
private function init_admin_panel(): void {
    if (is_admin()) {
        $this->admin_panel = new AdminPanel();
    }
}

private function init_graphql_security(): void {
    // Only initialize if WPGraphQL is active
    if (class_exists('WPGraphQL')) {
        $this->graphql_security = new GraphQLSecurity();
    }
}
```

## Configuration Management

### WordPress Options Pattern
All settings use prefixed WordPress options with consistent naming:
- `silver_assist_login_attempts` - Login security settings
- `silver_assist_graphql_query_depth` - GraphQL limits
- `silver_assist_session_timeout` - Session management settings

### Component Configuration Loading
```php
// In each component constructor
private function init_configuration(): void {
    $this->max_attempts = (int) get_option('silver_assist_login_attempts', 5);
    $this->lockout_duration = (int) get_option('silver_assist_lockout_duration', 900);
}
```

### GraphQL Centralized Configuration Pattern
All GraphQL configuration must use GraphQLConfigManager for centralized management:
```php
// ✅ CORRECT - Use centralized ConfigManager
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

class GraphQLSecurity {
    private GraphQLConfigManager $config_manager;
    
    public function __construct() {
        $this->config_manager = GraphQLConfigManager::getInstance();
    }
    
    private function get_rate_limit(): int {
        return $this->config_manager->get_rate_limit();
    }
}

// ✅ CORRECT - AdminPanel using ConfigManager for display
class AdminPanel {
    private function get_wpgraphql_current_settings(): array {
        return GraphQLConfigManager::getInstance()->get_all_configurations();
    }
}

// ❌ INCORRECT - Direct configuration duplication
private function init_configuration(): void {
    $this->query_depth = (int) get_option('silver_assist_graphql_query_depth', 8);
    $this->is_wpgraphql_active = class_exists('WPGraphQL');
    // This duplicates logic that should be centralized
}
```

### GraphQLConfigManager Pattern Requirements
When working with GraphQL configurations, always follow these patterns:

#### **Single Source of Truth**
- All GraphQL configuration MUST go through GraphQLConfigManager
- Never duplicate WPGraphQL detection logic
- Use centralized caching for performance

#### **Singleton Access Pattern**
```php
// Always use getInstance() method
$config_manager = GraphQLConfigManager::getInstance();
$rate_limit = $config_manager->get_rate_limit();
$is_headless = $config_manager->is_headless_mode();
```

#### **Configuration Retrieval Methods**
```php
// Centralized methods available in GraphQLConfigManager
get_query_depth(): int              // Get configured query depth limit
get_query_complexity(): int         // Get configured complexity limit
get_query_timeout(): int            // Get configured timeout seconds
get_rate_limit(): int               // Get intelligent rate limit
is_wpgraphql_active(): bool         // Check WPGraphQL plugin status
is_headless_mode(): bool            // Check if in headless CMS mode
get_wpgraphql_settings(): array     // Get WPGraphQL native settings
evaluate_security_level(): string   // Get security evaluation
get_configuration_html(): string    // Get formatted HTML display
get_all_configurations(): array     // Get complete configuration array
```

## Security Implementation Patterns

### Hook Registration Pattern
Each security component registers WordPress hooks in its `init()` method:
```php
// LoginSecurity.php example
private function init(): void {
    add_action('wp_login_failed', [$this, 'handle_failed_login']);
    add_filter('authenticate', [$this, 'check_login_lockout'], 30, 3);
    add_action('wp_login', [$this, 'handle_successful_login'], 10, 2);
}
```

### GraphQL Security Validation
GraphQL security uses centralized configuration management and custom validation:
- **Centralized Configuration**: All settings managed through GraphQLConfigManager
- **Query Validation**: Depth/complexity validation via `add_custom_validation_rules()`
- **Pre-execution Filtering**: Request validation via `graphql_request_data` filter
- **Intelligent Rate Limiting**: Adaptive limits based on WPGraphQL configuration
- **Native Integration**: Seamless integration with WPGraphQL native settings

### Rate Limiting Implementation
Uses centralized configuration with WordPress transients for IP-based rate limiting:
```php
// ✅ CORRECT - Using centralized rate limit configuration
$rate_limit = $this->config_manager->get_rate_limit();
$key = "graphql_rate_limit_{md5($ip)}";
$requests = get_transient($key) ?: 0;

if ($requests >= $rate_limit) {
    return new WP_Error('rate_limit_exceeded', 'Rate limit exceeded');
}

set_transient($key, $requests + 1, 60); // 1 minute window

// ❌ INCORRECT - Hardcoded rate limits
$key = 'graphql_rate_limit_' . $ip;
$requests = get_transient($key) ?: 0;
set_transient($key, $requests + 1, 60); // Missing intelligent configuration
```

### GraphQL Configuration Caching Pattern
GraphQLConfigManager implements intelligent caching for performance:
```php
// Automatic caching in ConfigManager
private function get_cached_config(string $key, callable $generator): mixed {
    $cache_key = "graphql_config_{$key}";
    $cached = get_transient($cache_key);
    
    if ($cached === false) {
        $value = $generator();
        set_transient($cache_key, $value, 300); // 5 minutes cache
        return $value;
    }
    
    return $cached;
}
```

## Admin Panel Patterns

### Settings Registration
Use WordPress Settings API with grouped settings:
```php
// Group settings by component
register_setting('silver_assist_security_login', 'silver_assist_login_attempts');
register_setting('silver_assist_security_graphql', 'silver_assist_graphql_query_depth');
```

### Form Handling
Admin forms process data with validation and immediate option updates:
- Numeric ranges with `min`/`max` validation
- Checkbox handling: `isset($_POST['field']) ? 1 : 0`
- Success/error message display via `add_settings_error()`

## 🚨 CRITICAL CODING STANDARDS - MANDATORY COMPLIANCE

### SecurityHelper Centralization - MANDATORY USAGE

**🚨 CRITICAL: ALL utility functions MUST be centralized in SecurityHelper.php to prevent code duplication and ensure consistency.**

#### **Mandatory SecurityHelper Usage Rules**
- **NEVER duplicate SecurityHelper logic** in other classes
- **ALWAYS use SecurityHelper functions** instead of implementing similar logic
- **PREFER SecurityHelper expansion** over creating new utility classes
- **MAINTAIN backwards compatibility** when updating helper functions
- **DOCUMENT breaking changes** clearly in helper function updates

#### **SecurityHelper Function Categories (ALL MANDATORY)**
1. **Asset Management**: `get_asset_url()` with SCRIPT_DEBUG-aware minification
2. **Network Security**: `get_client_ip()`, `is_bot_request()`, `send_404_response()`
3. **Authentication**: `is_strong_password()`, `verify_nonce()`, `check_user_capability()`
4. **Data Management**: `generate_ip_transient_key()`, `sanitize_admin_path()`
5. **Logging & Monitoring**: `log_security_event()`, `format_time_duration()`
6. **AJAX Utilities**: `validate_ajax_request()` with comprehensive security checks

#### **Integration Pattern - MANDATORY**
```php
// ✅ CORRECT - Use SecurityHelper for all utility functions
use SilverAssist\Security\Core\SecurityHelper;

class YourSecurityClass {
    private function load_assets(): void {
        $css_url = SecurityHelper::get_asset_url("assets/css/component.css");
        wp_enqueue_style("component-style", $css_url, [], "1.0.0");
    }
    
    public function ajax_handler(): void {
        if (!SecurityHelper::validate_ajax_request("your_nonce_action")) {
            wp_send_json_error(["error" => "Security validation failed"]);
            return;
        }
    }
}

// ❌ INCORRECT - Don't duplicate helper logic
class BadSecurityClass {
    private function get_asset_url($path): string {
        // Don't duplicate this logic - use SecurityHelper::get_asset_url()
    }
}
```

### Documentation Requirements
- **PHP**: Complete PHPDoc documentation for ALL classes, methods, and properties
- **JavaScript**: Complete JSDoc documentation for ALL functions (in English)
- **@since tags**: Required for all public APIs
- **English only**: All documentation must be in English for international collaboration

### WordPress i18n Standards
- **Text domain**: `"silver-assist-security"` - MANDATORY for all i18n functions
- **ALL user-facing strings**: Must use WordPress i18n functions with double quotes
- **Functions**: `__("text", "silver-assist-security")`, `esc_html_e("text", "silver-assist-security")`, etc.
- **JavaScript i18n**: Pass translated strings from PHP via `wp_localize_script()`
- **Forbidden**: Hardcoded user-facing strings without translation functions

#### sprintf() Placeholder Standards
- **Simple placeholders**: Use `%d`, `%s`, `%f` for sequential arguments: `sprintf(__("Found %d items", "domain"), $count)`
- **Positional placeholders**: Use `%1\$d`, `%2\$s` with escaped `$` for non-sequential: `__("Value %1\$d exceeds limit %2\$d", "domain")`
- **Translator comments**: ALWAYS add comments for placeholders: `/* translators: %d: number of items found */`
- **Multiple placeholders**: Use positional numbering for clarity: `%1\$d` for first, `%2\$s` for second, etc.
- **Escaping requirement**: In double-quoted strings, escape `$` in placeholders to prevent variable interpretation

## Modern PHP 8+ Conventions

### Type Declarations
- **Strict typing**: All methods use parameter and return type declarations
- **Nullable types**: Use `?Type` for optional returns (e.g., `?AdminPanel`)
- **Property types**: All class properties have explicit types

### PHP Coding Standards
- **String interpolation**: MANDATORY - Use double-quoted strings with interpolation `"prefix_{$variable}"` or `"text {$array['key']}"` instead of concatenation `'text ' . $variable`. Only use concatenation for multi-line readability or when mixing single/double quotes is necessary.
- **Short array syntax**: `[]` not `array()`
- **Namespaces**: Use descriptive namespaces like `SilverAssist\Security\ComponentType`
- **Singleton pattern**: `Class_Name::getInstance()` method pattern
- **WordPress hooks**: `add_action("init", [$this, "method"])` with array callbacks
- **PHP 8+ Features**: Match expressions, array spread operator, typed properties
- **Match over Switch**: Use `match` expressions instead of `switch` statements when possible for cleaner, more concise code
- **Global function calls**: Use `\` prefix **ONLY for WordPress functions** in namespaced context (e.g., `\add_action()`, `\get_option()`, `\is_ssl()`). PHP native functions like `array_key_exists()`, `explode()`, `trim()`, `sprintf()` do NOT need the `\` prefix.
- **WordPress Function Rule**: ALL WordPress core functions, WordPress API functions, and plugin functions MUST use the `\` prefix when called from within namespaced classes
- **PHP Native Function Rule**: PHP built-in functions (string, array, math, etc.) should NOT use the `\` prefix as they are automatically resolved
- **WordPress i18n**: All user-facing strings MUST use WordPress i18n functions (`__()`, `esc_html__()`, `esc_attr__()`, `_e()`, `esc_html_e()`) with text domain `"silver-assist-security"`

### PHP `use` Statement Standards - MANDATORY COMPLIANCE

#### **Import Organization & Ordering**
- **MANDATORY**: All `use` statements MUST be placed at the top of the file, immediately after the namespace declaration
- **Alphabetical Ordering**: ALWAYS sort `use` statements alphabetically for consistent organization
- **No In-Method Imports**: NEVER use fully qualified class names within methods - use `use` statements instead
- **Same Namespace Rule**: NEVER import classes that are in the same namespace as the current file

#### **Use Statement Examples**

**✅ CORRECT - Alphabetical ordering and proper imports:**
```php
<?php
namespace SilverAssist\Security\GraphQL;

use GraphQL\Error\Error;
use GraphQL\Error\UserError;
use GraphQL\Executor\ExecutionResult;
// Note: GraphQLConfigManager is NOT imported - same namespace

class GraphQLSecurity
{
    private GraphQLConfigManager $config_manager; // ✅ Same namespace - direct usage
    
    public function throwError(): void
    {
        throw new UserError("Error message"); // ✅ Clean usage via import
    }
}
```

**❌ INCORRECT - Wrong ordering and unnecessary imports:**
```php
<?php
namespace SilverAssist\Security\GraphQL;

use SilverAssist\Security\GraphQL\GraphQLConfigManager; // ❌ Same namespace - unnecessary
use GraphQL\Executor\ExecutionResult;
use GraphQL\Error\UserError;
use GraphQL\Error\Error; // ❌ Wrong alphabetical order

class GraphQLSecurity
{
    public function throwError(): void
    {
        throw new \GraphQL\Error\UserError("Error"); // ❌ Should use import instead
    }
}
```

#### **Namespace Rules & Guidelines**

**Same Namespace - NO Import Needed:**
```php
namespace SilverAssist\Security\Core;

// ✅ CORRECT - No use statement needed for DefaultConfig (same namespace)
class Plugin
{
    public function getConfig(): array
    {
        return DefaultConfig::get_defaults(); // Direct usage
    }
}
```

**Different Namespace - Import Required:**
```php
namespace SilverAssist\Security\Admin;

use SilverAssist\Security\Core\DefaultConfig; // ✅ Required - different namespace

class AdminPanel
{
    public function getConfig(): array
    {
        return DefaultConfig::get_option("setting_name");
    }
}
```

**External Libraries - Always Import:**
```php
namespace SilverAssist\Security\GraphQL;

use GraphQL\Error\Error;           // ✅ External library
use GraphQL\Error\UserError;       // ✅ External library  
use GraphQL\Executor\ExecutionResult; // ✅ External library

class GraphQLSecurity
{
    public function createError(): Error
    {
        return new Error("Message"); // ✅ Clean usage
    }
}
```

#### **Alphabetical Sorting Rules**
1. **Case-insensitive sorting**: `Error` comes before `ExecutionResult` before `UserError`
2. **Namespace depth sorting**: Shorter namespaces first, then by alphabetical order
3. **Group by vendor**: Internal classes first, then external libraries (optional but recommended)

**✅ CORRECT Alphabetical Order:**
```php
use GraphQL\Error\Error;
use GraphQL\Error\UserError;
use GraphQL\Executor\ExecutionResult;
use SilverAssist\Security\Core\DefaultConfig;
```

**❌ INCORRECT Order:**
```php
use GraphQL\Executor\ExecutionResult;
use SilverAssist\Security\Core\DefaultConfig;
use GraphQL\Error\UserError;
use GraphQL\Error\Error;
```

#### **Code Quality Benefits**
- **Cleaner Code**: No repetitive long namespaces in method bodies
- **Better Readability**: Clear dependency declarations at the top
- **Easier Maintenance**: Change namespace in one place instead of throughout the file
- **IDE Support**: Better autocomplete and refactoring support
- **Consistency**: Standardized approach across all project files

### JavaScript Coding Standards
- **Modern ES6+ Syntax**: MANDATORY use of ES6+ features for all new JavaScript code
- **Arrow functions**: Use `const functionName = () => {}` instead of `function functionName() {}`
- **Template literals**: Use backticks and `${variable}` interpolation instead of string concatenation
- **const/let declarations**: Use `const` for constants and `let` for variables, avoid `var`
- **Destructuring**: Use object/array destructuring where appropriate for cleaner code and better readability
- **JSDoc documentation**: ALL functions must have complete JSDoc documentation in English
- **WordPress i18n**: Use WordPress i18n in JavaScript via localized script data passed from PHP
- **jQuery dependency**: Use jQuery patterns for WordPress compatibility with ES6 arrow functions
- **Consistent naming**: Use camelCase for variables and functions
- **jQuery element variables**: MANDATORY use of `$` prefix for all jQuery element variables (e.g., `const $passwordField = $("#field")`)
- **Timeout variables**: Use descriptive names for timeout variables (e.g., `validationTimeout`, `hideTimeout`, `saveTimeout`)
- **Timing constants**: MANDATORY centralized timing constants in TIMING object at file top for all setTimeout/setInterval values
- **Validation constants**: MANDATORY centralized validation limits in VALIDATION_LIMITS object for form validation ranges
- **Error handling**: Use try-catch blocks for AJAX calls and complex operations
- **Module pattern**: Use IIFE with arrow functions: `(($ => { /* code */ }))(jQuery);`

#### ES6+ JavaScript Examples
```javascript
// ✅ CORRECT: ES6 arrow functions with const, jQuery $ prefix, and centralized constants
(($ => {
    'use strict';

    // Centralized timing constants at file top
    const TIMING = {
        VALIDATION_DEBOUNCE: 300,     // Input validation debounce (ms)
        HIDE_ON_INACTIVITY: 8000,    // Hide message after inactivity (ms)
        HIDE_ON_BLUR: 5000,          // Hide message on field blur (ms)
        FADE_OUT_DURATION: 400,      // Animation duration (ms)
        AUTO_SAVE_DELAY: 2000        // Auto-save delay (ms)
    };

    // Centralized validation limits for form validation
    const VALIDATION_LIMITS = {
        LOGIN_ATTEMPTS: { min: 1, max: 20 },
        LOCKOUT_DURATION: { min: 60, max: 3600 },
        SESSION_TIMEOUT: { min: 5, max: 120 },
        GRAPHQL_QUERY_DEPTH: { min: 1, max: 20 },
        GRAPHQL_QUERY_COMPLEXITY: { min: 10, max: 1000 },
        ADMIN_PATH_LENGTH: { min: 3, max: 50 }
    };

    const initFormValidation = () => {
        // Use destructuring for cleaner object access
        const { strings = {}, phpExecutionTimeout = 30 } = silverAssistSecurity || {};
        const errors = [];
        const $form = $("form");
        const $passwordField = $("#pass1");
        let validationTimeout;
        
        $form.on("submit", e => {
            let isValid = true;
            
            // Use centralized validation limits instead of hardcoded values
            const loginAttempts = $("#login_attempts").val();
            if (loginAttempts < VALIDATION_LIMITS.LOGIN_ATTEMPTS.min || 
                loginAttempts > VALIDATION_LIMITS.LOGIN_ATTEMPTS.max) {
                errors.push(`Login attempts must be between ${VALIDATION_LIMITS.LOGIN_ATTEMPTS.min} and ${VALIDATION_LIMITS.LOGIN_ATTEMPTS.max}`);
                isValid = false;
            }
            
            // Template literals for string interpolation
            const errorHtml = `<div class="notice notice-error">${errorMessage}</div>`;
            
            // Clear timeout variables properly
            clearTimeout(validationTimeout);
            
            // Arrow functions in callbacks
            errors.forEach(error => {
                console.log(`Error: ${error}`);
            });
        });
        
        // Timeout variable usage with descriptive naming and timing constants
        $passwordField.on("input", function() {
            clearTimeout(this.validationTimeout);
            
            this.validationTimeout = setTimeout(() => {
                validatePassword($passwordField.val());
                
                // Use timing constants instead of hardcoded values
                this.hideTimeout = setTimeout(() => {
                    hideValidationMessage();
                }, TIMING.HIDE_ON_INACTIVITY);
            }, TIMING.VALIDATION_DEBOUNCE);
        });
    };

    // ✅ CORRECT: Modern AJAX with destructuring, arrow functions and jQuery prefixes
    const autoSaveSettings = () => {
        const $form = $("form");
        const $saveIndicator = $(".saving-indicator");
        const formData = $form.serialize();
        let saveTimeout;
        
        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};
        
        // Use timing constants for consistent delays
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => {
            $.ajax({
                url: ajaxurl,
                type: "POST",
                data: {
                    action: "silver_assist_auto_save",
                    nonce: nonce,
                    form_data: formData
                },
                success: response => {
                    // Use destructuring for response handling
                    const { success, data = {} } = response || {};
                    
                    if (success) {
                        $saveIndicator.html(strings.saved || "Saved!")
                            .delay(TIMING.AUTO_SAVE_DELAY)
                            .fadeOut(TIMING.FADE_OUT_DURATION);
                    } else {
                        $saveIndicator.html(data.message || strings.saveFailed).addClass("error");
                    }
                },
                error: () => {
                    $saveIndicator.html(strings.saveFailed || "Save failed").addClass("error");
                }
            });
        }, TIMING.AUTO_SAVE_DELAY);
    };

    // ✅ CORRECT: Object destructuring for password validation
    const showValidationMessage = $container => {
        // Use destructuring for cleaner object access
        const { passwordSuccess } = window.silverAssistSecurity || {};
        const successMessage = passwordSuccess || "Default message";
        
        $container.html(`✓ ${successMessage}`).show();
    };

}))(jQuery);

// ❌ INCORRECT: Old function syntax, missing jQuery prefixes, hardcoded timing, no destructuring
function initFormValidation() {
    var errors = [];
    var form = $("form"); // Missing $ prefix
    var passwordField = $("#pass1"); // Missing $ prefix
    
    form.on("submit", function(e) {
        var isValid = true;
        var timeout; // Non-descriptive timeout variable name
        
        // String concatenation instead of template literals
        var errorHtml = "<div class=\"notice\">" + errorMessage + "</div>";
        
        // Hardcoded timing values instead of constants
        timeout = setTimeout(function() {
            validatePassword(passwordField.val());
        }, 300); // ❌ Hardcoded value
        
        // Auto-hide with hardcoded timing
        setTimeout(function() {
            hideMessage();
        }, 5000); // ❌ Hardcoded value
        
        // Old function syntax in callbacks, no destructuring
        errors.forEach(function(error) {
            console.log("Error: " + error);
        });
        
        // No destructuring for object access
        var message = silverAssistSecurity.strings.errorMessage;
        var ajaxUrl = silverAssistSecurity.ajaxurl;
    });
}
```

### Documentation Standards
- **Complete PHPDoc**: Every class, method, and property documented in English
- **@since tags**: Version tracking for all public APIs
- **@package**: Consistent namespace documentation
- **JSDoc for JavaScript**: ALL JavaScript functions must have complete JSDoc documentation in English

#### PHPDoc Example
```php
/**
 * Handle failed login attempts and apply security measures
 *
 * @since 1.1.1
 * @param string $username The username that failed login
 * @param WP_Error $error The login error object
 * @return void
 */
public function handle_failed_login(string $username, WP_Error $error): void
{
    // Implementation
}
```

#### JSDoc Example
```javascript
/**
 * Initialize form validation for security settings
 * 
 * Validates all form inputs including login attempts, session timeout,
 * and GraphQL settings.
 * 
 * @since 1.1.1
 * @returns {void}
 */
function initFormValidation() {
    // Implementation
}
```

### Error Handling
```php
try {
    Plugin::getInstance();
} catch (Exception $e) {
    error_log("Silver Assist Security Essentials initialization failed: " . $e->getMessage());
    \add_action("admin_notices", function() use ($e) {
        echo "<div class=\"notice notice-error\"><p>";
        echo "<strong>Silver Assist Security Essentials Error:</strong> " . esc_html($e->getMessage());
        echo "</p></div>";
    });
}
```

### Function Prefix Usage Examples - MANDATORY COMPLIANCE

**🚨 CRITICAL RULE: Use `\` prefix for ALL WordPress functions in namespaced context, but NOT for PHP native functions**

```php
// ✅ CORRECT - WordPress functions REQUIRE \ prefix in namespaced context
\add_action("init", [$this, "method"]);
\add_filter("graphql_request_data", [$this, "validate"]);
\get_option("option_name", "default");
\update_option("option_name", $value);
\is_ssl();
\current_user_can("administrator");
\wp_remote_get($url);
\current_time("mysql");
\get_transient($key);
\set_transient($key, $value, $expiration);
\class_exists("WPGraphQL");
\function_exists("get_graphql_setting");
\defined("WP_DEBUG");

// ✅ CORRECT - WordPress i18n functions REQUIRE \ prefix
\__("Text to translate", "silver-assist-security");
\esc_html__("Text to translate", "silver-assist-security");
\esc_html_e("Text to translate", "silver-assist-security");

// ✅ CORRECT - PHP native functions do NOT need \ prefix
array_key_exists($key, $array);
explode(",", $string);
trim($value);
sprintf("Hello %s", $name);
strlen($string);
substr($string, 0, 100);
preg_match("/pattern/", $string);
json_encode($data);
md5($string);
microtime(true);
header("Content-Type: application/json");
ini_get("max_execution_time");
set_time_limit(30);

// ✅ CORRECT - String interpolation examples
$transient_key = "login_attempts_{md5($ip)}";
$lockout_key = "lockout_{md5($ip)}";
$option_name = "_transient_timeout_{$lockout_key}";

// ❌ INCORRECT - Don't use \ with PHP native functions
\array_key_exists($key, $array);
\explode(",", $string);
\trim($value);
\sprintf("Hello %s", $name);
\strlen($string);
\json_encode($data);

// ❌ INCORRECT - Missing \ prefix for WordPress functions
add_action("init", [$this, "method"]);
get_option("option_name", "default");
__("Text", "domain");

// ❌ INCORRECT - Avoid concatenation when interpolation is cleaner
$transient_key = "login_attempts_" . md5($ip);
$option_name = "_transient_timeout_" . $lockout_key;
```

#### **WordPress Functions Categories (ALL need `\` prefix):**
- **Hooks & Filters**: `\add_action()`, `\add_filter()`, `\remove_action()`, `\remove_filter()`
- **Options API**: `\get_option()`, `\update_option()`, `\delete_option()`
- **Transients**: `\get_transient()`, `\set_transient()`, `\delete_transient()`
- **User Functions**: `\current_user_can()`, `\wp_get_current_user()`, `\is_user_logged_in()`
- **HTTP API**: `\wp_remote_get()`, `\wp_remote_post()`, `\wp_remote_request()`
- **Utilities**: `\is_ssl()`, `\current_time()`, `\wp_parse_url()`, `\wp_json_encode()`
- **Core Checks**: `\class_exists()`, `\function_exists()`, `\defined()`
- **Internationalization**: `\__()`, `\_e()`, `\esc_html__()`, `\esc_attr__()`

#### **PHP Native Functions Categories (NO `\` prefix needed):**
- **String Functions**: `strlen()`, `substr()`, `trim()`, `explode()`, `implode()`
- **Array Functions**: `array_key_exists()`, `array_merge()`, `array_filter()`, `count()`
- **Regular Expressions**: `preg_match()`, `preg_replace()`, `preg_match_all()`
- **Data Functions**: `json_encode()`, `json_decode()`, `serialize()`, `unserialize()`
- **Math Functions**: `max()`, `min()`, `ceil()`, `floor()`, `round()`
- **Hash Functions**: `md5()`, `sha1()`, `hash()`
- **Time Functions**: `microtime()`, `time()`, `date()`
- **System Functions**: `ini_get()`, `set_time_limit()`, `header()`, `error_log()`

### String Interpolation Standards - MANDATORY

**🚨 CRITICAL: Always prefer double-quoted string interpolation over concatenation for cleaner, more readable code**

#### **Correct String Interpolation Patterns**

```php
// ✅ CORRECT - Simple variable interpolation
$message = "Hello {$username}!";
$path = "/var/www/{$site}/public";
$key = "user_{$user_id}_session";

// ✅ CORRECT - Array key interpolation with curly braces
$value = "Setting: {$config['database']['host']}";
$name = "User: {$user['name']}";
$status = "Status: {$_SERVER['REQUEST_METHOD']}";

// ✅ CORRECT - Object property interpolation
$output = "Name: {$user->name}, Email: {$user->email}";
$log = "Class: {$object->getClass()}, Method: {$object->getMethod()}";

// ✅ CORRECT - Complex expressions with curly braces
$transient = "cache_{md5($ip)}_{$timestamp}";
$option = "setting_{strtolower($type)}_{$id}";
$key = "lock_{$user_id}_{time()}";

// ✅ CORRECT - Multi-variable interpolation
$message = "User {$username} from {$country} logged in at {$timestamp}";
$path = "{$base_dir}/{$category}/{$filename}.{$extension}";
$log = "[{$date}] {$level}: {$message} (IP: {$ip})";

// ✅ CORRECT - Concatenation for multi-line readability
$long_message = "This is a very long message that spans " .
                "multiple lines for better readability " .
                "and code organization.";
```

#### **Incorrect Concatenation Patterns**

```php
// ❌ INCORRECT - Unnecessary concatenation with variables
$message = "Hello " . $username . "!";
$path = "/var/www/" . $site . "/public";
$key = "user_" . $user_id . "_session";

// ❌ INCORRECT - Concatenation instead of interpolation
$value = "Setting: " . $config['database']['host'];
$name = "User: " . $user['name'];
$status = "Status: " . $_SERVER['REQUEST_METHOD'];

// ❌ INCORRECT - Mixed concatenation and interpolation
$message = "Hello " . $username . " from {$country}";
$path = $base_dir . "/" . $category . "/{$filename}";

// ❌ INCORRECT - Concatenating literal strings
$full_string = "Hello " . "World";  // Should be: "Hello World"
$path = "path/" . "to/" . "file";   // Should be: "path/to/file"
```

#### **When Concatenation is Acceptable**

```php
// ✅ ACCEPTABLE - Multi-line for readability
$sql = "SELECT * FROM users " .
       "WHERE status = 'active' " .
       "AND created_at > NOW() - INTERVAL 30 DAY " .
       "ORDER BY created_at DESC";

// ✅ ACCEPTABLE - Mixing single and double quotes
$html = '<div class="container">' .
        "Welcome {$username}!" .
        '</div>';

// ✅ ACCEPTABLE - Building complex strings incrementally
$query = "SELECT id, name";
if ($include_email) {
    $query .= ", email";
}
if ($include_phone) {
    $query .= ", phone";
}
$query .= " FROM users";
```

#### **Benefits of String Interpolation**

1. **Readability**: Cleaner, more natural syntax
2. **Maintainability**: Easier to understand variable placement
3. **Performance**: Slightly faster than concatenation in most cases
4. **Modern PHP**: Aligns with PSR-12 and modern PHP best practices
5. **Less Error-Prone**: Reduces risk of spacing/quote errors

#### **PHPCS Rule Enforcement**

The plugin enforces this via `Generic.Strings.UnnecessaryStringConcat`:
- Detects unnecessary concatenation of literal strings
- Flags code like `'Hello ' . 'World'` → should be `'Hello World'`
- Encourages interpolation over concatenation with variables

### Match vs Switch Statement Guidelines
Use PHP 8+ `match` expressions instead of `switch` statements when possible for cleaner, more concise code:

```php
// ✅ CORRECT - Use match for simple value returns
return match ($limit_type) {
    "depth" => $config["query_depth_limit"],
    "complexity" => $config["query_complexity_limit"],
    "timeout" => $config["query_timeout"],
    "aliases" => $is_headless ? 50 : 20,
    "directives" => $is_headless ? 30 : 15,
    "field_duplicates" => $is_headless ? 20 : 10,
    default => 0
};

// ✅ CORRECT - Use match for assignment
$status = match ($error_level) {
    0 => "success",
    1, 2 => "warning", // Multiple values
    3, 4, 5 => "error",
    default => "unknown"
};

// ❌ INCORRECT - Verbose switch statement for simple returns
switch ($limit_type) {
    case "depth":
        return $config["query_depth_limit"];
    case "complexity":
        return $config["query_complexity_limit"];
    case "timeout":
        return $config["query_timeout"];
    case "aliases":
        return $is_headless ? 50 : 20;
    case "directives":
        return $is_headless ? 30 : 15;
    case "field_duplicates":
        return $is_headless ? 20 : 10;
    default:
        return 0;
}

// ✅ CORRECT - Use switch for complex logic blocks
switch ($action_type) {
    case "validate_login":
        $this->check_rate_limits($ip);
        $this->log_attempt($username, $ip);
        $this->apply_security_headers();
        break;
    case "block_request":
        $this->log_security_event($ip, "blocked");
        $this->send_404_response();
        break;
    default:
        $this->handle_unknown_action($action_type);
}
```

**When to use `match`:**
- Simple value returns based on conditions
- Direct assignment of values
- No complex logic needed in cases
- All cases return/assign similar data types
- Prefer strict equality comparison (===)

**When to use `switch`:**
- Complex logic blocks in each case
- Multiple statements per case
- Need for fall-through behavior
- Side effects or procedure calls
- Breaking out of loops within cases

## Development Workflow

### TDD Development Cycle (ALWAYS FOLLOW THIS)

**🚨 MANDATORY: Every new feature must follow the TDD cycle:**

```bash
# 1. RED - Write test first (it MUST fail)
cat > tests/Security/NewFeatureTest.php << 'EOF'
class NewFeatureTest extends WP_UnitTestCase {
    public function test_new_feature_works(): void {
        $feature = new NewFeature();
        $this->assertTrue($feature->is_secure());
    }
}
EOF
vendor/bin/phpunit tests/Security/NewFeatureTest.php
# ❌ MUST FAIL - Class doesn't exist yet

# 2. GREEN - Write minimal code to pass test
cat > src/Security/NewFeature.php << 'EOF'
class NewFeature {
    public function is_secure(): bool {
        return true; // Minimal implementation
    }
}
EOF
vendor/bin/phpunit tests/Security/NewFeatureTest.php
# ✅ MUST PASS - Test now passes

# 3. REFACTOR - Improve code quality
# Add proper implementation, security checks, logging
# Run tests after each change to ensure nothing breaks

# 4. COMMIT - Tests + implementation together
git add tests/Security/NewFeatureTest.php src/Security/NewFeature.php
git commit -m "✨ Add NewFeature with TDD validation"
```

### Composer Scripts
```bash
composer test          # Run PHPUnit tests
composer phpcs          # WordPress Coding Standards check
composer phpstan        # Static analysis (level 8)
composer check          # Run all quality checks
```

### GitHub CLI (gh) for CI/CD Monitoring

**Prerequisites**: Ensure `gh` CLI is installed locally for GitHub Actions monitoring

**Common Monitoring Commands**:
```bash
# Quick check of recent runs (most commonly used)
gh run list --limit 3

# View last 5 workflow runs
gh run list --limit 5

# Get quick status of latest run
gh run list --limit 1 --json databaseId,status,conclusion --jq '.[0]'

# View specific run details
gh run view <run-id>

# Monitor run in real-time
gh run watch <run-id> --interval 20

# View detailed job logs (avoid interactive pager)
PAGER=cat gh run view --log --job=<job-id>
```

**Pager Management**:
- Use `PAGER=cat` prefix to avoid interactive pager for long outputs
- Example: `PAGER=cat gh run list --limit 3` - Avoid pager for run lists
- Example: `PAGER=cat gh run view --log --job=12345` - View logs without pager
- Long CI logs may require pager navigation or output redirection
- For quick monitoring, `gh run list --limit 3` is the most efficient command

**CI/CD Debugging Workflow**:
1. Make changes and push via GitHub Desktop (for workflow files) or git CLI (for code)
2. Monitor with `gh run list --limit 3` to get latest run ID
3. Watch progress with `gh run watch <run-id> --interval 20`
4. Debug issues with `PAGER=cat gh run view --log --job=<job-id>`
5. For quick status checks, use `gh run list --limit 3` repeatedly

**Example Monitoring Session**:
```bash
# Quick check of recent runs
gh run list --limit 3

# Get run ID and status
gh run list --limit 1 --json databaseId,status,conclusion --jq '.[0]'

# Watch the latest run in real-time
gh run watch 18385735131 --interval 20

# Get detailed logs without pager
PAGER=cat gh run view --log --job=52383549624

# View failed jobs only
gh run view 18385735131 --log-failed
```

### Asset Minification System
**🚨 CRITICAL: PostCSS + Grunt system replaced grunt-contrib-cssmin for modern CSS support**

#### **Build Commands**
```bash
npm run build          # Complete build process (CSS + JS minification)
npm run minify         # Minify assets without cleaning
npm run minify:css     # CSS only with PostCSS + cssnano
npm run minify:js      # JavaScript only with Grunt + uglify
npm run clean          # Remove all minified files
```

#### **Script Execution**
```bash
./scripts/minify-assets-npm.sh    # Full minification with detailed logging
./scripts/minify-assets-npm.sh --help    # Show available options
```

#### **System Architecture**
- **CSS Minification**: PostCSS + cssnano (supports @layer, nesting, container queries)
- **JavaScript Minification**: Grunt + uglify (reliable ES5 compatibility)
- **Modern CSS Preservation**: All 46 CSS classes preserved correctly
- **Compression Rates**: 37-50% CSS reduction, 69-79% JavaScript reduction
- **Dependencies**: postcss, cssnano, postcss-cli, grunt, grunt-contrib-uglify

#### **Required Files**
- `postcss.config.js` - PostCSS configuration with cssnano
- `Gruntfile.js` - Grunt configuration for JavaScript minification
- `package.json` - npm dependencies and build scripts

### Plugin Constants
Use these predefined constants:
- `SILVER_ASSIST_SECURITY_VERSION` - Plugin version
- `SILVER_ASSIST_SECURITY_PATH` - Plugin directory path
- `SILVER_ASSIST_SECURITY_URL` - Plugin URL
- `SILVER_ASSIST_SECURITY_BASENAME` - Plugin basename for hooks

### Translation Support
- **Text domain**: `"silver-assist-security"` - MANDATORY for all i18n functions
- **WP-CLI Required**: All translation operations require WP-CLI installation (see WP-CLI Integration section below)
- **Load translations**: In `Plugin::load_textdomain()` method
- **PHP i18n functions**: All user-facing strings wrapped in WordPress i18n functions:
  - `__("String", "silver-assist-security")` - Translate and return
  - `_e("String", "silver-assist-security")` - Translate and echo
  - `esc_html__("String", "silver-assist-security")` - Translate, escape HTML, return
  - `esc_html_e("String", "silver-assist-security")` - Translate, escape HTML, echo
  - `esc_attr__("String", "silver-assist-security")` - Translate, escape attributes, return
  - `esc_attr_e("String", "silver-assist-security")` - Translate, escape attributes, echo
- **JavaScript i18n**: Pass translated strings from PHP to JavaScript via `wp_localize_script()`
- **Complete Workflow**: See "WP-CLI Integration & Translation Management" section for detailed translation procedures

#### WordPress 6.7+ Translation Loading Requirements

**🚨 CRITICAL: WordPress 6.7+ requires proper textdomain loading timing to avoid "translation loading too early" warnings.**

The plugin implements a robust multi-location translation loading system to ensure compatibility:

##### **Implementation Pattern**
```php
/**
 * Load plugin textdomain for translations - WordPress 6.7+ compatible
 *
 * @since 1.1.1
 * @return void
 */
public function load_textdomain(): void
{
    // Default languages directory for silver-assist-security
    $lang_dir = SILVER_ASSIST_SECURITY_PATH . "/languages/";

    /**
     * Filters the languages directory path for Silver Assist Security
     *
     * @param string $lang_dir The languages directory path
     * @since 1.1.1
     */
    $lang_dir = \apply_filters("silver_assist_security_languages_directory", $lang_dir);

    // Get user locale (WordPress 6.5+ always has get_user_locale)
    $get_locale = \get_user_locale();

    /**
     * Language locale filter for Silver Assist Security
     *
     * @param string $get_locale The locale to use with get_user_locale()
     * @param string $domain     The text domain
     * @since 1.1.1
     */
    $locale = \apply_filters("plugin_locale", $get_locale, "silver-assist-security");
    $mofile = sprintf("%1\$s-%2\$s.mo", "silver-assist-security", $locale);

    // Setup paths to current locale file
    $mofile_local = $lang_dir . $mofile;
    $mofile_global = WP_LANG_DIR . "/silver-assist-security/" . $mofile;

    if (file_exists($mofile_global)) {
        // Look in global /wp-content/languages/silver-assist-security/ folder first
        \load_textdomain("silver-assist-security", $mofile_global);
    } elseif (file_exists($mofile_local)) {
        // Look in local /wp-content/plugins/silver-assist-security/languages/ folder
        \load_textdomain("silver-assist-security", $mofile_local);
    } else {
        // Load the default language files as fallback
        \load_plugin_textdomain("silver-assist-security", false, dirname(plugin_basename(SILVER_ASSIST_SECURITY_PATH . "/silver-assist-security.php")) . "/languages/");
    }
}
```

##### **Key Features:**
- **Multi-location Search**: Checks global WordPress languages directory first, then plugin directory, then fallback
- **User Locale Support**: Uses `get_user_locale()` for better user experience
- **Filter Integration**: Provides customizable filters for directory path and locale detection
- **Proper Timing**: Loaded via `init` hook to comply with WordPress 6.7+ timing requirements
- **Fallback System**: Three-tier fallback ensures translations always load even if preferred location fails

##### **Hook Registration:**
```php
// In Plugin constructor - proper timing for WordPress 6.7+
\add_action("init", [$this, "load_textdomain"]);
```

##### **Translation Directory Structure:**
```
/wp-content/languages/silver-assist-security/  ← Global (checked first)
└── silver-assist-security-es_ES.mo

/wp-content/plugins/silver-assist-security/languages/  ← Local (fallback)
├── silver-assist-security.pot
├── silver-assist-security-es_ES.po
└── silver-assist-security-es_ES.mo
```

**Resolves WordPress 6.7+ Issues:**
- ✅ Eliminates "translation loading too early" warnings
- ✅ Provides proper multi-location fallback system
- ✅ Ensures compatibility with WordPress automatic translation updates
- ✅ Maintains compatibility with WordPress 6.5+ requirements

#### PHP i18n Examples
```php
// ✅ CORRECT - Using proper i18n functions
echo "<h1>" . esc_html__("Security Settings", "silver-assist-security") . "</h1>";
esc_html_e("Login attempts exceeded", "silver-assist-security");
$message = __("Settings saved successfully", "silver-assist-security");

// ✅ CORRECT - sprintf() with escaped placeholders and translator comments
throw new \GraphQL\Error\UserError(
    sprintf(
        /* translators: 1: current complexity, 2: maximum allowed complexity */
        \__("Query complexity %1\$d exceeds maximum %2\$d", "silver-assist-security"),
        $current_complexity,
        $max_complexity
    )
);

// ✅ CORRECT - Simple placeholder without positional numbering
$message = sprintf(
    /* translators: %d: number of failed attempts */
    \__("Too many failed attempts: %d", "silver-assist-security"),
    $attempts
);

// ❌ INCORRECT - Hardcoded strings
echo "<h1>Security Settings</h1>";
echo "Login attempts exceeded";
$message = "Settings saved successfully";

// ❌ INCORRECT - Unescaped placeholders causing variable interpretation
\__("Query complexity %1$d exceeds maximum %2$d", "silver-assist-security"); // PHP sees $d as variable
```

#### JavaScript i18n Examples
```php
// In PHP - Pass translations to JavaScript
wp_localize_script("silver-assist-security-admin", "silverAssistSecurity", [
    "strings" => [
        "loading" => __("Loading...", "silver-assist-security"),
        "error" => __("An error occurred", "silver-assist-security"),
        "success" => __("Settings saved", "silver-assist-security"),
        "confirmDelete" => __("Are you sure you want to delete this?", "silver-assist-security")
    ]
]);
```

```javascript
// In JavaScript - Use localized strings
console.log(silverAssistSecurity.strings.loading);
alert(silverAssistSecurity.strings.confirmDelete);
$("#status").text(silverAssistSecurity.strings.success);
```

### WP-CLI Integration & Translation Management

**🚨 CRITICAL: WP-CLI is REQUIRED for all translation operations. Always verify installation before working with i18n files.**

#### **WP-CLI Installation**

**Check if WP-CLI is installed:**
```bash
wp --version
```

**Install WP-CLI on macOS (Recommended):**
```bash
# Using Homebrew (preferred method)
brew install wp-cli

# Verify installation
wp --version
```

**Alternative Installation Methods:**
```bash
# Direct download (if Homebrew not available)
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp

# Verify installation
wp --version
```

#### **Translation File Generation & Management**

**MANDATORY: Always use WP-CLI for translation operations - never edit .pot files manually.**

##### **Step 1: Generate .pot Template File**
```bash
# Generate/regenerate .pot file with all translatable strings
wp i18n make-pot . languages/silver-assist-security.pot --domain=silver-assist-security --exclude=vendor,node_modules,tests

# This scans all PHP files for WordPress i18n functions and creates template
```

##### **Step 2: Update Existing Translation Files**
```bash
# Update existing .po files with new strings from .pot
wp i18n update-po languages/silver-assist-security.pot languages/silver-assist-security-es_ES.po

# This merges new strings while preserving existing translations
```

##### **Step 3: Compile Binary Translation Files**
```bash
# Compile .po to .mo binary format for WordPress
wp i18n make-mo languages/silver-assist-security-es_ES.po

# Creates .mo file that WordPress uses for translations
```

#### **Complete Translation Workflow**

**For Major Updates (new features, version updates):**
```bash
# 1. Regenerate .pot file with all new strings
wp i18n make-pot . languages/silver-assist-security.pot --domain=silver-assist-security --exclude=vendor,node_modules,tests

# 2. Update all existing language files
wp i18n update-po languages/silver-assist-security.pot languages/silver-assist-security-es_ES.po

# 3. Manually translate new strings in .po files (msgid -> msgstr)
# Edit languages/silver-assist-security-es_ES.po:
# msgid "New English String"
# msgstr "Nueva Cadena en Español"

# 4. Update .po file headers for new version
# Project-Id-Version: Silver Assist Security Essentials X.X.X
# POT-Creation-Date: YYYY-MM-DD HH:MM-TIMEZONE
# PO-Revision-Date: YYYY-MM-DD HH:MM+TIMEZONE

# 5. Compile updated .po files to .mo
wp i18n make-mo languages/silver-assist-security-es_ES.po

# 6. Verify compilation success
ls -la languages/*.mo
```

#### **Translation File Structure**
```
languages/
├── silver-assist-security.pot         # Template file (English source)
├── silver-assist-security-es_ES.po    # Spanish translation source
├── silver-assist-security-es_ES.mo    # Spanish compiled binary
├── silver-assist-security-fr_FR.po    # French translation source (future)
└── silver-assist-security-fr_FR.mo    # French compiled binary (future)
```

#### **Translation Standards & Guidelines**

**File Naming Convention:**
- Template: `{textdomain}.pot`
- Translation source: `{textdomain}-{locale}.po` 
- Compiled binary: `{textdomain}-{locale}.mo`
- Locale format: `{language}_{country}` (e.g., `es_ES`, `fr_FR`, `de_DE`)

**Spanish Translation Guidelines:**
```po
# ✅ CORRECT Spanish translations
msgid "Security Settings"
msgstr "Configuración de Seguridad"

msgid "Login Protection"
msgstr "Protección de Login"

msgid "GraphQL Security"
msgstr "Seguridad GraphQL"

msgid "Introspection"
msgstr "Introspección"

msgid "Public"
msgstr "Público"

msgid "Restricted"
msgstr "Restringido"

msgid "Headless CMS"
msgstr "CMS sin Cabeza"
```

**Version Management in Translation Files:**
```po
# Always update header information for new versions
msgid ""
msgstr ""
"Project-Id-Version: Silver Assist Security Essentials 1.1.0\n"
"POT-Creation-Date: 2025-08-06 10:30-0500\n"
"PO-Revision-Date: 2025-08-06 10:35+0000\n"
"Last-Translator: Silver Assist Security Team\n"
"Language: es_ES\n"
```

#### **Translation Quality Assurance**

**Before Committing Translation Updates:**
1. **Verify .pot generation**: Check that all new i18n strings are captured
2. **Review .po updates**: Ensure new msgid entries have corresponding msgstr translations
3. **Test .mo compilation**: Verify binary files compile without errors
4. **Version consistency**: Update Project-Id-Version in .po files
5. **Character encoding**: Ensure UTF-8 encoding throughout all files

**Common WP-CLI Translation Warnings:**
```bash
# These warnings indicate missing translator comments for placeholders
Warning: The string "New version %s available." contains placeholders but has no "translators:" comment

# Add translator comments in PHP source:
/* translators: %s: version number */
__("New version %s available.", "silver-assist-security");
```

#### **Integration with Development Workflow**

**After Adding New i18n Strings:**
```bash
# 1. Update .pot file
wp i18n make-pot . languages/silver-assist-security.pot --domain=silver-assist-security --exclude=vendor,node_modules,tests

# 2. Update translation files
wp i18n update-po languages/silver-assist-security.pot languages/silver-assist-security-es_ES.po

# 3. Translate new strings manually
# 4. Compile translations
wp i18n make-mo languages/silver-assist-security-es_ES.po

# 5. Commit all changes
git add languages/
git commit -m "🌍 Update translations for v1.1.0 with new GraphQL terminology"
```

**Version Release Checklist - Translations:**
- [ ] Regenerated .pot file with `wp i18n make-pot`
- [ ] Updated all .po files with `wp i18n update-po`
- [ ] Manually translated all new msgid strings
- [ ] Updated Project-Id-Version in .po file headers
- [ ] Compiled all .po files to .mo with `wp i18n make-mo`
- [ ] Verified .mo files exist and have recent timestamps
- [ ] Tested translations in WordPress admin interface

## Commit Message Standards

**🌍 IMPORTANT: All commit messages must be written in English for international collaboration and consistency.**

Follow these emoji conventions for clear and consistent commit history:

### Commit Types with Emojis

#### **🐛 Bug Fixes**
```bash
# For fixing bugs, errors, or issues
git commit -m "🐛 Fix GraphQL rate limiting false positives"
git commit -m "🐛 Resolve update notification display bug"
git commit -m "🐛 Fix login attempt counter reset issue"
```

#### **✨ New Features**
```bash
# For adding new features or functionality
git commit -m "✨ Add automatic GitHub update system"
git commit -m "✨ Implement admin settings page for updates"
git commit -m "✨ Add real-time AJAX update checking"
```

#### **🔧 Fixes & Improvements**
```bash
# For general fixes, improvements, or maintenance
git commit -m "🔧 Improve error handling in update system"
git commit -m "🔧 Optimize script loading performance"
git commit -m "🔧 Update documentation with new features"
```

### Additional Commit Types
- **📚 Documentation**: `📚 Update README with v1.0.1 features`
- **🎨 Style/Format**: `🎨 Improve code formatting and structure`
- **♻️ Refactor**: `♻️ Refactor update system for better modularity`
- **⚡ Performance**: `⚡ Optimize GraphQL validation with smart caching`
- **🔒 Security**: `🔒 Enhance input validation and sanitization`
- **🚀 Release**: `🚀 Release v1.0.1 with automatic update system`

### Commit Message Format
```bash
<emoji> <type>: <description>

# Examples:
🐛 Fix GraphQL query depth validation
✨ Add security logging for failed logins
🔧 Improve admin interface styling
📚 Update installation documentation
🚀 Release v1.0.1 with GitHub integration
```

### Best Practices
- **English Language**: All commit messages MUST be written in English
- **Clear descriptions**: Explain what was changed and why
- **Present tense**: "Add feature" not "Added feature"
- **Concise but descriptive**: Keep under 50 characters when possible
- **Reference issues**: Include issue numbers when applicable
- **Consistent emoji usage**: Follow the established pattern

## Composer Integration

### Package Configuration
The plugin includes a comprehensive `composer.json` configuration for development tools and PSR-4 autoloading:

#### Key Features
- **PHP 8.3+ Requirement**: Matches plugin requirements
- **PSR-4 Autoloading**: Modern namespace organization with proper class loading
- **WordPress Coding Standards**: Automated PHPCS integration
- **Development Tools**: PHPUnit, PHPCS, PHPCBF integration
- **WordPress Plugin Type**: Proper Composer installer configuration

#### Available Scripts
```bash
# Install dependencies
composer install

# Run WordPress Coding Standards check
composer run phpcs

# Auto-fix coding standards issues
composer run phpcbf

# Run PHP syntax validation
composer run lint

# Run unit tests (when implemented)
composer run test
```

#### PSR-4 Autoloading Structure
```php
"autoload": {
  "psr-4": {
    "SilverAssist\\Security\\": "src/"
  }
}
```

#### Development Dependencies
- **PHPCS & WPCS**: WordPress coding standards enforcement (v3.1+ & v3.0+)
- **PHPUnit**: Unit testing framework ready for future tests (v9.6+)
- **Composer Installers**: WordPress plugin installation support

#### Package Exclusions
Composer files are automatically excluded from distribution packages:
- `composer.json` and `composer.lock` excluded from ZIP releases
- `vendor/` directory excluded from all packages
- Development tools not included in WordPress plugin distribution

#### Quality Assurance Integration
- **Single PHP Version**: Automated testing with PHP 8.3
- **WordPress Compatibility**: Testing with WordPress 6.5-latest
- **Security Validation**: Automated vulnerability scanning
- **Standards Enforcement**: Automated PHPCS validation in CI/CD

## Key Integration Points

### WordPress Hooks Priority
- Authentication filters: Priority 30 (after WordPress core)
- GraphQL hooks: Use WPGraphQL's hook system
- Admin hooks: Standard priority (10)

### External Dependencies
- **WPGraphQL**: Conditional loading - check `class_exists('WPGraphQL')`
- **WordPress Core**: Minimum version 6.5, PHP 8.3+

### Database Operations
- No custom tables - uses WordPress options and transients
- Cleanup handled in uninstall hook with direct database queries for transients

## Security Logging Pattern
Structured JSON logging for security events:
```php
error_log(sprintf(
    'SECURITY_ALERT: %s - {"timestamp":"%s","ip":"%s","user_agent":"%s"}',
    $message,
    current_time('mysql'),
    $this->get_client_ip(),
    $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
));
```

## Asset Management

### CSS Architecture & Design System

The plugin implements a comprehensive CSS variables system for consistent styling across all components.

#### CSS Variables System (`assets/css/variables.css`)

**🎨 MANDATORY: All CSS styling MUST use CSS custom properties instead of hardcoded values for maintainability and consistency.**

##### **Color Palette Variables**
```css
/* Primary Colors */
--silver-primary-blue: #0073aa;
--silver-primary-blue-hover: #005a87;
--silver-primary-blue-light: #f0f6fc;

/* Status Colors - Success/Error/Warning */
--silver-success-primary: #46b450;
--silver-success-bg: #d4edda;
--silver-success-border: #c3e6cb;
--silver-success-text: #155724;

--silver-error-primary: #dc3232;
--silver-error-bg: #f8d7da;
--silver-error-border: #f5c6cb;
--silver-error-text: #721c24;

--silver-warning-primary: #ffb900;
--silver-warning-bg: #fff3cd;
--silver-warning-text: #856404;

/* Text & Background Colors */
--silver-text-primary: #1d2327;
--silver-text-secondary: #50575e;
--silver-bg-primary: #ffffff;
--silver-bg-secondary: #f0f0f1;
--silver-border-primary: #c3c4c7;
```

##### **Typography Variables**
```css
/* Font Families */
--silver-font-family-primary: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
--silver-font-family-mono: Consolas, Monaco, "Courier New", monospace;

/* Typography Scale */
--silver-font-size-xs: 0.75rem;    /* 12px */
--silver-font-size-sm: 0.8125rem;  /* 13px */
--silver-font-size-base: 1rem;     /* 16px */
--silver-font-size-lg: 1.125rem;   /* 18px */
--silver-font-size-xl: 1.25rem;    /* 20px */

/* Font Weights */
--silver-font-weight-normal: 400;
--silver-font-weight-medium: 500;
--silver-font-weight-semibold: 600;
--silver-font-weight-bold: 700;

/* Letter Spacing & Line Height */
--silver-letter-spacing-tight: 0.3px;
--silver-letter-spacing-normal: 0.5px;
--silver-line-height-base: 1.4;
--silver-line-height-relaxed: 1.6;
```

##### **Spacing & Layout Variables**
```css
/* Spacing Scale */
--silver-spacing-xs: 4px;
--silver-spacing-sm: 8px;
--silver-spacing-md: 12px;
--silver-spacing-lg: 15px;
--silver-spacing-xl: 20px;
--silver-spacing-xxl: 25px;

/* Border Width */
--silver-border-width-thin: 1px;
--silver-border-width-base: 2px;
--silver-border-width-thick: 4px;
--silver-border-width-thicker: 6px;

/* Border Radius */
--silver-radius-sm: 3px;
--silver-radius-base: 4px;
--silver-radius-md: 6px;
--silver-radius-lg: 8px;
--silver-radius-pill: 20px;

/* Shadows */
--silver-shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.1);
--silver-shadow-base: 0 2px 4px rgba(0, 0, 0, 0.05);
--silver-shadow-md: 0 2px 8px rgba(0, 0, 0, 0.08);
--silver-shadow-lg: 0 4px 12px rgba(0, 0, 0, 0.12);
```

##### **Component-Specific Variables**
```css
/* Toggle Switch Components */
--silver-toggle-width: 50px;
--silver-toggle-height: 24px;
--silver-toggle-thumb-size: 18px;

/* Form Elements */
--silver-input-width-sm: 100px;
--silver-input-width-md: 200px;
--silver-input-width-lg: 280px;

/* GraphQL/Headless Mode Colors */
--silver-headless-bg: #e1f5fe;
--silver-headless-text: #01579b;
--silver-standard-bg: #f3e5f5;
--silver-standard-text: #4a148c;

/* Transitions */
--silver-transition-fast: 0.2s;
--silver-transition-base: 0.3s;
--silver-transition-ease: ease;
```

##### **Responsive Breakpoints**
```css
--silver-breakpoint-sm: 480px;
--silver-breakpoint-md: 768px;
--silver-breakpoint-lg: 1200px;
```

#### CSS Development Standards

**✅ CORRECT Usage Pattern:**
```css
/* Use CSS variables for all styling */
.security-card {
    background-color: var(--silver-bg-primary);
    border: var(--silver-border-width-thin) solid var(--silver-border-primary);
    border-radius: var(--silver-radius-md);
    padding: var(--silver-spacing-lg);
    font-size: var(--silver-font-size-base);
    color: var(--silver-text-primary);
    box-shadow: var(--silver-shadow-sm);
    transition: all var(--silver-transition-base) var(--silver-transition-ease);
}

.success-notice {
    background-color: var(--silver-success-bg);
    border-left: var(--silver-border-width-thick) solid var(--silver-success-border);
    color: var(--silver-success-text);
    padding: var(--silver-spacing-md) var(--silver-spacing-lg);
}

.validation-message {
    border: var(--silver-border-width-base) solid var(--silver-primary-blue);
    outline: var(--silver-border-width-base) solid var(--silver-primary-blue);
}
```

**❌ INCORRECT - Never use hardcoded values:**
```css
.security-card {
    background-color: #ffffff;        /* Use var(--silver-bg-primary) */
    border: 1px solid #c3c4c7;      /* Use var(--silver-border-width-thin) solid var(--silver-border-primary) */
    border-radius: 6px;              /* Use var(--silver-radius-md) */
    padding: 15px;                   /* Use var(--silver-spacing-lg) */
    font-size: 14px;                 /* Use var(--silver-font-size-sm) */
    color: #1d2327;                  /* Use var(--silver-text-primary) */
}

.validation-message {
    border-left: 4px solid #0073aa;  /* Use var(--silver-border-width-thick) solid var(--silver-primary-blue) */
    outline: 2px solid #0073aa;      /* Use var(--silver-border-width-base) solid var(--silver-primary-blue) */
}
```

#### Variable Categories & Usage Guidelines

**🎨 Color Variables:**
- **Status Colors**: Use `--silver-success-*`, `--silver-error-*`, `--silver-warning-*` for all status indicators
- **Text Colors**: Use `--silver-text-*` for all text elements
- **Background Colors**: Use `--silver-bg-*` for all background elements
- **Border Colors**: Use `--silver-border-*` for all border elements

**📐 Spacing Variables:**
- **Padding/Margin**: Use `--silver-spacing-*` scale (xs to xxxl)
- **Border Width**: Use `--silver-border-width-*` for all border thickness (thin/base/thick/thicker)
- **Border Radius**: Use `--silver-radius-*` for all rounded corners
- **Shadows**: Use `--silver-shadow-*` for consistent depth

**🔤 Typography Variables:**
- **Font Sizes**: Use `--silver-font-size-*` scale (xs to 3xl)
- **Font Weights**: Use `--silver-font-weight-*` for consistent weights
- **Line Heights**: Use `--silver-line-height-*` for text spacing

**⚡ Animation Variables:**
- **Transitions**: Use `--silver-transition-*` for consistent timing
- **Durations**: Use predefined fast/base/slow durations

#### Development Workflow Integration

**CSS File Loading Order:**
1. `variables.css` - Load first to define all custom properties
2. `admin.css` - Main admin styles using variables
3. `password-validation.css` - Feature-specific styles using variables

**Build Process:**
- All CSS files automatically enqueued with cache-busting version numbers
- Variables are globally available through `:root` selector
- Responsive breakpoints defined as CSS variables for consistency

### Modern CSS Examples for Future Development

The plugin implements cutting-edge CSS techniques for maintainable and international-friendly styling. Here are practical examples for future developers:

#### **CSS Nesting with Container Queries**
```css
/* Modern security card with nested selectors and container-based responsiveness */
.modern-security-card {
    background: var(--silver-bg-primary);
    border: var(--silver-border-width-thin) solid var(--silver-border-primary);
    border-radius: var(--silver-radius-lg);
    padding: var(--silver-fluid-spacing);
    container-type: inline-size;
    
    /* Nested selectors for better organization */
    h3 {
        font-size: var(--silver-font-size-fluid-lg);
        margin-block-end: var(--silver-spacing-md);
        
        /* Container queries within nested elements */
        @container (max-width: 300px) {
            font-size: var(--silver-font-size-base);
        }
    }
    
    .status-badge {
        padding-inline: var(--silver-space-inline);
        padding-block: var(--silver-space-block);
        border-radius: var(--silver-radius-base);
        
        &.success {
            background: var(--silver-success-bg-light);
            color: var(--silver-success-text);
        }
        
        &.error {
            background: var(--silver-error-bg-light);
            color: var(--silver-error-text);
        }
    }
    
    /* Responsive layout based on container, not viewport */
    @container (min-width: 400px) {
        display: grid;
        grid-template-columns: 1fr auto;
        gap: var(--silver-spacing-lg);
        align-items: center;
    }
}
```

#### **Logical Properties for International Support**
```css
/* RTL/LTR friendly form styling */
.rtl-friendly-form {
    .form-field {
        margin-block-end: var(--silver-spacing-lg);
        
        label {
            display: block;
            margin-block-end: var(--silver-spacing-sm);
            font-weight: var(--silver-font-weight-semibold);
        }
        
        input {
            inline-size: 100%;
            padding-inline: var(--silver-spacing-md);
            padding-block: var(--silver-spacing-sm);
            border: var(--silver-border-width-thin) solid var(--silver-border-secondary);
            border-radius: var(--silver-radius-base);
            
            &:focus {
                border-inline-start: var(--silver-border-width-thick) solid var(--silver-primary-blue);
                outline: var(--silver-border-width-base) solid var(--silver-primary-blue);
                outline-offset: 1px;
            }
        }
    }
}
```

#### **Fluid Typography with clamp()**
```css
/* Responsive typography that scales smoothly */
.fluid-typography-example {
    h1 { font-size: var(--silver-font-size-fluid-xl); }
    h2 { font-size: var(--silver-font-size-fluid-lg); }
    p { font-size: var(--silver-font-size-fluid-base); }
    
    .responsive-container {
        padding: var(--silver-fluid-spacing);
        gap: var(--silver-responsive-gap);
    }
}
```

#### **Utility Classes Pattern**
```css
/* Reusable utility classes with logical properties */
.utility-demo {
    /* Flow utility for consistent vertical spacing */
    .content-section {
        & > * + * {
            margin-block-start: var(--silver-spacing-xl);
        }
    }
    
    /* Cluster utility for flexible layouts */
    .action-buttons {
        display: flex;
        flex-wrap: wrap;
        gap: var(--silver-spacing-md);
        justify-content: flex-end;
        align-items: center;
    }
    
    /* Surface utility for consistent card styling */
    .info-card {
        background: var(--silver-bg-secondary);
        border: var(--silver-border-width-thin) solid var(--silver-border-primary);
        border-radius: var(--silver-radius-md);
        padding: var(--silver-spacing-xl);
    }
    
    /* Logical property utilities for RTL support */
    .highlighted-section {
        border-inline-start: var(--silver-border-width-thick) solid var(--silver-primary-blue);
        padding-inline: var(--silver-space-inline-lg);
        margin-block-end: var(--silver-spacing-xl);
    }
}
```

#### **Advanced Container Query Layouts**
```css
/* Container-based responsive layouts */
@container (min-width: 600px) {
    .advanced-layout {
        display: grid;
        grid-template-columns: 2fr 1fr;
        gap: var(--silver-spacing-xl);
        
        .sidebar {
            padding-inline-start: var(--silver-spacing-lg);
            border-inline-start: var(--silver-border-width-thin) solid var(--silver-border-light);
        }
    }
}

@container (max-width: 599px) {
    .advanced-layout {
        .sidebar {
            margin-block-start: var(--silver-spacing-lg);
            padding-block-start: var(--silver-spacing-lg);
            border-block-start: var(--silver-border-width-thin) solid var(--silver-border-light);
        }
    }
}
```

#### **Modern CSS Benefits Implemented**
- **Container Queries**: Components respond to their container, not the viewport
- **Logical Properties**: Automatic RTL/LTR support without separate stylesheets
- **CSS Nesting**: Better code organization and maintainability
- **Fluid Design**: Typography and spacing that adapts smoothly across devices
- **CSS Layers**: Better control over cascade and specificity
- **Utility Classes**: Reusable components for consistent design

### Asset Loading & Performance

- **Admin CSS/JS**: Enqueued only on plugin admin pages
- **Version**: Using plugin version constant for cache busting
- **Dependencies**: jQuery for admin JavaScript functionality
- **CSS Variables**: Centralized design system for consistent styling
- **Minification System**: PostCSS + cssnano for CSS, Grunt + uglify for JavaScript
- **Modern CSS Support**: @layer directives, CSS nesting, container queries preserved
- **Build Commands**: `npm run build` for complete minification, individual scripts available
- **Compression**: 37-50% CSS reduction, 69-79% JavaScript reduction
