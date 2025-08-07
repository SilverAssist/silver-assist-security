# Silver Assist Security Essentials - AI Coding Instructions

## Architecture Overview

This is a **WordPress security plugin** that resolves critical security vulnerabilities found in WordPress security audits. It uses **PSR-4 autoloading** with modern PHP 8+ patterns and follows a **modular component architecture** with strict separation of concerns.

### Security Vulnerabilities Addressed

The plugin specifically addresses three critical security issues commonly found in WordPress security assessments:

1. **WordPress Admin Login Page Exposure**: Implements comprehensive brute force protection with IP-based login attempt limiting, session timeout management, user enumeration protection, strong password enforcement, advanced bot/crawler blocking with 404 responses to automated reconnaissance tools, and security scanner blocking.

2. **HTTPOnly Cookie Flag Missing**: Automatically implements HTTPOnly flags for all WordPress cookies, secure cookies for HTTPS sites, SameSite protection against CSRF attacks, and enhanced session cookie security.

3. **GraphQL Security Misconfigurations**: Provides complete GraphQL security including introspection blocking in production, query depth and complexity limits, query timeout protection, rate limiting, alias abuse protection, field duplication blocking, and directive limitation.

## Core Technologies

- **PHP 8.0+**: Modern PHP with strict typing, union types, and match expressions
- **WordPress 6.5+**: Latest WordPress APIs and hooks
- **PSR-4 Autoloading**: Namespace-based class loading for better organization
- **Real-time Dashboard**: Live security monitoring with AJAX updates
- **Multi-language Support**: Complete i18n implementation (English/Spanish)
- **WP-CLI**: Required for translation file generation and management (install via `brew install wp-cli`)

## Project Structure

```
silver-assist-security/
├── src/                           # PSR-4 source code
│   ├── Admin/AdminPanel.php       # WordPress admin interface
│   ├── Core/
│   │   ├── Plugin.php            # Main plugin initialization
│   │   └── Updater.php           # Automatic GitHub updates
│   ├── Security/
│   │   ├── GeneralSecurity.php   # HTTPOnly cookies & headers
│   │   └── LoginSecurity.php     # Brute force protection & bot blocking
│   └── GraphQL/
│       ├── GraphQLConfigManager.php # Centralized GraphQL configuration
│       └── GraphQLSecurity.php   # GraphQL protection
├── assets/                        # Frontend resources
│   ├── css/admin.css             # Admin panel styling
│   └── js/admin.js               # Real-time dashboard
├── languages/                     # Internationalization
│   ├── silver-assist-security.pot # Translation template
│   ├── silver-assist-security-es_ES.po # Spanish translations
│   └── silver-assist-security-es_ES.mo # Compiled Spanish
├── tests/                         # Unit and integration tests
│   ├── Unit/                     # Unit tests
│   ├── Integration/              # Integration tests
│   ├── Security/                 # Security tests
│   └── Helpers/                  # Test helper classes
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

### 2. Core\Updater.php
**Purpose**: Automatic GitHub-based update system
**Key Responsibilities**:
- Check for updates from SilverAssist/silver-assist-security repository
- Download and install plugin updates
- Version comparison and update notifications
- Backup recommendations and update management

### 3. Admin\AdminPanel.php
**Purpose**: WordPress admin interface for security configuration
**Key Responsibilities**:
- Render Security Essentials dashboard page
- Handle AJAX requests for real-time updates
- Process security configuration form submissions
- Display security statistics and compliance status
- Use GraphQLConfigManager for centralized GraphQL configuration

### 4. Security\LoginSecurity.php
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

### 5. Security\GeneralSecurity.php
**Purpose**: HTTPOnly cookies and general WordPress hardening
**Key Responsibilities**:
- Automatic HTTPOnly flag implementation for all cookies
- Secure cookie configuration for HTTPS sites
- SameSite protection against CSRF
- Security headers (X-Frame-Options, X-XSS-Protection, CSP)
- WordPress hardening (XML-RPC blocking, version hiding)

### 6. GraphQL\GraphQLConfigManager.php
**Purpose**: Centralized GraphQL configuration management
**Key Responsibilities**:
- Single source of truth for all GraphQL configurations
- WPGraphQL plugin detection and integration
- Headless CMS mode configuration management
- Intelligent rate limiting configuration
- Security evaluation and recommendations
- HTML display generation for admin interface
- Configuration caching for performance optimization

### 7. GraphQL\GraphQLSecurity.php
**Purpose**: Comprehensive GraphQL endpoint protection
**Key Responsibilities**:
- Introspection blocking in production environments
- Query depth limits (1-20 levels, default: 8)
- Query complexity control (10-1000 points, default: 100)
- Query timeout protection (1-30 seconds, default: 5)
- Rate limiting (30 requests/minute per IP)
- Alias abuse and field duplication protection

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

### Default Security Configuration
```php
$default_options = [
    "silver_assist_login_attempts" => 5,           // Failed logins before lockout
    "silver_assist_lockout_duration" => 900,       // 15 minutes lockout
    "silver_assist_session_timeout" => 30,         // 30 minutes session
    "silver_assist_password_strength_enforcement" => 1, // Strong passwords required
    "silver_assist_bot_protection" => 1,           // Bot and crawler blocking enabled
    "silver_assist_graphql_query_depth" => 8,      // Max query depth
    "silver_assist_graphql_query_complexity" => 100, // Max complexity points
    "silver_assist_graphql_query_timeout" => 5     // 5 second timeout
];
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

## Testing & Quality Assurance

### Security Testing Requirements
- **Brute Force Testing**: Verify login attempt limiting works correctly
- **Cookie Security**: Confirm HTTPOnly flags are applied properly
- **GraphQL Protection**: Test query limits and rate limiting
- **User Enumeration**: Ensure login errors don't reveal valid usernames
- **Cross-site Scripting**: Verify XSS protection via HTTPOnly cookies

### Performance Testing
- **Page Load Impact**: Ensure minimal performance overhead
- **Memory Usage**: Monitor PHP memory consumption
- **Database Queries**: Optimize database interactions
- **AJAX Responsiveness**: Real-time dashboard should update smoothly

### Compatibility Testing
- **WordPress Versions**: Test with WordPress 6.5+
- **PHP Versions**: Ensure compatibility with PHP 8.0+
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

## Troubleshooting Guide

### Common Issues
- **GraphQL Not Working**: Check WPGraphQL plugin activation
- **Login Issues**: Verify IP not blocked, check session timeouts
- **Performance Issues**: Review rate limiting settings and query limits
- **Admin Access**: Ensure proper WordPress capabilities

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

### String Quotation Standards
- **MANDATORY**: ALL strings in PHP and JavaScript MUST use double quotes: `"string"`
- **i18n Functions**: ALL WordPress i18n functions MUST use double quotes: `__("Text", "silver-assist-security")`, `esc_html_e("Text", "silver-assist-security")`
- **FORBIDDEN**: Single quotes for strings: `'string'` or `__('text', 'domain')`
- **Exception**: Only use single quotes inside double-quoted strings when necessary
- **SQL Queries**: Use double quotes for string literals in SQL: `WHERE option_value = "1"`
- **sprintf() Placeholders**: When using `sprintf()` with positional placeholders like `%1$d`, escape the `$` to prevent PHP variable interpretation: `"Query complexity %1\$d exceeds maximum %2\$d"`

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
- **Double quotes for all strings**: `"string"` not `'string'` - MANDATORY for both PHP and JavaScript
- **String interpolation**: Use `"prefix_{$variable}"` instead of `"prefix_" . $variable` when concatenating variables into strings
- **Short array syntax**: `[]` not `array()`
- **Namespaces**: Use descriptive namespaces like `SilverAssist\Security\ComponentType`
- **Singleton pattern**: `Class_Name::getInstance()` method pattern
- **WordPress hooks**: `add_action("init", [$this, "method"])` with array callbacks
- **PHP 8+ Features**: Match expressions, array spread operator, typed properties
- **Match over Switch**: Use `match` expressions instead of `switch` statements when possible for cleaner, more concise code
- **Global function calls**: Use `\` prefix **ONLY for WordPress functions** in namespaced context (e.g., `\add_action()`, `\get_option()`, `\is_ssl()`). PHP native functions like `array_key_exists()`, `explode()`, `trim()`, `sprintf()` do NOT need the `\` prefix.
- **WordPress i18n**: All user-facing strings MUST use WordPress i18n functions (`__()`, `esc_html__()`, `esc_attr__()`, `_e()`, `esc_html_e()`) with text domain `"silver-assist-security"`

### JavaScript Coding Standards
- **Modern ES6+ Syntax**: MANDATORY use of ES6+ features for all new JavaScript code
- **Double quotes for all strings**: `"string"` not `'string'` - MANDATORY consistency with PHP
- **Arrow functions**: Use `const functionName = () => {}` instead of `function functionName() {}`
- **Template literals**: Use backticks and `${variable}` interpolation instead of string concatenation
- **const/let declarations**: Use `const` for constants and `let` for variables, avoid `var`
- **Destructuring**: Use object/array destructuring where appropriate
- **JSDoc documentation**: ALL functions must have complete JSDoc documentation in English
- **WordPress i18n**: Use WordPress i18n in JavaScript via localized script data passed from PHP
- **jQuery dependency**: Use jQuery patterns for WordPress compatibility with ES6 arrow functions
- **Consistent naming**: Use camelCase for variables and functions
- **Error handling**: Use try-catch blocks for AJAX calls and complex operations
- **Module pattern**: Use IIFE with arrow functions: `(($ => { /* code */ }))(jQuery);`

#### ES6+ JavaScript Examples
```javascript
// ✅ CORRECT: ES6 arrow functions with const
const initFormValidation = () => {
    const errors = [];
    
    $("form").on("submit", e => {
        let isValid = true;
        
        // Template literals for string interpolation
        const errorHtml = `<div class="notice notice-error">${errorMessage}</div>`;
        
        // Arrow functions in callbacks
        errors.forEach(error => {
            console.log(`Error: ${error}`);
        });
    });
};

// ✅ CORRECT: Modern AJAX with arrow functions
const autoSaveSettings = () => {
    const formData = $("form").serialize();
    
    $.ajax({
        url: silverAssistSecurity.ajaxurl,
        type: "POST",
        data: {
            action: "silver_assist_auto_save",
            nonce: silverAssistSecurity.nonce,
            form_data: formData
        },
        success: response => {
            $(".saving-indicator").html("Saved!").delay(2000).fadeOut();
        },
        error: () => {
            $(".saving-indicator").html("Save failed").addClass("error");
        }
    });
};

// ✅ CORRECT: ES6 module pattern
(($ => {
    "use strict";
    
    $(() => {
        initFormValidation();
        initAutoSave();
    });
    
}))(jQuery);

// ❌ INCORRECT: Old function syntax
function initFormValidation() {
    var errors = [];
    
    $("form").on("submit", function(e) {
        var isValid = true;
        
        // String concatenation instead of template literals
        var errorHtml = "<div class=\"notice\">" + errorMessage + "</div>";
        
        // Old function syntax in callbacks
        errors.forEach(function(error) {
            console.log("Error: " + error);
        });
    });
}

// ❌ INCORRECT: Old module pattern
(function($) {
    $(document).ready(function() {
        initFormValidation();
    });
})(jQuery);
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

### Function Prefix Usage Examples
```php
// ✅ CORRECT - WordPress functions need \ prefix in namespaced context
\add_action("init", [$this, "method"]);
\get_option("option_name", "default");
\is_ssl();
\current_user_can("administrator");

// ✅ CORRECT - PHP native functions do NOT need \ prefix
array_key_exists($key, $array);
explode(",", $string);
trim($value);
sprintf("Hello %s", $name);
defined("CONSTANT_NAME");
header("Content-Type: application/json");

// ✅ CORRECT - String interpolation examples
$transient_key = "login_attempts_{md5($ip)}";
$lockout_key = "lockout_{md5($ip)}";
$option_name = "_transient_timeout_{$lockout_key}";

// ❌ INCORRECT - Don't use \ with PHP native functions
\array_key_exists($key, $array);
\explode(",", $string);
\trim($value);

// ❌ INCORRECT - Avoid concatenation when interpolation is cleaner
$transient_key = "login_attempts_" . md5($ip);
$option_name = "_transient_timeout_" . $lockout_key;
```

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

### Composer Scripts
```bash
composer test          # Run PHPUnit tests
composer phpcs          # WordPress Coding Standards check
composer phpstan        # Static analysis (level 8)
composer check          # Run all quality checks
```

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
- **PHP 8.0+ Requirement**: Matches plugin requirements
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
- **Multi-environment Testing**: Automated testing across PHP 8.0-8.3
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
- **WordPress Core**: Minimum version 6.5, PHP 8.0+

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
- Admin CSS/JS: Enqueued only on plugin admin pages
- Version using plugin version constant for cache busting
- Dependencies: jQuery for admin JavaScript functionality
