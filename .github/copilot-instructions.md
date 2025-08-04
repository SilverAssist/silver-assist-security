# Silver Assist Security Suite - AI Coding Instructions

## Architecture Overview

This is a **WordPress security plugin** using **PSR-4 autoloading** with modern PHP 8+ patterns. The plugin follows a **modular component architecture** with strict separation of concerns.

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
- `silver_assist_password_reset_enforcement` - Password policies

### Component Configuration Loading
```php
// In each component constructor
private function init_configuration(): void {
    $this->max_attempts = (int) get_option('silver_assist_login_attempts', 5);
    $this->lockout_duration = (int) get_option('silver_assist_lockout_duration', 900);
}
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
GraphQL security uses custom validation rules and request filters:
- Query depth/complexity validation via `add_custom_validation_rules()`
- Pre-execution validation via `graphql_request_data` filter
- Rate limiting with WordPress transients

### Rate Limiting Implementation
Uses WordPress transients for IP-based rate limiting:
```php
$key = 'graphql_rate_limit_' . $ip;
$requests = get_transient($key) ?: 0;
set_transient($key, $requests + 1, 60); // 1 minute window
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

## Modern PHP 8+ Conventions

### Type Declarations
- **Strict typing**: All methods use parameter and return type declarations
- **Nullable types**: Use `?Type` for optional returns (e.g., `?AdminPanel`)
- **Property types**: All class properties have explicit types

### PHP Coding Standards
- **Double quotes for all strings**: `"string"` not `'string'`
- **String interpolation**: Use `"prefix_{$variable}"` instead of `"prefix_" . $variable` when concatenating variables into strings
- **Short array syntax**: `[]` not `array()`
- **Namespaces**: Use descriptive namespaces like `SilverAssist\Security\ComponentType`
- **Singleton pattern**: `Class_Name::getInstance()` method pattern
- **WordPress hooks**: `add_action("init", [$this, "method"])` with array callbacks
- **PHP 8+ Features**: Match expressions, array spread operator, typed properties
- **Global function calls**: Use `\` prefix **ONLY for WordPress functions** in namespaced context (e.g., `\add_action()`, `\get_option()`, `\is_ssl()`). PHP native functions like `array_key_exists()`, `explode()`, `trim()`, `sprintf()` do NOT need the `\` prefix.

### Documentation Standards
- **Complete PHPDoc**: Every class, method, and property documented
- **@since tags**: Version tracking for all public APIs
- **@package**: Consistent namespace documentation

### Error Handling
```php
try {
    Plugin::getInstance();
} catch (Exception $e) {
    error_log("Silver Assist Security Suite initialization failed: " . $e->getMessage());
    \add_action("admin_notices", function() use ($e) {
        echo "<div class=\"notice notice-error\"><p>";
        echo "<strong>Silver Assist Security Suite Error:</strong> " . esc_html($e->getMessage());
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
- Text domain: `silver-assist-security`
- Load translations in `Plugin::load_textdomain()`
- All user-facing strings wrapped in `__()` or `esc_html__()`

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
