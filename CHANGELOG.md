# Changelog

All notable changes to Silver Assist Security Essentials will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
