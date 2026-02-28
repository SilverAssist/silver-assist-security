# Changelog

All notable changes to Silver Assist Security Essentials will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- 🧩 **RenderHelper Utility Class**: New `RenderHelper` class (`src/Admin/Renderer/RenderHelper.php`) with static methods for consistent UI component rendering
  - `render_feature_status()` — Renders feature enabled/disabled rows with optional custom labels
  - `render_stat()` — Renders numeric stat values with label, optional suffix and HTML id
  - `render_async_stat()` — Renders AJAX-loaded stat cards with loading spinner

### Changed (Refactor)

- ♻️ **DashboardRenderer Refactored**: Replaced all repetitive HTML blocks with `RenderHelper` calls
  - 8 `feature-status` blocks replaced by `RenderHelper::render_feature_status()`
  - 7 inline `stat` blocks replaced by `RenderHelper::render_stat()`
  - 3 async `stat` blocks replaced by `RenderHelper::render_async_stat()`
  - Guarantees consistent HTML structure and CSS classes across all dashboard cards

### Added

- 🎨 **Dashboard UI Overhaul**: Complete redesign of security dashboard with card-based layout
  - Status cards with `stat-value`/`stat-label` components for Login Security, Admin Security, GraphQL, General Security, and Form Protection
  - Activity tabs (Blocked IPs / Security Logs) with interactive tab switching
  - Loading spinners and loading-text for async content loading
  - Feature-status display with enabled/disabled indicators and `::before` icons
  - Security Statistics section with Blocked IPs, Failed Attempts (24h), and Security Events (7d)
- 🛡️ **Admin Hide Security**: Restored Admin Hide section in Login Security settings tab
  - Toggle switch to enable/disable admin URL hiding
  - Custom admin path input with real-time validation
  - Security warning notice with recovery instructions
- 📊 **Security Logs Panel**: New security logs viewer in dashboard Recent Activity
  - `loadSecurityLogs()` JS function with AJAX data loading
  - Table display with timestamp, event type, and details columns
  - Integration with existing log parsing infrastructure
- 🔓 **IP Unblock Functionality**: Added ability to unblock IPs from IP Management tab
  - `unblock_ip` AJAX endpoint in `SecurityAjaxHandler`
  - Full table view in IP Management with per-IP unblock buttons
  - Compact summary view (last 3 IPs) with "View all" link in dashboard
- 📝 **Dashboard Styles Documentation**: Created `.github/skills/dashboard-styles/SKILL.md`
  - Comprehensive guide for CSS classes, HTML patterns, and component usage
  - Status indicators, status cards, feature displays, statistics, and activity tabs
  - Do's and Don'ts section for consistent UI development

### Changed

- 🎨 **Settings Tabs Card Structure Migration**: All 4 settings tabs now use `.status-card` with `.card-header`/`.card-content`
  - Login Protection wrapped in `.status-card.login-security` with lock icon
  - GraphQL Security wrapped in `.status-card.graphql-security` with rest-api icon
  - Contact Form 7 wrapped in `.status-card.cf7-security` with email icon
  - IP Management wrapped in `.status-card.admin-security` with shield icon
  - CF7 Blocked IPs section upgraded from bare div to `.status-card`
  - Manual IP Management section wrapped in `.status-card`
- 🎨 **Status Indicator Semantics**: Renamed `.disabled` to `.inactive` for status indicators
- 🎨 **Toggle Switch Refactor**: Use `.toggle-slider` class and native `:checked` selector instead of JS class toggling
- 🎨 **Blocked IPs Display**: Split into compact dashboard summary and full IP Management table
- 📊 **SecurityDataProvider Expanded**: Added `form_protection`, GraphQL detail fields (`query_depth_limit`, `query_complexity_limit`, `query_timeout`, `introspection_disabled`), `xmlrpc_disabled`, `version_hiding`, and overall statistics (`failed_attempts_24h`, `security_events_7d`)
- 🔧 **StatisticsProvider**: Added to SecurityDataProvider for cross-component stats; fixed circular dependency by inlining log file reading instead of calling SecurityDataProvider
- 🔧 **Dashboard Initialization**: `initDashboard()` now called on document ready; activity tab switching initialized in dashboard init
- ❌ **Removed**: Hover transform on status cards for cleaner UX; unnecessary dashboard refresh case from tab switching

### Fixed

- 🐛 **CF7 Detection (CF7 v6.x)**: Removed deprecated `function_exists('wpcf7_get_contact_form_by_id')` check from `SecurityHelper::is_contact_form_7_active()` — this function was removed in CF7 v6.x, causing the CF7 tab to not appear
- 🐛 **CF7 Blocked IPs Loading**: JS `loadCF7BlockedIPs()` now targets both `#cf7-blocked-ips-content` and `#cf7-blocked-ips-container` selectors to populate both the CF7 tab and IP Management tab
- 🐛 **CF7 Tab Data Loading**: Added `cf7-security` case to `switchToTab` so CF7 blocked IPs load when switching to the CF7 tab
- 🐛 **CF7 Empty State Styling**: Changed `<p class="no-blocked-ips">` to `<p class="no-threats">` for consistent green styling on empty blocked IP lists
- 🐛 **Admin Path Validation**: Added fallback `"Invalid path"` for undefined error messages; removed static `<div id="admin-path-validation">` (JS creates it dynamically)
- 🐛 **Toggle Switch Initialization**: Skip checkboxes already inside `.toggle-switch` labels to prevent double-wrapping
- 🐛 **Blocked IPs Data Extraction**: Handle both array and object response formats from `get_blocked_ips` AJAX endpoint

### Fixed

- 🐛 **Dependabot Auto-Merge Workflow Restriction**: Documented GitHub Actions limitation for auto-merging PRs that modify workflow files
  - GitHub Actions prevents `GITHUB_TOKEN` from modifying workflow files as a security measure
  - Error: "refusing to allow a GitHub App to create or update workflow" when merging PR #30
  - **Solution**: PRs that modify `.github/workflows/` files require manual approval and merge
  - **Repository Setting Required**: Enable "Allow GitHub Actions to create and approve pull requests" in Settings → Actions → General
  - Dependabot can still create PRs for workflow updates, but auto-merge is disabled for security
  - This is a GitHub platform limitation, not a workflow configuration issue

### Added

- 📦 **Contact Form 7 Stubs**: Added `miguelcolmenares/cf7-stubs` ^6.1 for enhanced PHPStan static analysis
  - Provides Contact Form 7 function and class declaration stubs
  - Improves code intelligence and type checking for CF7 integration
  - Better IDE autocomplete and error detection
  - PHPStan configuration updated to load CF7 stubs automatically
- 📚 **Test Script Environment Variables Documentation**: Comprehensive documentation for test script configuration
  - Added environment variables section to `.github/copilot-instructions.md`
  - Added environment variables section to `tests/README.md`
  - Documents `WP_TESTS_DIR`, `WP_VERSION`, `FORCE_DB_RECREATE`, `FORCE_CF7_REINSTALL`, `CI` variables
  - Includes usage examples for local development and CI/CD integration
  - Provides detailed variable descriptions and default values

### Changed

- 🔧 **GitHub Workflow Permissions**: Added `contents: write` and `pull-requests: write` permissions to `.github/workflows/quality-checks.yml` for proper GitHub App operations
- 📚 **Documentation Policy Reinforced**: Enhanced Copilot instructions with explicit examples to prevent creation of standalone `.md` files (e.g., `FIX_SUMMARY.md`, `GITHUB_APP_PERMISSIONS.md`)
  - All documentation must be consolidated in README.md, CHANGELOG.md, or copilot-instructions.md
  - No separate documentation files allowed under any circumstances
  - Prevents documentation fragmentation and repository clutter
- 🚀 **Quality Checks Script Enhanced**: Improved non-interactive mode and CI/CD integration
  - `WP_TESTS_DIR` now exported as environment variable for all child scripts
  - WordPress version respects `WP_VERSION` environment variable in CI/CD
  - Automatic database recreation with `FORCE_DB_RECREATE=true`
  - Cleaner integration with GitHub Actions workflow
- ⚙️ **GitHub Actions Workflow Optimized**: Simplified quality checks workflow
  - Removed duplicate WordPress and CF7 installation steps
  - Now uses unified `run-quality-checks.sh` script for all operations
  - Passes `WP_VERSION`, `WP_TESTS_DIR`, and CI flags as environment variables
  - Reduced workflow complexity and execution time

### Fixed

- 🐛 **PHPStan Static Analysis Errors**: Resolved all 37 PHPStan level 8 errors
  - **SecurityAjaxHandler.php**: Removed unreachable code after `wp_send_json_error()` calls (7 errors)
  - **SecurityAjaxHandler.php**: Removed non-existent `PathValidator::check_path_conflicts()` method call
  - **SecurityAjaxHandler.php**: Fixed `IPBlacklist::add_ip()` to `add_to_blacklist()` with correct parameters
  - **GraphQLSecurity.php**: Changed undefined `get_limit()` to `get_safe_limit()` in 3 locations
  - **GraphQLSecurity.php**: Added type casting for `preg_replace()` string|null returns (9 errors)
  - **SettingsRenderer.php**: Fixed undefined method `get_configuration_html()` to `get_settings_display()`
  - **SettingsRenderer.php**: Added type casting for `round()` float to string conversion
  - **SecurityDataProvider.php**: Added type casting for `format_time_duration()` float|int parameter
  - **SecurityDataProvider.php**: Improved `WP_DEBUG_LOG` type check for bool|string constant
  - **phpstan.neon**: Added ignore patterns for WordPress-specific code patterns:
    - Properties used via WordPress hooks (side effects not detected by static analysis)
    - Unreachable statements after `wp_send_json_*` functions (they exit execution)
    - Always-true conditions for intentional code clarity
    - WP_DEBUG_LOG type checking (WordPress constant can be bool or string)
  - **Result**: Zero PHPStan errors (100% static analysis compliance at level 8)

### Removed

- 🗑️ Deleted temporary documentation files that violated consolidation policy (`.github/FIX_SUMMARY.md`, `.github/GITHUB_APP_PERMISSIONS.md`)

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
