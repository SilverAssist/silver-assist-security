## 🚀 What's Changed in v1.1.14

### 🔧 Dependencies (33 updates)
- 🔧 Standardize all CI/CD workflows with unified validation
- 🔧 Fix WordPress Test Suite detection in quality checks script
- 🔧 Fix 5 PHPStan type errors and improve testing infrastructure
- 🔧 Reformat PHPUnit dependency ignore section for clarity
- ✨ Add comprehensive TDD tests for GraphQL Security integration (25 tests)
- 🔧 Update minimum PHP version requirement in Updater
- 🔧 Fix PHPStan errors and align workflow validations
- 🔧 Fix inline comment punctuation in Plugin.php
- 🔧 Configure PHPCS rules and fix inline comments in DefaultConfig
- 🔧 Remove mandatory double quotes coding standard
- Merge pull request #8 from SilverAssist/dependabot/github_actions/actions/setup-node-5
- 🔧(deps): Bump actions/setup-node from 4 to 5
- Merge pull request #7 from SilverAssist/dependabot/github_actions/actions/checkout-5
- 🔧(deps): Bump actions/checkout from 4 to 5
- ✨ Add weekly automated draft release system
- Merge pull request #4 from SilverAssist/dependabot/composer/axepress/wp-graphql-stubs-tw-2.3
- 🔧(deps-dev): Update axepress/wp-graphql-stubs requirement
- Merge pull request #3 from SilverAssist/dependabot/github_actions/actions/github-script-8
- Merge pull request #6 from SilverAssist/dependabot/composer/dealerdirect/phpcodesniffer-composer-installer-tw-1.1.2
- Merge pull request #5 from SilverAssist/dependabot/composer/yoast/phpunit-polyfills-tw-4.0
- Merge pull request #2 from SilverAssist/dependabot/github_actions/actions/cache-4
- Merge pull request #1 from SilverAssist/dependabot/github_actions/softprops/action-gh-release-2
- 🔧(deps-dev): Update yoast/phpunit-polyfills requirement
- 🔧(deps-dev): Update dealerdirect/phpcodesniffer-composer-installer requirement
- 🔧(deps): Bump actions/cache from 3 to 4
- 🔧(deps): Bump softprops/action-gh-release from 1 to 2
- 🔧(deps): Bump actions/github-script from 7 to 8
- ♻️ Remove redundant validate-pr job from dependency-updates workflow
- 🔧 Add PR write permissions to validate-pr job and GitHub CLI pager guidelines
- 🔧 Fix CI/CD dependency workflow and PHPStan unreachable code warnings
- ✨ Add labels back to Dependabot configuration
- 🔧 Fix Dependabot configuration - remove invalid assignees and labels
- 🐛 Fix dependency check workflow - install before checking outdated

### 🔒 Security (16 fixes)
- 🔧 Fix 5 PHPStan type errors and improve testing infrastructure
- �� Ignore PHPUnit major version updates in Dependabot
- 📚 Update test documentation with GraphQL Security integration tests
- ✨ Add comprehensive TDD tests for GraphQL Security integration (25 tests)
- ✨ Add comprehensive TDD tests for Updater class
- 🔒 Prevent HSTS in development environments (TDD)
- ✅ Add comprehensive AdminPanel integration tests
- ✅ Add comprehensive LoginSecurity integration tests
- ✅ Add comprehensive AdminHideSecurity integration tests
- 🔒 Add WordPress system paths to forbidden list
- ♻️ Remove unused dead code methods
- 🔧 Fix PHPStan errors and align workflow validations
- 🔒 Add capability check to render_admin_page for test compatibility
- Merge branch 'main' of https://github.com/SilverAssist/silver-assist-security
- ✨ Add weekly automated draft release system
- 🤖 Add automated dependency management with GitHub Actions + Dependabot

### 🐛 Bug Fixes (16 fixes)
- 🔧 Fix WordPress Test Suite detection in quality checks script
- 🔧 Fix 5 PHPStan type errors and improve testing infrastructure
- ✨ Add comprehensive TDD tests for GraphQL Security integration (25 tests)
- 🔧 Fix PHPStan errors and align workflow validations
- 🔒 Add capability check to render_admin_page for test compatibility
- 🔧 Fix inline comment punctuation in Plugin.php
- 🔧 Configure PHPCS rules and fix inline comments in DefaultConfig
- 🎨 Apply PHPCBF auto-fixes for WordPress Coding Standards
- 🐛 Fix PHPStan level 8 errors in AdminPanel and DefaultConfig
- 🐛 Fix false positive in PHP syntax check
- 🐛 Fix PHP syntax check in auto-draft-release workflow
- ✨ Add weekly automated draft release system
- 🔧 Add PR write permissions to validate-pr job and GitHub CLI pager guidelines
- 🔧 Fix CI/CD dependency workflow and PHPStan unreachable code warnings
- 🔧 Fix Dependabot configuration - remove invalid assignees and labels
- 🐛 Fix dependency check workflow - install before checking outdated

### ✨ Features (8 new)
- 🔧 Fix 5 PHPStan type errors and improve testing infrastructure
- ✨ Add comprehensive TDD tests for GraphQL Security integration (25 tests)
- ✨ Add comprehensive TDD tests for Updater class
- ✅ Add comprehensive LoginSecurity integration tests
- ✅ Add comprehensive AdminHideSecurity integration tests
- ✨ Add weekly automated draft release system
- ✨ Add labels back to Dependabot configuration
- 🤖 Add automated dependency management with GitHub Actions + Dependabot

### 📝 Other Changes
- �� Ignore PHPUnit major version updates in Dependabot
- 📚 Update test documentation with GraphQL Security integration tests
- ✅ Add comprehensive AdminPanel integration tests
- ✅ Add comprehensive LoginSecurity integration tests
- ✅ Add comprehensive AdminHideSecurity integration tests
- ♻️ Remove unused dead code methods
- 🎨 Apply PHPCBF auto-fixes for WordPress Coding Standards
- Merge branch 'main' of https://github.com/SilverAssist/silver-assist-security
- ♻️ Remove redundant validate-pr job from dependency-updates workflow

---

**Full Changelog**: https://github.com/SilverAssist/silver-assist-security/compare/v1.1.13...v1.1.14

📊 **Statistics:**
- 49 commits
- 1 days since last release
- 33 dependency updates
- 🔒 16 security fixes
- 16 bug fixes
- 8 new features
