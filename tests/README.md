# Silver Assist Security Essentials - Test Suite

This directory contains comprehensive tests for the Silver Assist Security Essentials plugin using **WordPress Test Suite (WP_UnitTestCase)**.

## Quick Start

### First-Time Setup

```bash
# Install WordPress Test Suite (required once)
scripts/install-wp-tests.sh wordpress_test root '' localhost latest

# Verify installation
ls /tmp/wordpress-tests-lib/includes/functions.php
```

### Running Tests

```bash
# Run all tests
vendor/bin/phpunit --testdox

# Run specific suite
vendor/bin/phpunit --testsuite "Unit Tests"

# Run specific file
vendor/bin/phpunit tests/Unit/DefaultConfigTest.php

# With coverage (requires Xdebug)
vendor/bin/phpunit --coverage-html coverage/
```

## Test Structure

```
tests/
├── bootstrap.php          # WordPress Test Suite bootstrap
├── Helpers/
│   └── TestHelper.php    # Test utility functions
├── Unit/                 # Unit tests with WP_UnitTestCase
│   ├── DefaultConfigTest.php         # Configuration management tests
│   ├── GraphQLConfigManagerTest.php  # GraphQL configuration tests
│   ├── LoginSecurityTest.php         # Login security tests
│   ├── SecurityHelperTest.php        # Security helper utilities tests
│   └── UpdaterTest.php               # GitHub updater unit tests (11 tests) ✅
├── Integration/          # Integration tests
│   ├── AdminAccessTest.php           # Admin panel access control tests
│   ├── SettingsHubTest.php           # Settings Hub integration tests
│   ├── UpdaterIntegrationTest.php    # Updater WordPress integration (16 tests) ✅
│   └── GraphQLSecurityIntegrationTest.php  # GraphQL security integration (25 tests) ✅
├── WordPress/            # WordPress integration examples
│   └── AdminPanelTest.php           # WP_UnitTestCase example
├── Security/            # Security-focused tests
│   └── SecurityTest.php             # Overall security validation
├── Core/                 # Core functionality tests
│   └── PathValidatorTest.php        # Path validation tests (11 tests) ✅
└── results/             # Test results (git-ignored)
    ├── junit.xml                              # PHPUnit test results
    ├── test-coverage-report.md                # Coverage analysis
    └── graphql-integration-report.md          # GraphQL tests detailed report ✅
```

## Test Framework

### WordPress Test Suite (WP_UnitTestCase)

All tests extend `WP_UnitTestCase` which provides:
- ✅ **Real WordPress Environment**: Full WordPress installation with all functions available
- ✅ **Real Database**: MySQL with automatic transaction rollback after each test
- ✅ **WordPress Factories**: Built-in factories for users, posts, terms, etc.
- ✅ **Hook System**: Test real WordPress hooks and filters
- ✅ **Auto-Cleanup**: Isolated test execution with automatic cleanup

### Test Writing Pattern

```php
use WP_UnitTestCase;

class ExampleTest extends WP_UnitTestCase
{
    public function test_wordpress_option(): void
    {
        // Use real WordPress functions - no mocks needed
        update_option("my_option", "value");
        $result = get_option("my_option");
        $this->assertEquals("value", $result);
    }
    
    public function test_user_creation(): void
    {
        // Use WordPress factories for test data
        $user_id = $this->factory()->user->create(['role' => 'administrator']);
        $this->assertGreaterThan(0, $user_id);
    }
    
    public function test_hooks(): void
    {
        // Test real WordPress hooks
        $called = false;
        add_action('my_hook', function() use (&$called) {
            $called = true;
        });
        do_action('my_hook');
        $this->assertTrue($called);
    }
}
```

## Test Types

### Unit Tests (`tests/Unit/`)
Test individual classes and methods with real WordPress:
- **DefaultConfig**: Configuration management, option handling, defaults
- **GraphQLConfigManager**: Centralized GraphQL configuration, rate limiting, caching
- **LoginSecurity**: IP detection, session management, lockout mechanisms, bot detection
- **SecurityHelper**: Utility functions, asset loading, IP detection, validation

### WordPress Examples (`tests/WordPress/`)
Integration test examples showing WP_UnitTestCase patterns:
- **AdminPanel**: Admin interface, AJAX handlers, settings, menus, nonces

### Security Tests (`tests/Security/`)
Focused on security implementations:
- HTTPOnly cookie enforcement
- GraphQL security with centralized configuration
- Security headers (X-Frame-Options, X-XSS-Protection, CSP)
- Input sanitization and validation

## Running Tests

### Prerequisites

1. **WordPress Test Environment**:
   ```bash
   # Install WordPress tests
   scripts/install-wp-tests.sh wordpress_test root '' localhost latest
   ```

2. **PHPUnit Installation**:
   ```bash
   composer install --dev
   ```

### Running All Tests

```bash
# Run complete test suite
vendor/bin/phpunit

# Run with coverage report
vendor/bin/phpunit --coverage-html tests/coverage
```

### Running Specific Test Types

```bash
# Unit tests only
vendor/bin/phpunit tests/Unit/

# Integration tests only
vendor/bin/phpunit tests/Integration/

# Security tests only
vendor/bin/phpunit tests/Security/

# Specific test class
vendor/bin/phpunit tests/Unit/LoginSecurityTest.php

# Specific test method
vendor/bin/phpunit --filter test_failed_login_tracking tests/Unit/LoginSecurityTest.php
```

### Code Quality Checks

```bash
# Run PHP CodeSniffer
vendor/bin/phpcs

# Auto-fix coding standards
vendor/bin/phpcbf

# Run both tests and coding standards
composer run check
```

## Test Configuration

### PHPUnit Configuration (`phpunit.xml.dist`)
- Test suites organization
- Coverage reporting
- WordPress constants
- Test environment setup

### PHP CodeSniffer (`.phpcs.xml.dist`)
- WordPress coding standards
- Security rule enforcement
- Modern PHP compatibility
- Custom plugin rules

## Test Helpers

The `TestHelper` class provides utilities for:

- **User Management**: Create/delete test users
- **HTTP Mocking**: Simulate requests and bot behavior
- **Transient Cleanup**: Clean test data between runs
- **Login Simulation**: Test authentication flows
- **GraphQL Testing**: Generate test queries
- **Security Assertions**: Validate security settings

## Example Test Usage

```php
use SilverAssist\Security\Tests\Helpers\TestHelper;

// Create test user
$user_id = TestHelper::create_test_user(['role' => 'administrator']);

// Mock bot behavior
TestHelper::mock_bot_user_agent('scanner');

// Simulate login attempt
$result = TestHelper::simulate_login('username', 'password', '192.168.1.1');

// Clean up
TestHelper::cleanup_transients();
TestHelper::delete_test_user($user_id);
```

## WordPress Test Environment

### Database Setup
Tests use a separate database to avoid affecting development data:
- Database: `wordpress_test`
- Isolated from main WordPress installation
- Automatically cleaned between test runs

### Constants Available in Tests
- `SILVER_ASSIST_SECURITY_TESTING`: Indicates test environment
- `SILVER_ASSIST_SECURITY_VERSION`: Plugin version for testing
- WordPress test constants (WP_TESTS_DOMAIN, etc.)

## Continuous Integration

Tests are designed to run in CI environments:

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        php: [8.0, 8.1, 8.2, 8.3]
        wordpress: [6.5, latest]
    steps:
      - uses: actions/checkout@v3
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
      - name: Install dependencies
        run: composer install
      - name: Setup WordPress tests
        run: scripts/install-wp-tests.sh wordpress_test root '' localhost ${{ matrix.wordpress }}
      - name: Run tests
        run: vendor/bin/phpunit
      - name: Check coding standards
        run: vendor/bin/phpcs
```

## Coverage Reports

HTML coverage reports are generated in `tests/coverage/`:
- Line coverage for all source files
- Method and class coverage
- Visual coverage maps
- Coverage metrics and statistics

## Best Practices

### Test Naming
- Use descriptive test method names: `test_failed_login_tracking`
- Group related tests in same class
- Use meaningful assertions messages

### Test Data
- Always clean up test data in `tearDown()`
- Use realistic test data
- Test edge cases and boundary conditions

### Assertions
- Use specific assertions: `assertEquals` vs `assertTrue`
- Include descriptive failure messages
- Test both success and failure scenarios

### Performance
- Keep tests fast and focused
- Use mocking for external dependencies
- Avoid unnecessary database operations

## Troubleshooting

### Common Issues

**WordPress Test Environment Not Found**:
```bash
# Install WordPress tests
scripts/install-wp-tests.sh wordpress_test root '' localhost latest
```

**Database Connection Errors**:
- Verify MySQL/MariaDB is running
- Check database credentials
- Ensure test database exists

**Permission Errors**:
```bash
# Fix permissions
chmod -R 755 tests/
chown -R $USER:$USER tests/
```

**Memory Limit Issues**:
```bash
# Increase PHP memory limit
php -d memory_limit=512M vendor/bin/phpunit
```

### Debug Mode
Enable debug output in tests:
```php
// Add to test methods
echo "Debug: " . var_export($data, true) . "\n";
```

## Contributing

When adding new tests:

1. Follow existing test structure and naming conventions
2. Add tests for both success and failure scenarios
3. Include security-focused test cases
4. Update this README if adding new test types
5. Ensure all tests pass before committing
6. Maintain high code coverage (aim for >80%)

---

*Silver Assist Security Essentials - Comprehensive Test Coverage*
