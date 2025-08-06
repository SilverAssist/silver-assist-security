# Silver Assist Security Essentials - Test Suite

This directory contains comprehensive tests for the Silver Assist Security Essentials plugin.

## Test Structure

```
tests/
├── bootstrap.php          # PHPUnit bootstrap file
├── Helpers/
│   └── TestHelper.php    # Test utility functions
├── Unit/                 # Unit tests for individual classes
│   ├── LoginSecurityTest.php
│   └── GraphQLConfigManagerTest.php  # NEW in v1.0.4
├── Integration/          # Integration tests for component interaction
│   └── AdminPanelTest.php
├── Security/            # Security-focused tests
│   └── SecurityTest.php
└── results/             # Test results and coverage reports
```

## Test Types

### Unit Tests (`tests/Unit/`)
Test individual classes and methods in isolation:
- **LoginSecurity functionality**: IP detection, session management, lockout mechanisms
- **GraphQLConfigManager (v1.0.4)**: Centralized configuration, singleton pattern, caching, rate limiting
- Password validation and enforcement
- Bot detection and blocking logic
- Failed login attempt tracking

### Integration Tests (`tests/Integration/`)
Test component interactions and WordPress integration:
- Admin panel functionality with GraphQLConfigManager integration (v1.0.4)
- AJAX endpoints and real-time updates
- Settings management through centralized configuration
- Menu registration and capability checks
- Script/style enqueuing and dependencies
- Form handling, validation, and auto-save functionality

### Security Tests (`tests/Security/`)
Focused on security implementations:
- HTTPOnly cookie enforcement across all WordPress cookies
- **GraphQL security with centralized configuration (v1.0.4)**: Query validation, depth limiting, rate limiting
- Security headers implementation (X-Frame-Options, X-XSS-Protection, CSP)
- Input sanitization and validation
- XML-RPC blocking
- User enumeration protection
- Version hiding

## Running Tests

### Prerequisites

1. **WordPress Test Environment**:
   ```bash
   # Install WordPress tests
   bin/install-wp-tests.sh wordpress_test root '' localhost latest
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
        run: bin/install-wp-tests.sh wordpress_test root '' localhost ${{ matrix.wordpress }}
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
bin/install-wp-tests.sh wordpress_test root '' localhost latest
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
