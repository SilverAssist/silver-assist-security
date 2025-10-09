# Silver Assist Security Essentials - Scripts

Bash scripts for development, testing, and release automation.

## Available Scripts

### Testing

**install-wp-tests.sh** - Installs WordPress Test Suite for local development and CI/CD.

Usage: `./scripts/install-wp-tests.sh wordpress_test root '' localhost 6.7.1`

### Version Management

**check-versions.sh** - Displays current version numbers across all files.

**update-version-simple.sh** - Updates version numbers automatically.

Usage: `./scripts/update-version-simple.sh 1.0.2`

### Asset Management

**minify-assets-npm.sh** - Minifies CSS and JavaScript for production.

Usage: `./scripts/minify-assets-npm.sh`

### Release

**build-release.sh** - Creates production ZIP package.

Usage: `./scripts/build-release.sh`

**test-graphql-security.sh** - Tests GraphQL security configurations.

## Setup

```bash
chmod +x scripts/*.sh
./scripts/install-wp-tests.sh wordpress_test root '' localhost 6.7.1
npm install
```
