# Silver Assist Security Essentials - Release Scripts

This directory contains bash scripts to automate the release process for the Silver Assist Security Essentials WordPress plugin.

## Scripts Overview

### 📝 `check-versions.sh`
Checks and displays current version numbers across all plugin files.

**Usage:**
```bash
./scripts/check-versions.sh
```

**What it checks:**
- Main plugin file (header, constant, docblock)
- All PHP files (`@version` tags)
- All CSS files (`@version` tags)
- All JavaScript files (`@version` tags)
- Documentation files (`HEADER-STANDARDS.md`, `README.md`)
- Scripts themselves
- Composer configuration

**Features:**
- ✅ Visual consistency report with colored output
- ✅ Version mismatch detection
- ✅ Missing version tag identification
- ✅ Summary statistics
- ✅ Helpful next-step suggestions

---

### 📝 `update-version.sh`
Automatically updates version numbers across all plugin files.

**Usage:**
```bash
./scripts/update-version.sh <new-version>
```

**Examples:**
```bash
./scripts/update-version.sh 1.0.2
./scripts/update-version.sh 1.1.0
./scripts/update-version.sh 2.0.0
```

**What it updates:**
- Main plugin file header (`Version: X.X.X`)
- Plugin constant (`SILVER_ASSIST_SECURITY_VERSION`)
- All PHP files (`@version` tags)
- All CSS files (`@version` tags)
- All JavaScript files (`@version` tags)
- Documentation files (`HEADER-STANDARDS.md`, `README.md`)
- This script itself

**Features:**
- ✅ Semantic version validation
- ✅ Interactive confirmation
- ✅ Automatic backup creation
- ✅ Rollback on failure
- ✅ Colored output with status messages

---

### 📦 `build-release.sh`
Creates a production-ready ZIP package for distribution.

**Usage:**
```bash
./scripts/build-release.sh [version]
```

**Examples:**
```bash
./scripts/build-release.sh           # Uses version from plugin file
./scripts/build-release.sh 1.0.2     # Override version
```

**What it includes:**
- ✅ Main plugin file (`silver-assist-security.php`)
- ✅ Source code (`src/` directory)
- ✅ Assets (`assets/` directory)
- ✅ Language files (`languages/` directory)
- ✅ Documentation (`README.md`, `LICENSE`)
- ✅ Composer configuration (`composer.json`)

**What it excludes:**
- ❌ Development files (`.git`, `.github`, `scripts/`)
- ❌ Dependencies (`vendor/`, `node_modules/`)
- ❌ Configuration files (`.vscode/`, `.idea/`)
- ❌ Build artifacts (`*.log`, `*.tmp`, `*.bak`)
- ❌ Documentation standards (`HEADER-STANDARDS.md`, `MIGRATION.md`)

**Output:**
- ZIP file: `silver-assist-security-v{version}.zip`
- Internal folder: `silver-assist-security/` (clean name without version)
- Size: ~45KB (compressed)

---

## Complete Release Workflow

Here's the recommended workflow for creating a new release:

### 0. Check Current State
```bash
# Check current version consistency
./scripts/check-versions.sh
```

### 1. Update Version
```bash
# Update all version numbers in the codebase
./scripts/update-version.sh 1.0.2
```

### 2. Review Changes
```bash
# Review all changes made by the version update
git diff

# Verify version consistency
./scripts/check-versions.sh

# Make sure all files were updated correctly
grep -r "1.0.2" . --exclude-dir=.git
```

### 3. Update Documentation
```bash
# Manually update CHANGELOG.md with new features/fixes
# Update MIGRATION.md if there are breaking changes
```

### 4. Test Plugin
```bash
# Test the plugin with the new version
# Verify all functionality works correctly
```

### 5. Commit Changes
```bash
# Commit the version update
git add .
git commit -m "🔧 Update version to 1.0.2"
```

### 6. Create Release Package
```bash
# Build the distribution ZIP
./scripts/build-release.sh

# This creates silver-assist-security-v1.0.2.zip
```

### 7. Test Release Package
```bash
# Test the ZIP package in a WordPress installation
# 1. Upload the ZIP via WordPress admin
# 2. Activate the plugin
# 3. Verify all features work correctly
```

### 8. Create Git Tag and Release
```bash
# Create a git tag
git tag v1.0.2

# Push changes and tag
git push origin main
git push origin v1.0.2

# Create GitHub release
# 1. Go to GitHub repository
# 2. Create new release from tag v1.0.2
# 3. Upload silver-assist-security-v1.0.2.zip
# 4. Write release notes
```

---

## Requirements

- **Operating System:** macOS or Linux
- **Shell:** bash
- **Commands:** `grep`, `sed`, `zip`, `find`
- **Permissions:** Execute permissions on script files

## Setup

Make scripts executable:
```bash
chmod +x scripts/*.sh
```

## Notes

### Version Format
- Use semantic versioning: `MAJOR.MINOR.PATCH`
- Examples: `1.0.0`, `1.2.3`, `2.0.0`

### Script Behavior
- **`update-version.sh`** only updates `@version` tags, not `@since` tags
- **`build-release.sh`** creates a clean package without development files
- Both scripts include backup and error handling

### GitHub Actions Integration
The `build-release.sh` script outputs variables for GitHub Actions:
- `package_name`
- `package_size`
- `package_size_kb`
- `zip_path`
- `version`

### Troubleshooting

**Permission errors:**
```bash
chmod +x scripts/*.sh
```

**Version not detected:**
```bash
# Check the main plugin file has proper version header
grep "Version:" silver-assist-security.php
```

**ZIP creation fails:**
```bash
# Check if zip is installed
which zip
# Install if needed (macOS)
brew install zip
```
