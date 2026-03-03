#!/bin/bash

################################################################################
# Silver Assist — Unified Build Release Script
#
# Creates a production-ready WordPress plugin ZIP package.
# Auto-detects plugin structure and copies only runtime files.
#
# Usage: ./scripts/build-release.sh [version]
#
# @package SilverAssist
# @author  Silver Assist
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SLUG=$(basename "$PROJECT_ROOT")

echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ${PLUGIN_SLUG} — Release Builder${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""

# Auto-detect main plugin file
MAIN_FILE=$(find "$PROJECT_ROOT" -maxdepth 1 -name "*.php" -exec grep -l "Plugin Name:" {} \; 2>/dev/null | head -1)
if [ -z "$MAIN_FILE" ]; then
    echo -e "${RED}❌ No main plugin file found${NC}"
    exit 1
fi
MAIN_FILE_NAME=$(basename "$MAIN_FILE")

# Get version
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "$MAIN_FILE" | cut -d' ' -f2)
fi

if [ -z "$VERSION" ]; then
    echo -e "${RED}❌ Could not detect version${NC}"
    exit 1
fi

echo -e "  Plugin:  ${PLUGIN_SLUG}"
echo -e "  File:    ${MAIN_FILE_NAME}"
echo -e "  Version: ${VERSION}"
echo ""

# Setup
BUILD_DIR="${PROJECT_ROOT}/build"
PLUGIN_DIR="${BUILD_DIR}/${PLUGIN_SLUG}"
ZIP_FILE="${PLUGIN_SLUG}-v${VERSION}.zip"

rm -rf "$BUILD_DIR"
mkdir -p "$PLUGIN_DIR"

# ─── Copy plugin files ───────────────────────────────────────────────────────

echo -e "${YELLOW}📋 Copying plugin files...${NC}"

cp "$MAIN_FILE" "$PLUGIN_DIR/"
echo "  ✅ ${MAIN_FILE_NAME}"

for dir in includes Includes src assets languages blocks templates; do
    if [ -d "${PROJECT_ROOT}/${dir}" ]; then
        cp -r "${PROJECT_ROOT}/${dir}" "$PLUGIN_DIR/"
        echo "  ✅ ${dir}/"
    fi
done

for file in README.md CHANGELOG.md LICENSE LICENSE.md; do
    if [ -f "${PROJECT_ROOT}/${file}" ]; then
        cp "${PROJECT_ROOT}/${file}" "$PLUGIN_DIR/"
    fi
done

# ─── Vendor dependencies ─────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}📦 Building vendor dependencies...${NC}"

cd "$PROJECT_ROOT"

if [ ! -f "composer.json" ]; then
    echo -e "${RED}❌ composer.json not found${NC}"
    exit 1
fi

composer install --no-dev --optimize-autoloader --no-interaction

if [ ! -f "vendor/autoload.php" ]; then
    echo -e "${RED}❌ vendor/autoload.php not found${NC}"
    exit 1
fi

echo -e "${YELLOW}📦 Copying production vendor files...${NC}"

mkdir -p "$PLUGIN_DIR/vendor/composer"
cp vendor/autoload.php "$PLUGIN_DIR/vendor/"
cp vendor/composer/*.php "$PLUGIN_DIR/vendor/composer/"
cp vendor/composer/*.json "$PLUGIN_DIR/vendor/composer/" 2>/dev/null || true
echo "  ✅ autoloader"

if [ -d "vendor/composer/installers" ]; then
    mkdir -p "$PLUGIN_DIR/vendor/composer/installers"
    [ -d "vendor/composer/installers/src" ] && cp -r "vendor/composer/installers/src" "$PLUGIN_DIR/vendor/composer/installers/"
    echo "  ✅ composer/installers"
fi

if [ -d "vendor/silverassist" ]; then
    mkdir -p "$PLUGIN_DIR/vendor/silverassist"
    for package_dir in vendor/silverassist/*/; do
        if [ -d "$package_dir" ]; then
            package_name=$(basename "$package_dir")
            dest="$PLUGIN_DIR/vendor/silverassist/$package_name"
            mkdir -p "$dest"
            [ -d "$package_dir/src" ] && cp -r "$package_dir/src" "$dest/"
            [ -d "$package_dir/assets" ] && cp -r "$package_dir/assets" "$dest/"
            echo "  ✅ silverassist/${package_name}"
        fi
    done
fi

# Restore dev dependencies (skip in CI — environment is ephemeral)
if [ -z "$GITHUB_ACTIONS" ]; then
    echo ""
    echo -e "${YELLOW}📦 Restoring development dependencies...${NC}"
    composer install --no-interaction > /dev/null 2>&1
    echo "  ✅ Dev environment restored"
fi

# ─── Validate ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}🔍 Validating package...${NC}"

ERRORS=0

if [ ! -f "$PLUGIN_DIR/$MAIN_FILE_NAME" ]; then
    echo -e "${RED}  ❌ Main plugin file${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ ! -f "$PLUGIN_DIR/vendor/autoload.php" ]; then
    echo -e "${RED}  ❌ Autoloader${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ ! -f "$PLUGIN_DIR/vendor/silverassist/wp-settings-hub/assets/css/settings-hub.css" ]; then
    echo -e "${RED}  ❌ wp-settings-hub CSS asset${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ Settings Hub CSS"
fi

if [ ! -f "$PLUGIN_DIR/vendor/silverassist/wp-github-updater/assets/js/check-updates.js" ]; then
    echo -e "${RED}  ❌ wp-github-updater JS asset${NC}"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ GitHub Updater JS"
fi

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}❌ Validation failed (${ERRORS} errors)${NC}"
    exit 1
fi

echo -e "${GREEN}  ✅ All checks passed${NC}"

# ─── Create ZIP ───────────────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}🗜️  Creating ZIP...${NC}"

cd "$BUILD_DIR"
zip -r "$ZIP_FILE" "$PLUGIN_SLUG/" -x "*.DS_Store*" > /dev/null

# Checksums
md5sum "$ZIP_FILE" > "${ZIP_FILE}.md5" 2>/dev/null || md5 -r "$ZIP_FILE" > "${ZIP_FILE}.md5"
shasum -a 256 "$ZIP_FILE" > "${ZIP_FILE}.sha256"

cd "$PROJECT_ROOT"

ZIP_SIZE=$(du -h "$BUILD_DIR/$ZIP_FILE" | cut -f1)

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Build complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "  📦 build/${ZIP_FILE} (${ZIP_SIZE})"
echo "  🔐 build/${ZIP_FILE}.md5"
echo "  🔐 build/${ZIP_FILE}.sha256"

# GitHub Actions output
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "zip_path=build/${ZIP_FILE}" >> "$GITHUB_OUTPUT"
    echo "zip_name=${ZIP_FILE}" >> "$GITHUB_OUTPUT"
    echo "version=${VERSION}" >> "$GITHUB_OUTPUT"
    echo "zip_size=${ZIP_SIZE}" >> "$GITHUB_OUTPUT"
fi
