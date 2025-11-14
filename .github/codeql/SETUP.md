# CodeQL Setup Instructions

## ⚠️ Important: Disable GitHub Default CodeQL Setup

This repository uses a **custom CodeQL workflow** (`.github/workflows/codeql.yml`) that conflicts with GitHub's default CodeQL setup.

### Steps to Disable Default Setup:

1. Go to your repository on GitHub
2. Navigate to: **Settings** → **Code security and analysis**
3. Find **"Code scanning"** section
4. Under **"CodeQL analysis"**:
   - Click **"Set up"** dropdown if enabled
   - Select **"Advanced"** or **"Disable"** the default setup
   - This will allow our custom workflow to run without conflicts

### Why We Use Custom Workflow:

- ✅ **Multi-language analysis**: JavaScript/TypeScript, PHP, GitHub Actions
- ✅ **Extended security queries**: `security-extended` and `security-and-quality` suites
- ✅ **WordPress-specific patterns**: Custom queries for WordPress security (planned)
- ✅ **Full control**: Custom configuration and scheduling
- ✅ **Version pinning**: SHA-pinned actions for security

### Current Configuration:

**File**: `.github/workflows/codeql.yml`

**Languages Analyzed**:
- `javascript-typescript` - Frontend JavaScript/TypeScript code
- `php` - WordPress plugin PHP code  
- `actions` - GitHub Actions workflows

**Query Suites**:
- `security-extended` - Advanced security analysis
- `security-and-quality` - Security + code quality

**Schedule**:
- Push to `main` or `develop`
- Pull requests to `main`
- Weekly: Mondays at 2:30 AM UTC

### Troubleshooting:

**Error**: "CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled"

**Solution**: 
1. Disable GitHub's default CodeQL setup (see steps above)
2. Wait a few minutes for GitHub to process the change
3. Re-run the workflow: Actions → CodeQL → Re-run jobs

**Error**: "Did not recognize the following languages: php"

**Solution**: This should be resolved automatically once default setup is disabled. If it persists:
1. Verify CodeQL action version is v4+
2. Check that `language: php` is spelled correctly
3. Ensure `build-mode: none` is set for PHP

### Custom Queries (Future):

Custom WordPress-specific queries are prepared in `.github/codeql/custom-queries/` but currently disabled to avoid conflicts. They will be enabled in a future update once we verify the basic setup works correctly.

---

**Last Updated**: November 13, 2025  
**Workflow Version**: CodeQL v4 with SHA pinning
