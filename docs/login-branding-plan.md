# Implementation Plan: Login Page Branding (#83)

## Problem Statement

The WordPress login page uses default WordPress branding. Silver Assist needs a custom-branded login experience with a modern split-layout design to reinforce brand identity for client sites.

## Current Architecture

- `LoginSecurity` handles login protection (brute force, lockouts, session timeouts)
- `Plugin.php` initializes security components via `init_security_components()`
- `DefaultConfig` centralizes all option defaults with `get_option()` fallback pattern
- `SettingsHandler` processes form submissions per settings category
- Assets live in `assets/css/` and `assets/js/`

## Proposed Changes

### New Files

| File | Purpose |
|------|---------|
| `src/Security/LoginBranding.php` | Main module — registers login page hooks |
| `assets/css/login-branding.css` | Split-layout styles, form override, responsive |
| `assets/images/silver-assist-logo.svg` | Inline SVG brand logo |
| `assets/images/login-illustration.svg` | Right-column decorative illustration |
| `tests/Unit/LoginBrandingTest.php` | Unit tests for hook registration and filters |

### Modified Files

| File | Change |
|------|--------|
| `src/Core/Plugin.php` | Add `LoginBranding` instantiation in `init_security_components()` |
| `src/Core/DefaultConfig.php` | Add 4 new option defaults for login branding |
| `src/Admin/Settings/SettingsHandler.php` | Add `save_login_branding_settings()` method |

## Phase Breakdown

### Phase 1: Core Module + CSS

1. Create `LoginBranding.php` with hook registration
2. Create `login-branding.css` with split-layout styles
3. Register in `Plugin.php`
4. Add defaults to `DefaultConfig.php`

### Phase 2: SVG Assets + HTML Injection

1. Create `silver-assist-logo.svg`
2. Create `login-illustration.svg`
3. Implement `inject_login_head()` (inline SVG logo)
4. Implement `inject_login_footer()` (illustration panel)

### Phase 3: Settings Integration

1. Add `save_login_branding_settings()` to `SettingsHandler`
2. Add settings UI in admin login security tab

### Phase 4: Testing + QA

1. Write `LoginBrandingTest.php` unit tests
2. Run PHPCS + PHPStan
3. Manual visual QA at breakpoints

## Testing Strategy

- Unit tests verify: hooks registered when enabled, NOT registered when disabled, filter return values
- PHPCS and PHPStan Level 8 must pass
- Manual verification of login/register/lost-password flows
