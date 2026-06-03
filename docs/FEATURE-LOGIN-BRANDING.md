# Feature: Login Page Branding

## Overview

Custom branding for the WordPress login page (`wp-login.php`) that replaces the default WordPress appearance with Silver Assist branding. Implements a modern split-layout design with the login form on the left and a decorative illustration panel on the right.

---

## Goals

1. Replace the WordPress logo with the Silver Assist logo (SVG inline)
2. Override the default login page layout with a modern two-column design
3. Apply Silver Assist brand colors, typography, and spacing
4. Maintain full compatibility with WordPress login hooks (login, register, lost password)
5. Responsive design: illustration panel hidden on narrow screens
6. Togglable via admin settings (enabled/disabled)

---

## Technical Architecture

### New Files

| File | Purpose |
|------|---------|
| `src/Security/LoginBranding.php` | Main module class — registers hooks |
| `assets/css/login-branding.css` | Login page custom styles |
| `assets/images/silver-assist-logo.svg` | Brand logo SVG file |
| `assets/images/login-illustration.svg` | Right-column decorative illustration |
| `templates/login-branding.php` | Optional template for injected HTML blocks |

### Modified Files

| File | Change |
|------|--------|
| `src/Core/Plugin.php` | Instantiate `LoginBranding` conditionally |
| `src/Core/DefaultConfig.php` | Add default options for the feature |
| `src/Admin/Settings/SettingsHandler.php` | Add save logic for login branding settings |
| Admin settings view (login security tab) | Add UI toggles for login branding |

---

## WordPress Hooks Used

### Login Page Customization Hooks

| Hook | Type | Purpose |
|------|------|---------|
| `login_enqueue_scripts` | action | Enqueue custom CSS and JS |
| `login_headerurl` | filter | Change logo link URL (→ site URL) |
| `login_headertext` | filter | Change logo alt text (→ site name) |
| `login_head` | action | Inject inline SVG logo + custom `<style>` |
| `login_body_class` | filter | Add custom body classes for layout |
| `login_footer` | action | Inject illustration panel HTML + footer branding |
| `login_form` | action | Inject additional form elements if needed |
| `login_message` | filter | Custom welcome message above the form |

### Additional Hooks for Full Customization

| Hook | Type | Purpose |
|------|------|---------|
| `login_title` | filter | Custom `<title>` tag (e.g., "Login — Silver Assist") |
| `login_form_top` | action | Inject content at top of form |
| `login_form_bottom` | action | Inject content at bottom of form |
| `wp_login_errors` | filter | Customize error message styling |

---

## Design Specification

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                        100vw × 100vh                            │
├────────────────────────────┬────────────────────────────────────┤
│                            │                                    │
│   LEFT COLUMN (50%)        │   RIGHT COLUMN (50%)              │
│   ┌──────────────────┐     │                                    │
│   │ [Logo] Silver     │     │   ┌────────────────────────────┐  │
│   │        Assist     │     │   │                            │  │
│   │                   │     │   │    Decorative              │  │
│   │    Login          │     │   │    Illustration            │  │
│   │                   │     │   │    (full-bleed)            │  │
│   │  ┌─────────────┐ │     │   │                            │  │
│   │  │ Email       │ │     │   │    Rocket / Mountains      │  │
│   │  └─────────────┘ │     │   │    / Sky theme             │  │
│   │  ┌─────────────┐ │     │   │                            │  │
│   │  │ Password    │ │     │   │                            │  │
│   │  └─────────────┘ │     │   │                            │  │
│   │                   │     │   │                            │  │
│   │  [═══ Log In ═══] │     │   │                            │  │
│   │                   │     │   │    Watermark: Silver Assist │  │
│   │  Forgot Password? │     │   │                            │  │
│   │                   │     │   └────────────────────────────┘  │
│   │  © Silver Assist  │     │                                    │
│   │  Terms | Privacy  │     │                                    │
│   └──────────────────┘     │                                    │
│                            │                                    │
└────────────────────────────┴────────────────────────────────────┘
```

### Responsive Behavior

| Breakpoint | Behavior |
|------------|----------|
| > 1024px | Two-column layout (50/50) |
| 768–1024px | Two-column layout (60/40) |
| < 768px | Single column, illustration hidden, form full-width |

### Brand Colors (from `variables.css`)

| Token | Value | Usage |
|-------|-------|-------|
| `--silver-brand-cyan` | `#00D1FF` | Logo icon, CTA button, accents |
| `--silver-text-primary` | `#1d2327` | Form labels, headings |
| `--silver-text-secondary` | `#50575e` | Placeholder text, footer |
| `--silver-bg-primary` | `#ffffff` | Left column background |
| `--silver-bg-secondary` | `#f0f0f1` | Input field backgrounds |
| `--silver-border-primary` | `#c3c4c7` | Input borders |

### Typography

| Element | Size | Weight | Font |
|---------|------|--------|------|
| Brand name | 24px | 600 (semibold) | System font stack |
| Page title ("Login") | 32px | 300 (light) | System font stack |
| Labels | 14px | 700 (bold) | System font stack |
| Inputs | 16px | 400 (regular) | System font stack |
| CTA button | 16px | 700 (bold) | System font stack, uppercase |
| Footer | 12px | 400 | System font stack |

### Form Inputs

- Width: 100% of form container
- Border-radius: 6px
- Border: 1px solid `--silver-border-primary`
- Padding: 12px 16px
- Focus: 2px outline `--silver-brand-cyan`

### CTA Button

- Width: 100%
- Height: 48px
- Background: `#00D1FF`
- Color: `#ffffff`
- Border-radius: 8px
- Text: uppercase, bold
- Hover: darken 10%
- Transition: 200ms ease

---

## Settings & Options

### New Options in `DefaultConfig`

```php
'silver_assist_login_branding_enabled'     => 1,    // Enable login branding (default: on)
'silver_assist_login_branding_logo_url'    => '',   // Custom logo URL (empty = built-in SVG)
'silver_assist_login_branding_bg_color'    => '',   // Right column bg color (empty = default gradient)
'silver_assist_login_branding_show_illustration' => 1, // Show illustration panel
```

### Admin Settings UI

Add a "Login Branding" section within the existing "Login Security" settings tab:

- **Enable Login Branding** — Toggle on/off
- **Custom Logo** — Media uploader (optional; falls back to built-in SVG)
- **Show Illustration Panel** — Toggle on/off
- **Background Color** — Color picker for the illustration column

---

## Class Design: `LoginBranding`

```php
namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;

class LoginBranding {

    private string $plugin_version;
    private bool $enabled;

    public function __construct() {
        $this->plugin_version = SILVER_ASSIST_SECURITY_VERSION;
        $this->enabled = (bool) DefaultConfig::get_option('silver_assist_login_branding_enabled');

        if ($this->enabled) {
            $this->init();
        }
    }

    private function init(): void {
        // Enqueue custom login styles
        add_action('login_enqueue_scripts', [$this, 'enqueue_login_assets']);

        // Replace WordPress logo
        add_filter('login_headerurl', [$this, 'custom_login_url']);
        add_filter('login_headertext', [$this, 'custom_login_text']);

        // Inject layout HTML
        add_action('login_head', [$this, 'inject_login_head']);
        add_action('login_footer', [$this, 'inject_login_footer']);
        add_filter('login_body_class', [$this, 'add_body_classes']);

        // Custom page title
        add_filter('login_title', [$this, 'custom_login_title'], 10, 2);
    }

    public function enqueue_login_assets(): void {
        wp_enqueue_style(
            'silver-assist-login-branding',
            plugin_dir_url(SILVER_ASSIST_SECURITY_FILE) . 'assets/css/login-branding.css',
            [],
            $this->plugin_version
        );
    }

    public function custom_login_url(): string {
        return home_url('/');
    }

    public function custom_login_text(): string {
        return get_bloginfo('name');
    }

    public function inject_login_head(): void {
        // Output inline SVG logo replacement CSS
        // Hide #login h1 a default logo, replace with inline SVG
    }

    public function inject_login_footer(): void {
        // Output illustration panel HTML
        // Output footer branding
    }

    public function add_body_classes(array $classes): array {
        $classes[] = 'silver-assist-branded-login';
        if (DefaultConfig::get_option('silver_assist_login_branding_show_illustration')) {
            $classes[] = 'silver-assist-split-layout';
        }
        return $classes;
    }

    public function custom_login_title(string $login_title, string $title): string {
        return $title . ' — Silver Assist';
    }
}
```

---

## CSS Architecture: `login-branding.css`

### Key Selectors

```css
/* Layout wrapper — split the page */
body.silver-assist-split-layout {
    display: flex;
    min-height: 100vh;
    background: var(--silver-bg-primary);
}

/* Left column: form */
body.silver-assist-split-layout #login {
    width: 50%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding: 2rem;
}

/* Right column: illustration (injected via login_footer) */
.silver-login-illustration-panel {
    width: 50%;
    background: linear-gradient(135deg, #0a1628 0%, #1a2a4a 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    position: relative;
}

/* Hide default WP logo, replace with Silver Assist */
body.silver-assist-branded-login #login h1 a {
    background-image: none !important;
    width: auto;
    height: auto;
    text-indent: 0;
}

/* Custom form styling */
body.silver-assist-branded-login #loginform {
    border: none;
    box-shadow: none;
    padding: 0;
    background: transparent;
}

body.silver-assist-branded-login #loginform input[type="text"],
body.silver-assist-branded-login #loginform input[type="password"] {
    border-radius: 6px;
    padding: 12px 16px;
    font-size: 16px;
    border: 1px solid var(--silver-border-primary, #c3c4c7);
}

body.silver-assist-branded-login #loginform .button-primary {
    width: 100%;
    height: 48px;
    background: #00D1FF;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 700;
    text-transform: uppercase;
    cursor: pointer;
    transition: background 200ms ease;
}

body.silver-assist-branded-login #loginform .button-primary:hover {
    background: #00b8e6;
}

/* Responsive */
@media (max-width: 768px) {
    body.silver-assist-split-layout {
        flex-direction: column;
    }
    body.silver-assist-split-layout #login {
        width: 100%;
    }
    .silver-login-illustration-panel {
        display: none;
    }
}
```

---

## SVG Logo (Inline)

The Silver Assist logo SVG is embedded inline in `inject_login_head()` to avoid extra HTTP requests and ensure it renders immediately. The SVG uses `#00D1FF` (brand cyan) as the primary fill and white for the heart accent.

---

## Integration with Existing LoginSecurity Module

The `LoginBranding` class is **independent** from `LoginSecurity`. Both hook into `login_enqueue_scripts` but do not conflict:

- `LoginSecurity` hides "Remember Me" checkbox → still works (CSS-based)
- `LoginBranding` styles the form → respects hidden elements
- Password strength enforcement → unaffected (only on profile pages)
- Login lockout messages → styled by new CSS but logic unchanged

---

## Initialization in Plugin.php

```php
// In Plugin::init_security_components()
if ( DefaultConfig::get_option( 'silver_assist_login_branding_enabled' ) ) {
    $this->login_branding = new LoginBranding();
}
```

---

## Security Considerations

1. **SVG sanitization** — Built-in logo is hardcoded (no user-uploaded SVG risk). Custom logos use WordPress Media Library (already sanitized).
2. **CSS specificity** — All selectors scoped to `body.silver-assist-branded-login` to prevent conflicts.
3. **No inline JS** — Pure CSS layout; no script injection on login page.
4. **Escaping** — All dynamic values passed through `esc_attr()` / `esc_url()`.
5. **CSP compliance** — Inline styles limited to logo SVG; CSS loaded as external file.

---

## Testing Plan

### Unit Tests

- `LoginBrandingTest.php` — Verify hooks registered when enabled
- `LoginBrandingTest.php` — Verify hooks NOT registered when disabled
- `LoginBrandingTest.php` — Verify filter outputs (URL, text, title, classes)

### Integration Tests

- Login page renders with custom CSS enqueued
- Login page renders without illustration when setting is off
- Login/register/lost-password actions still function normally
- Responsive layout verified at breakpoints

### Manual QA

- Visual comparison: default WP login vs branded login
- Test on Chrome, Firefox, Safari
- Test mobile viewport (< 768px)
- Test with long site names
- Test with custom logo upload
- Verify login flow end-to-end (login, errors, lockout messages)

---

## Future Enhancements

- Custom background image upload for illustration panel
- Color scheme presets (dark mode, light mode)
- Custom footer links (Terms, Privacy) configurable via settings
- Registration form branding (same layout)
- Lost password page branding
- Animated illustration (Lottie/CSS)
