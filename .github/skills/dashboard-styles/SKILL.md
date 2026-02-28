---
name: dashboard-styles
description: Silver Assist Security dashboard CSS styles, component classes, status indicators, and UI patterns. Use when creating or modifying dashboard cards, status badges, feature indicators, statistics displays, or any admin panel UI component.
---

# Silver Assist Security - Dashboard Styles Guide

This skill defines the CSS classes and HTML patterns for the Security Dashboard UI components.

## CSS Architecture

The plugin uses a **CSS Layers** approach with **CSS Custom Properties** (variables). All styles are scoped within the `@layer components` layer.

### Key Files
- [variables.css](../../../assets/css/variables.css) - CSS custom properties (colors, spacing, typography)
- [admin.css](../../../assets/css/admin.css) - Component styles

---

## Status Indicator Classes

Use `.status-indicator` with one of these modifier classes:

| Class | Purpose | Visual |
|-------|---------|--------|
| `.status-indicator.active` | Feature is enabled/working | ✅ Green pill badge |
| `.status-indicator.inactive` | Feature is disabled/not available | ❌ Red pill badge |
| `.status-indicator.warning` | Feature needs attention | ⚠️ Yellow pill badge |

> **Note:** Always use `.inactive` for disabled states on status indicators. Do not use `.disabled` as an alias.

### HTML Example
```html
<span class="status-indicator active">Active</span>
<span class="status-indicator inactive">Inactive</span>
<span class="status-indicator warning">Warning</span>
```

### PHP Example
```php
<span class="status-indicator <?php echo $is_active ? 'active' : 'inactive'; ?>">
    <?php echo $is_active ? esc_html__('Active', 'silver-assist-security') : esc_html__('Inactive', 'silver-assist-security'); ?>
</span>
```

---

## Status Cards

Cards are the primary container for dashboard sections.

### Structure
```html
<div class="status-card {card-type}">
    <div class="card-header">
        <span class="dashicons dashicons-{icon}"></span>
        <h3>Card Title</h3>
        <span class="status-indicator active">Active</span>
    </div>
    <div class="card-content">
        <!-- Content goes here -->
    </div>
</div>
```

### Card Type Classes
- `.status-card.login-security` - Login protection card
- `.status-card.graphql-security` - GraphQL security card
- `.status-card.general-security` - General security card
- `.status-card.admin-security` - Admin security card
- `.status-card.cf7-security` - Contact Form 7 card

---

## Feature Status Display

Use for showing enabled/disabled features within cards. **Two patterns available:**

### Pattern 1: Inline Feature Status (Recommended for simple lists)
```html
<span class="feature-status enabled">HTTPOnly Cookies</span>
<span class="feature-status disabled">SSL/HTTPS</span>
```

Creates a colored text with ✓ or ✗ prefix automatically via CSS `::before`.

### Pattern 2: Name + Value (Recommended for detailed displays)
```html
<div class="feature-status">
    <span class="feature-name">HTTPOnly Cookies</span>
    <span class="feature-value enabled">Enabled</span>
</div>
```

Creates a row with label on left and colored badge on right.

### CSS Classes Reference

| Class | Purpose |
|-------|---------|
| `.feature-status` | Container for feature row |
| `.feature-status.enabled` | Green text with ✓ prefix |
| `.feature-status.disabled` | Red text with ✗ prefix |
| `.feature-name` | Label text (left side) |
| `.feature-value` | Badge container |
| `.feature-value.enabled` | Green background badge |
| `.feature-value.disabled` | Red background badge |

---

## Statistics Display

For numeric statistics with labels.

### Structure
```html
<div class="stat">
    <span class="stat-value">5</span>
    <span class="stat-label">Max Attempts</span>
</div>
```

### Alternative: Large Stat Card
```html
<div class="status-card">
    <div class="stat-value" id="blocked-ips-count">0</div>
    <div class="stat-label">Blocked IPs</div>
</div>
```

---

## Dashboard Grid

Wrap cards in `.silver-stats-grid` for responsive grid layout:

```html
<div class="silver-stats-grid">
    <div class="status-card">...</div>
    <div class="status-card">...</div>
    <div class="status-card">...</div>
</div>
```

Automatically creates responsive columns with `minmax(280px, 1fr)`.

---

## Complete Card Example

```html
<div class="status-card login-security">
    <div class="card-header">
        <span class="dashicons dashicons-lock"></span>
        <h3>Login Security</h3>
        <span class="status-indicator active">Active</span>
    </div>
    <div class="card-content">
        <div class="stat">
            <span class="stat-value">5</span>
            <span class="stat-label">Max Attempts</span>
        </div>
        <div class="stat">
            <span class="stat-value">0</span>
            <span class="stat-label">Blocked IPs</span>
        </div>
        <div class="stat">
            <span class="stat-value">15</span>
            <span class="stat-label">Lockout (min)</span>
        </div>
    </div>
</div>
```

---

## Activity Tabs (Tabbed Content within Cards)

For content with multiple views (e.g., Blocked IPs / Security Logs), use `.activity-tabs` inside a `.status-card`:

```html
<div class="status-card recent-activity-section">
    <div class="card-header">
        <h3>Recent Security Activity</h3>
    </div>
    <div class="card-content">
        <div class="activity-tabs">
            <button class="activity-tab active" data-tab="blocked-ips">
                <span class="dashicons dashicons-dismiss"></span>
                Blocked IPs
            </button>
            <button class="activity-tab" data-tab="security-logs">
                <span class="dashicons dashicons-list-view"></span>
                Security Logs
            </button>
        </div>

        <div id="blocked-ips-content" class="activity-content active">
            <!-- Tab content here -->
        </div>

        <div id="security-logs-content" class="activity-content">
            <!-- Tab content here -->
        </div>
    </div>
</div>
```

### Activity Tab Classes

| Class | Purpose |
|-------|---------|
| `.activity-tabs` | Tab bar container with bottom border |
| `.activity-tab` | Individual tab button |
| `.activity-tab.active` | Selected tab (blue underline) |
| `.activity-content` | Tab panel (hidden by default) |
| `.activity-content.active` | Visible tab panel |

### Loading States

Use `.loading-spinner` + `.loading-text` for async content:

```html
<div class="loading-spinner"></div>
<p class="loading-text">Loading data...</p>
```

---

## CSS Variables Used

### Colors
- `--silver-success-bg-light`, `--silver-success-text`, `--silver-success-border-light` - Green/active states
- `--silver-error-bg-light`, `--silver-error-text`, `--silver-error-border-light` - Red/inactive states  
- `--silver-warning-bg-light`, `--silver-warning-text`, `--silver-warning-border` - Yellow/warning states
- `--silver-primary-blue` - Primary accent color

### Spacing
- `--silver-spacing-xs`, `--silver-spacing-sm`, `--silver-spacing-md`, `--silver-spacing-lg`, `--silver-spacing-xl`

### Typography
- `--silver-font-size-sm`, `--silver-font-size-base`, `--silver-font-size-xl`, `--silver-font-size-2xl`
- `--silver-font-weight-semibold`, `--silver-font-weight-bold`

---

## Do's and Don'ts

### ✅ DO
- Use `.status-indicator` with `.active`, `.inactive`, or `.warning`
- Use `.feature-value` with `.enabled` or `.disabled` for badges
- Use `.stat-value` + `.stat-label` for numeric statistics
- Wrap cards in `.silver-stats-grid` for responsive layout

### ❌ DON'T
- Don't create new status classes - use existing ones
- Don't use `.disabled` and `.inactive` interchangeably on different element types
- Don't inline color styles - use CSS variables
- Don't skip the `.card-header` and `.card-content` structure
