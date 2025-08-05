# Silver Assist Security - Translation Guide

## Overview
Silver Assist Security Plugin supports internationalization (i18n) using WordPress standard translation system. This plugin specifically addresses critical security vulnerabilities found in WordPress security assessments.

## Plugin Purpose
This plugin resolves three specific security issues commonly identified in security audits:
1. **WordPress Admin Login Page Exposure** - Brute force protection
2. **HTTPOnly Cookie Flag Missing** - XSS attack prevention
3. **GraphQL Security Misconfigurations** - DoS and introspection protection

## Available Translations
- **English (en_US)**: Default language
- **Spanish (es_ES)**: Complete translation included

## Text Domain
The plugin uses the text domain: `silver-assist-security`

## Translation Files Location
All translation files are located in: `/languages/`

## File Structure
- `silver-assist-security.pot` - Translation template (for translators)
- `silver-assist-security-es_ES.po` - Spanish translation source
- `silver-assist-security-es_ES.mo` - Spanish compiled translation

## Creating New Translations

### Step 1: Copy the POT file
```bash
cp silver-assist-security.pot silver-assist-security-[locale].po
```

### Step 2: Translate the strings
Open the `.po` file in a translation editor like:
- Poedit (recommended)
- LokaliseEditor
- Any text editor

### Step 3: Compile the translation
```bash
msgfmt silver-assist-security-[locale].po -o silver-assist-security-[locale].mo
```

## Supported Languages Examples
- Spanish (Spain): `es_ES`
- French (France): `fr_FR`
- German (Germany): `de_DE`
- Portuguese (Brazil): `pt_BR`
- Italian (Italy): `it_IT`

## Translation Functions Used
- `__()` - Basic translation
- `esc_html__()` - Translated and escaped for HTML
- `sprintf()` - For translations with placeholders

## Developer Notes
All user-facing strings in the plugin use WordPress translation functions:

```php
// Basic translation
__('Text to translate', 'silver-assist-security')

// HTML escaped translation
esc_html__('Text to translate', 'silver-assist-security')

// With placeholders
sprintf(__('Text with %s placeholder', 'silver-assist-security'), $variable)
```

## Contributing Translations
If you would like to contribute a translation:

1. Create a new `.po` file for your language
2. Translate all strings
3. Compile to `.mo` format
4. Test with your WordPress installation
5. Submit the translation files

## Testing Translations
1. Place `.mo` file in `/languages/` directory
2. Set WordPress language in `wp-config.php`:
   ```php
   define('WPLANG', 'es_ES'); // For Spanish
   ```
3. Activate the plugin
4. Verify all messages appear in your language

## Current Translatable Strings
The plugin includes translations for:
- Security audit compliance messages
- Login protection notifications
- HTTPOnly cookie status messages
- GraphQL security alerts and warnings
- Admin interface configuration options
- Security dashboard and monitoring displays

## Support
For translation support or questions, contact the Silver Assist team.
