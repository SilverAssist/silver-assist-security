# CodeQL Custom Queries for WordPress Security

This directory contains custom CodeQL queries specifically designed to validate WordPress security best practices.

## 📋 Implemented Queries

### 1. **Missing Nonce Verification** (`missing-nonce.ql`)

- **Severity**: Error (8.0/10)
- **Detects**: WordPress AJAX handlers without nonce verification
- **Prevents**: CSRF (Cross-Site Request Forgery) attacks
- **Example**:
  ```php
  // ❌ INCORRECTO
  add_action('wp_ajax_my_action', 'my_ajax_handler');
  function my_ajax_handler() {
      // Sin wp_verify_nonce()
  }
  
  // ✅ CORRECTO
  add_action('wp_ajax_my_action', 'my_ajax_handler');
  function my_ajax_handler() {
      check_ajax_referer('my_nonce_action', 'security');
      // o wp_verify_nonce($_POST['nonce'], 'my_nonce_action')
  }
  ```

### 2. **Unescaped Output** (`unescaped-output.ql`)

- **Severity**: Warning (7.0/10)
- **Detects**: Output without escaping in echo/print statements
- **Prevents**: XSS (Cross-Site Scripting) attacks
- **Example**:

  ```php
  // ❌ INCORRECTO
  echo $user_input;
  echo "<div>" . $data . "</div>";
  
  // ✅ CORRECTO
  echo esc_html($user_input);
  echo "<div>" . esc_html($data) . "</div>";
  echo '<a href="' . esc_url($link) . '">' . esc_html($text) . '</a>';
  ```

### 3. **Missing Capability Check** (`missing-capability-check.ql`)

- **Severity**: Error (8.5/10)
- **Detects**: Admin pages without capability verification
- **Prevents**: Unauthorized access to admin functions
- **Example**:

  ```php
  // ❌ INCORRECTO
  add_menu_page('My Plugin', 'My Plugin', 'manage_options', 'my-plugin');
  function my_plugin_page() {
      // Sin current_user_can()
  }
  
  // ✅ CORRECTO
  function my_plugin_page() {
      if (!current_user_can('manage_options')) {
          wp_die(__('You do not have sufficient permissions'));
      }
      // Contenido de la página
  }
  ```

## 🔧 Configuration

The queries run automatically on every:

- Push to `main` or `develop`
- Pull Request to `main`
- Weekly scheduled analysis (Mondays at 2:30 AM UTC)

### Workflow Configuration

The `.github/codeql/codeql-config.yml` file configures:

- Custom WordPress queries
- `security-extended` suite (additional security queries)
- `security-and-quality` suite (security + code quality)

## 📊 Niveles de Severidad

| Nivel | Severidad | Acción |
|-------|-----------|--------|
| Error | 8.0+ | ❌ Debe corregirse antes de merge |
| Warning | 6.0-7.9 | ⚠️ Revisión recomendada |
| Note | < 6.0 | ℹ️ Informativo |

## 🚀 Planned Additional Queries

### Phase 2

- [ ] SQL injection detection in custom queries
- [ ] Input sanitization validation (`$_GET`, `$_POST`, `$_REQUEST`)
- [ ] File upload validation detection
- [ ] Correct usage verification of `wp_remote_get()` vs `file_get_contents()`

### Phase 3

- [ ] File permissions analysis
- [ ] Hardcoded secrets detection (API keys, passwords)
- [ ] WordPress transients and options validation
- [ ] WordPress hooks and filters analysis

## 📚 Referencias

- [CodeQL for PHP](https://codeql.github.com/docs/codeql-language-guides/codeql-for-php/)
- [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/)
- [WordPress Security Best Practices](https://developer.wordpress.org/apis/security/)
- [CodeQL Query Writing](https://codeql.github.com/docs/writing-codeql-queries/)

## 🤝 Contributing

To add new queries:

1. Create a `.ql` file in `.github/codeql/custom-queries/`
2. Follow the format of existing queries
3. Add documentation with `@name`, `@description`, `@security-severity`
4. Update `codeql-config.yml` if necessary
5. Test locally with CodeQL CLI
6. Create a Pull Request

## 🔍 Local Testing

```bash
# Install CodeQL CLI
brew install codeql

# Create database
codeql database create wordpress-db --language=php

# Run specific query
codeql query run .github/codeql/custom-queries/missing-nonce.ql \
  --database=wordpress-db

# View results
codeql bqrs decode results.bqrs --format=sarif-latest
```

---

**Maintainer**: Silver Assist Security Team  
**Last Updated**: November 2025
