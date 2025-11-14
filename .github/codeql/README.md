# CodeQL Custom Queries for WordPress Security

Este directorio contiene queries personalizadas de CodeQL específicas para validar las mejores prácticas de seguridad en WordPress.

## 📋 Queries Implementadas

### 1. **Missing Nonce Verification** (`missing-nonce.ql`)
- **Severidad**: Error (8.0/10)
- **Detecta**: Handlers AJAX de WordPress sin verificación de nonce
- **Previene**: Ataques CSRF (Cross-Site Request Forgery)
- **Ejemplo**:
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
- **Severidad**: Warning (7.0/10)
- **Detecta**: Output sin escape en echo/print
- **Previene**: Ataques XSS (Cross-Site Scripting)
- **Ejemplo**:
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
- **Severidad**: Error (8.5/10)
- **Detecta**: Páginas de admin sin verificación de capacidades
- **Previene**: Acceso no autorizado a funciones de administración
- **Ejemplo**:
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

## 🔧 Configuración

Las queries se ejecutan automáticamente en cada:
- Push a `main` o `develop`
- Pull Request a `main`
- Análisis semanal programado (Lunes 2:30 AM UTC)

### Configuración del Workflow

El archivo `.github/codeql/codeql-config.yml` configura:
- Queries personalizadas de WordPress
- Suite `security-extended` (queries adicionales de seguridad)
- Suite `security-and-quality` (seguridad + calidad de código)

## 📊 Niveles de Severidad

| Nivel | Severidad | Acción |
|-------|-----------|--------|
| Error | 8.0+ | ❌ Debe corregirse antes de merge |
| Warning | 6.0-7.9 | ⚠️ Revisión recomendada |
| Note | < 6.0 | ℹ️ Informativo |

## 🚀 Queries Adicionales Planificadas

### Fase 2:
- [ ] Detección de SQL injection en queries personalizadas
- [ ] Validación de sanitización de inputs (`$_GET`, `$_POST`, `$_REQUEST`)
- [ ] Detección de archivos subidos sin validación
- [ ] Verificación de uso correcto de `wp_remote_get()` vs `file_get_contents()`

### Fase 3:
- [ ] Análisis de permisos de archivos
- [ ] Detección de secrets hardcodeados (API keys, passwords)
- [ ] Validación de transients y opciones de WordPress
- [ ] Análisis de hooks y filters de WordPress

## 📚 Referencias

- [CodeQL for PHP](https://codeql.github.com/docs/codeql-language-guides/codeql-for-php/)
- [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/)
- [WordPress Security Best Practices](https://developer.wordpress.org/apis/security/)
- [CodeQL Query Writing](https://codeql.github.com/docs/writing-codeql-queries/)

## 🤝 Contribuir

Para agregar nuevas queries:
1. Crear archivo `.ql` en `.github/codeql/custom-queries/`
2. Seguir el formato de queries existentes
3. Agregar documentación con `@name`, `@description`, `@security-severity`
4. Actualizar `codeql-config.yml` si es necesario
5. Probar localmente con CodeQL CLI
6. Crear Pull Request

## 🔍 Testing Local

```bash
# Instalar CodeQL CLI
brew install codeql

# Crear database
codeql database create wordpress-db --language=php

# Ejecutar query específica
codeql query run .github/codeql/custom-queries/missing-nonce.ql \
  --database=wordpress-db

# Ver resultados
codeql bqrs decode results.bqrs --format=sarif-latest
```

---

**Mantenedor**: Silver Assist Security Team  
**Última actualización**: Noviembre 2025
