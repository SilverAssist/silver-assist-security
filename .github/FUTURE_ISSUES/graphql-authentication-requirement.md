# feat: Add GraphQL endpoint authentication requirement option

**Priority**: Minor release (1.X.0) — Non-breaking addition  
**Labels**: `enhancement`, `security`, `graphql`

---

## Context

Based on RSM pentest audit (February 2026), the GraphQL endpoint at `/graphql` is publicly accessible. While the plugin already implements robust security controls (introspection disabled, rate limiting, query depth/complexity limits), the audit recommends adding the option to **require authentication for all queries**.

> **Audit Finding #2**: "GraphQL Endpoint Exposed to Open Internet"
> **Recommendation**: "Restrict external access to the GraphQL endpoint by requiring authentication and authorization for all queries or by disabling public access entirely if the endpoint is not intended for external use."

## Current State

The plugin currently:
- ✅ Disables introspection in production
- ✅ Implements rate limiting (30 req/min, 100 burst for headless)
- ✅ Enforces query depth limits (default: 8)
- ✅ Enforces query complexity limits (default: 100)
- ✅ Validates query patterns (aliases, directives, field duplication)
- ❌ Does NOT have an option to require authentication for all queries

WPGraphQL already has a setting `restrict_endpoint_to_authenticated_users`, which is read by `GraphQLConfigManager` but not actively enforced by our plugin.

---

## Technical Requirements

### 1. New Option

Add new WordPress option:
```php
'silver_assist_graphql_require_authentication' => false // default
```

Register in `DefaultConfig.php` with default value `false`.

### 2. GraphQLSecurity Enhancement

In `GraphQLSecurity::init()`, add a new hook to enforce authentication:

```php
\add_action( 'graphql_init', array( $this, 'enforce_authentication_requirement' ) );
```

Implement `enforce_authentication_requirement()`:
```php
public function enforce_authentication_requirement(): void {
    $require_auth = (bool) DefaultConfig::get_option('silver_assist_graphql_require_authentication');
    
    if ( ! $require_auth ) {
        return;
    }
    
    // Hook before query execution to check authentication
    \add_filter( 'graphql_request_data', array( $this, 'validate_authentication' ), 0, 5 );
}

public function validate_authentication( array $request_data, $request = null, ?string $operation_name = null, ?array $variables = null, $context = null ): array {
    // Allow introspection queries in development for tooling
    if ( defined( 'WP_ENVIRONMENT_TYPE' ) && WP_ENVIRONMENT_TYPE !== 'production' ) {
        return $request_data;
    }
    
    // Check if user is authenticated
    if ( ! is_user_logged_in() ) {
        throw new \GraphQL\Error\UserError(
            \esc_html( \__( 'Authentication required to access GraphQL endpoint.', 'silver-assist-security' ) )
        );
    }
    
    return $request_data;
}
```

### 3. GraphQLConfigManager Enhancement

Add method to check authentication requirement:
```php
public function is_authentication_required(): bool {
    // Check our plugin setting first
    $our_setting = (bool) DefaultConfig::get_option('silver_assist_graphql_require_authentication');
    
    // Also check WPGraphQL native setting
    $wpgraphql_setting = $this->get_wpgraphql_setting('restrict_endpoint_to_authenticated_users', 'off') === 'on';
    
    // Either setting being enabled should enforce authentication
    return $our_setting || $wpgraphql_setting;
}
```

### 4. Admin Panel UI

Add toggle in the GraphQL Security tab:
- Label: "Require Authentication"
- Description: "When enabled, all GraphQL queries will require a logged-in user. Useful for private/internal APIs."
- Warning: "⚠️ Enabling this will break public GraphQL access for frontend applications like Gatsby or Next.js unless they use authenticated requests."

### 5. Coordination with WPGraphQL

If WPGraphQL's `restrict_endpoint_to_authenticated_users` is already enabled, show a notice:
> "WPGraphQL authentication restriction is already enabled. Silver Assist Security is coordinating with this setting."

### 6. Dashboard Indicator

Update `DashboardRenderer` to show authentication status:
- 🔒 "Authentication Required" (when enabled)
- 🌐 "Public Access" (when disabled)

---

## Testing Requirements

- [ ] Unit test for `is_authentication_required()` method
- [ ] Unit test for `enforce_authentication_requirement()` hook
- [ ] Integration test verifying unauthenticated requests are blocked when enabled
- [ ] Integration test verifying authenticated requests pass through
- [ ] Test coordination with WPGraphQL native setting
