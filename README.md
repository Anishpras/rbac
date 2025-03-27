# @anishpras/rbac: Role and Attribute Based Access Control

A fast, flexible, and production-ready role-based access control (RBAC) system for JavaScript/TypeScript applications.

## Features

- 🚀 **Fast and efficient**: Optimized for speed with LRU caching
- 🔒 **Type-safe**: Full TypeScript support
- 🧩 **Flexible**: Define custom roles, resources, and permissions
- 🔄 **Role hierarchy**: Support for role inheritance with robust cycle detection
- 🛠️ **Middleware support**: Ready for Express.js and other frameworks
- 📝 **Fluent API**: Intuitive builder pattern for configuration
- 📊 **Runtime updates**: Modify permissions without restarting
- 🧪 **Strict mode**: Optional throw on unrecognized roles/resources
- 📈 **Scalable**: Designed for large-scale applications

## Installation

```bash
npm install @anishpras/rbac
# or
yarn add @anishpras/rbac
# or
pnpm add @anishpras/rbac
```

## Quick Start

```typescript
import { RBACManager, RBACBuilder } from '@anishpras/rbac';

// Create a configuration using the builder
const config = new RBACBuilder()
  .role('ADMIN', 'Administrator with full access')
    .grantFullAccess('Products')
    .grantFullAccess('News')
    .grantFullAccess('Bookings')
    .done()
  .role('EDITOR', 'Editor with limited access')
    .forResource('Products').grantAll().and()
    .forResource('News').grantAll().and()
    .forResource('Bookings').grantReadOnly().done()
  .setDefaultRole('EDITOR')
  .build();

// Create the RBAC manager
const rbac = new RBACManager(config, {
  cache: {
    enabled: true,
    maxSize: 1000,
    ttl: 60 * 1000 // 1 minute
  },
  strict: false, // Avoid runtime errors in production
  logger: {
    debug: (msg) => console.debug(`[RBAC] ${msg}`),
    info: (msg) => console.info(`[RBAC] ${msg}`),
    warn: (msg) => console.warn(`[RBAC] ${msg}`),
    error: (msg) => console.error(`[RBAC] ${msg}`)
  }
});

// Check permissions
const user = {
  id: 1,
  roles: ['EDITOR']
};

// Check if a user can create a product
if (rbac.userCan(user, 'Products', 'CREATE')) {
  // User can create products
}

// Check if a user can update a booking
if (rbac.userCan(user, 'Bookings', 'UPDATE')) {
  // User cannot update bookings
}
```

## Express.js Middleware Example

```typescript
import express from 'express';
import { RBACManager } from '@anishpras/rbac';

const app = express();
const rbac = new RBACManager(config);

// Middleware to protect routes
app.get(
  '/api/products',
  rbac.middleware({
    getUserRoles: (req) => req.user.roles,
    resource: 'Products',
    permission: 'READ',
    onDenied: (req, res) => {
      res.status(403).json({ error: 'Access denied' });
    }
  }),
  (req, res) => {
    // Handle the request
  }
);

// Dynamic permission based on HTTP method
app.all(
  '/api/bookings/:id',
  rbac.middleware({
    getUserRoles: (req) => req.user.roles,
    resource: 'Bookings',
    permission: (req) => {
      // Map HTTP method to permission
      switch (req.method) {
        case 'GET': return 'READ';
        case 'POST': return 'CREATE';
        case 'PUT': case 'PATCH': return 'UPDATE';
        case 'DELETE': return 'DELETE';
        default: return 'READ';
      }
    },
    onDenied: (req, res) => {
      res.status(403).json({ 
        error: 'Access denied',
        message: `You don't have permission to ${req.method} bookings` 
      });
    }
  }),
  (req, res) => {
    // Handle the request
  }
);
```

## Understanding Role Hierarchy (Role Inheritance)

The role hierarchy feature allows roles to inherit permissions from other roles. This is one of the most powerful but sometimes confusing aspects of the library.

```typescript
// Define role hierarchy
rbac.setRoleHierarchy({
  'EDITOR': ['ADMIN'],  // EDITOR inherits all permissions from ADMIN
  'VIEWER': ['EDITOR']  // VIEWER inherits all permissions from EDITOR
});
```

**Important Clarification on Role Hierarchy**: 

In the role hierarchy configuration:
- The `key` is the **child role** (the one inheriting permissions)
- The `array values` are the **parent roles** (the ones being inherited from)

This means:
- `'EDITOR': ['ADMIN']` means that EDITOR inherits permissions from ADMIN, not the other way around
- `'VIEWER': ['EDITOR']` means VIEWER inherits from EDITOR (and transitively from ADMIN too)

Think of it like this:
```
'CHILD_ROLE': ['PARENT_ROLE_1', 'PARENT_ROLE_2']
```

Let's look at a more complete example to illustrate how role hierarchy works:

```typescript
// Define role hierarchy with more complex relationships
rbac.setRoleHierarchy({
  // Store roles inherit from more general roles
  'STORE_MANAGER': ['ADMIN'],      // Store Manager inherits from Admin
  'STORE_CLERK': ['STORE_MANAGER'], // Store Clerk inherits from Store Manager
  
  // Content roles also inherit
  'CONTENT_EDITOR': ['ADMIN'],     // Content Editor inherits from Admin
  'CONTENT_VIEWER': ['CONTENT_EDITOR'], // Content Viewer inherits from Content Editor
  
  // Special case: dual inheritance
  'SUPERVISOR': ['STORE_MANAGER', 'CONTENT_EDITOR'] // Inherits from both roles
});

// Let's test some permissions
console.log(rbac.can('STORE_CLERK', 'Products', 'READ')); // true if STORE_MANAGER has this permission
console.log(rbac.can('SUPERVISOR', 'Content', 'PUBLISH')); // true if either parent role has this permission
```

The library automatically handles transitive inheritance and detects circular references to prevent infinite loops.

## Dynamic Permission Updates

You can modify permissions at runtime without restarting your application:

```typescript
// Add a new role
rbac.addRole('MANAGER', {
  description: 'Manager role',
  permissions: {
    'Products': ['READ', 'UPDATE'],
    'Bookings': ['READ', 'UPDATE', 'CREATE']
  }
});

// Grant new permissions
rbac.grant('EDITOR', 'Reports', ['READ']);

// Revoke permissions
rbac.revoke('EDITOR', 'Bookings', ['DELETE']);

// Revoke all permissions on a resource
rbac.revoke('EDITOR', 'Bookings');

// Remove a role entirely
rbac.removeRole('GUEST');

// Update the entire configuration
rbac.updateConfig(newConfig);
```

Remember to clear the cache after making permission changes (the built-in methods like `grant()` and `revoke()` handle this automatically):

```typescript
// Manually clear the cache when needed
rbac.clearCache();
```

## Policy Evaluation

You can evaluate policies directly:

```typescript
const policyResult = rbac.evaluatePolicy({
  role: 'EDITOR',
  resource: 'Products',
  permission: 'UPDATE'
});

console.log(policyResult.allowed); // boolean
console.log(policyResult.reason);  // explanation string
```

## Query Available Permissions and Resources

```typescript
// Get all permissions a role has on a resource
const permissions = rbac.getPermissions('EDITOR', 'Products');
// Returns: ['CREATE', 'READ', 'UPDATE', 'DELETE']

// Get all resources a role has access to
const resources = rbac.getResources('ADMIN');
// Returns: ['Products', 'News', 'Bookings', ...]

// Get all roles in the system
const roles = rbac.getRoles();
// Returns: ['ADMIN', 'EDITOR', 'VIEWER', ...]

// Get cache statistics
const cacheStats = rbac.getCacheStats();
// Returns: { enabled: true, size: 42 }
```

## Best Practices

### 1. Use Constants for Roles, Resources and Permissions

Define constants to prevent typos and ensure consistency:

```typescript
// Define constants
const ROLES = {
  ADMIN: 'ADMIN',
  EDITOR: 'EDITOR',
  VIEWER: 'VIEWER'
} as const;

const RESOURCES = {
  PRODUCTS: 'Products',
  USERS: 'Users',
  ORDERS: 'Orders'
} as const;

const PERMISSIONS = {
  CREATE: 'CREATE',
  READ: 'READ',
  UPDATE: 'UPDATE',
  DELETE: 'DELETE'
} as const;

// Use constants in your code
rbac.grant(ROLES.EDITOR, RESOURCES.PRODUCTS, [PERMISSIONS.READ, PERMISSIONS.UPDATE]);
```

### 2. Non-strict Mode in Production

Set `strict: false` in production to prevent throwing errors for undefined roles or resources. This prevents service disruptions if a role is referenced that doesn't exist.

```typescript
const rbac = new RBACManager(config, {
  strict: process.env.NODE_ENV === 'development'
});
```

### 3. Enable Caching

Always use caching in production for better performance:

```typescript
const rbac = new RBACManager(config, {
  cache: {
    enabled: true,
    maxSize: 1000, // Limit cache size to prevent memory issues
    ttl: 5 * 60 * 1000 // Cache TTL of 5 minutes
  }
});
```

### 4. Properly Set Up Role Hierarchy

Remember that in the hierarchy object:
- The key is the child role (the one inheriting permissions)  
- The array values are parent roles (the ones being inherited from)

```typescript
// CORRECT:
rbac.setRoleHierarchy({
  'EDITOR': ['ADMIN'], // EDITOR inherits from ADMIN
});

// INCORRECT (would mean ADMIN inherits from EDITOR):
rbac.setRoleHierarchy({
  'ADMIN': ['EDITOR']
});
```

### 5. Use Custom Logger

Configure a custom logger to integrate with your application's logging system:

```typescript
const rbac = new RBACManager(config, {
  logger: {
    debug: (msg) => myLogger.debug(`[RBAC] ${msg}`),
    info: (msg) => myLogger.info(`[RBAC] ${msg}`),
    warn: (msg) => myLogger.warn(`[RBAC] ${msg}`),
    error: (msg) => myLogger.error(`[RBAC] ${msg}`)
  }
});
```

### 6. Implement Resource Ownership

For multi-tenant systems, combine RBAC with resource ownership checks:

```typescript
// Middleware to check both permissions and ownership
const checkPermissionAndOwnership = (req, res, next) => {
  const resourceId = req.params.id;
  const userId = req.user.id;
  
  // First check RBAC permissions
  if (!rbac.userCan(req.user, 'Orders', 'UPDATE')) {
    return res.status(403).json({ error: 'Permission denied' });
  }
  
  // Then check ownership
  orderService.getOrderById(resourceId)
    .then(order => {
      if (order.userId !== userId) {
        return res.status(403).json({ error: 'Not your order' });
      }
      next();
    });
};
```

## Security Features

This package includes security-focused features to protect your application's permission system:

1. **Input Validation**: All role, resource, and permission inputs are validated to prevent injection attacks and manipulation.

2. **Circular Reference Detection**: Automatic detection and prevention of circular references in role hierarchies.

3. **Default Deny**: The system always defaults to denying access when errors occur or when roles/permissions are undefined.

4. **Deep Cloning**: All configuration objects are deep-cloned to prevent external mutation attacks.

5. **Protected Cache Keys**: The caching system uses sanitized keys to prevent cache poisoning.

6. **Secure Middleware**: The Express middleware is designed to securely handle errors and always default to access denial.

7. **Audit Logging**: Built-in audit logging for critical permission changes and access attempts.

8. **Type Safety**: TypeScript types enforce proper structure and prevent common mistakes.

9. **Race Condition Protection**: Special handling to prevent race conditions during permission updates.

10. **Secure Error Handling**: Error messages are designed to avoid leaking sensitive information.

## Advanced Examples

For more advanced usage examples, check the `examples` directory in the repository:

- `product-shop.ts`: Basic e-commerce example with standard roles
- `express-integration.ts`: Example integration with Express.js middleware
- `advanced-example.ts`: Complex role hierarchy with comprehensive permissions

## API Reference

### RBACManager

The main class for managing RBAC functionality.

```typescript
// Create a new instance
const rbac = new RBACManager(config, options);

// Check if a role has permission
rbac.can(role, resource, permission);

// Check if a user has permission
rbac.userCan(user, resource, permission);

// Set role hierarchy
rbac.setRoleHierarchy(hierarchy);

// Update configuration
rbac.updateConfig(config);

// Add a new role
rbac.addRole(role, definition);

// Remove a role
rbac.removeRole(role);

// Grant permissions
rbac.grant(role, resource, permission);

// Revoke permissions
rbac.revoke(role, resource, permission);

// Evaluate a policy
rbac.evaluatePolicy(policy);

// Get permissions for a role on a resource
rbac.getPermissions(role, resource);

// Get all resources a role has access to
rbac.getResources(role);

// Get all roles
rbac.getRoles();

// Get the complete configuration
rbac.getConfig();

// Clear the permission cache
rbac.clearCache();

// Get cache statistics
rbac.getCacheStats();

// Create middleware
rbac.middleware(options);
```

### RBACBuilder

A fluent API for building RBAC configurations.

```typescript
// Create a new builder
const builder = new RBACBuilder();

// Define roles and permissions
builder
  .role('ADMIN')
    .grantFullAccess('Products')
    .done()
  .role('EDITOR')
    .forResource('Products').grant('READ', 'UPDATE').and()
    .forResource('News').grantAll().done()
  .setDefaultRole('EDITOR');

// Build the configuration
const config = builder.build();
```

## License

MIT