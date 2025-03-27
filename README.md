# @anishpras/rbac: Role and Attribute Based Access Control

A fast, flexible, and production-ready role-based access control (RBAC) system for JavaScript/TypeScript applications.

## Features

- 🚀 **Fast and efficient**: Optimized for speed with LRU caching
- 🔒 **Type-safe**: Full TypeScript support
- 🧩 **Flexible**: Define custom roles, resources, and permissions
- 🔄 **Role hierarchy**: Support for role inheritance
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
    .grantFullAccess('AdditionalServices')
    .grantFullAccess('Locations')
    .done()
  .role('EDITOR', 'Editor with limited access')
    .forResource('Products').grantAll().and()
    .forResource('News').grantAll().and()
    .forResource('Bookings').grantReadOnly().and()
    .forResource('AdditionalServices').grantAll().and()
    .forResource('Locations').grantReadOnly().done()
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
```

## Working with Role Hierarchies

```typescript
// Define role hierarchy
rbac.setRoleHierarchy({
  'EDITOR': ['ADMIN'],  // EDITOR inherits all permissions from ADMIN
  'VIEWER': ['EDITOR']  // VIEWER inherits all permissions from EDITOR
});

// Now EDITOR inherits all permissions from ADMIN,
// and VIEWER inherits permissions from both EDITOR and ADMIN (transitively)
```

**Important Note on Role Hierarchy**: When setting up hierarchy, specify which role inherits from which. In the example above, `'EDITOR': ['ADMIN']` means that EDITOR inherits permissions from ADMIN, not that ADMIN inherits from EDITOR. This is effectively a parent-child relationship where the child is the key and the parents are in the array.

## Dynamic Permission Updates

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
```

## Best Practices

1. **Use Non-strict Mode in Production**: Set `strict: false` in production to prevent throwing errors for undefined roles or resources, which could cause service disruptions.

2. **Enable Caching**: Always use caching in production for better performance, but be aware of the memory usage implications.

3. **Clear Cache After Updates**: Always call `clearCache()` after making permission changes, or simply use the built-in methods like `grant()` and `revoke()` which handle this automatically.

4. **Properly Set Up Role Hierarchy**: Remember that in the hierarchy object, the key is the child role and the array values are parent roles (e.g., `{'EDITOR': ['ADMIN']}` means EDITOR inherits from ADMIN).

5. **Use Custom Logger**: Configure a custom logger to integrate with your application's logging system.

6. **Isolate Permission Checks**: For high-security areas, consider using isolated permission checks rather than role-based checks for more granular control.

7. **Regular Permission Audits**: Implement a system to audit and review permissions regularly, especially for sensitive resources.

8. **Implement Resource Ownership**: For multi-tenant systems, combine RBAC with resource ownership checks for additional security.

## Security Features

This package includes security-focused features to protect your application's permission system:

1. **Input Validation**: All role, resource, and permission inputs are validated to prevent injection attacks and manipulation.

2. **Circular Reference Detection**: Automatic detection and prevention of circular references in role hierarchies.

3. **Default Deny**: The system always defaults to denying access when errors occur or when roles/permissions are undefined.

4. **Deep Cloning**: All configuration objects are deep-cloned to prevent external mutation attacks.

5. **Protected Cache Keys**: The caching system uses sanitized keys and secret salts to prevent cache poisoning.

6. **Secure Middleware**: The Express middleware is designed to securely handle errors and always default to access denial.

7. **Audit Logging**: Built-in audit logging for critical permission changes and access attempts.

8. **Type Safety**: TypeScript types enforce proper structure and prevent common mistakes.

9. **Race Condition Protection**: Special handling to prevent race conditions during permission updates.

10. **Secure Error Handling**: Error messages are designed to avoid leaking sensitive information.

### Recommended Security Configuration

```typescript
// Create a secure RBAC manager
const rbac = new RBACManager(config, {
  cache: {
    enabled: true,
    maxSize: 1000,
    ttl: 30 * 60 * 1000  // 30 minute TTL
  },
  strict: true,  // In development: fails fast on errors
  logger: {
    debug: (msg, ...args) => console.debug(`[RBAC] ${msg}`, ...args),
    info: (msg, ...args) => console.info(`[RBAC] ${msg}`, ...args),
    warn: (msg, ...args) => console.warn(`[RBAC] ${msg}`, ...args),
    error: (msg, ...args) => console.error(`[RBAC] ${msg}`, ...args)
  }
});

// Use secure middleware with audit logging
app.get(
  '/api/sensitive-data',
  rbac.middleware({
    getUserRoles: (req) => req.user.roles,
    resource: 'SensitiveData',
    permission: 'READ',
    auditLog: true,  // Enable audit logging for sensitive operations
    onDenied: (req, res) => {
      // Log the denial but don't expose details
      console.warn(`Access denied for user ${req.user.id}`);
      res.status(403).json({ error: 'Access denied' });
    }
  }),
  (req, res) => {
    // Handle the request
  }
);
```

### Security Hardening Recommendations

1. **Use Predefined Constants**: Instead of using arbitrary strings for roles, resources, and permissions, define constants:

```typescript
// Define constants for roles, resources, and permissions
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

2. **Regular Security Audits**: Implement periodic reviews of your role hierarchies and permission assignments.

3. **Principle of Least Privilege**: Assign the minimum permissions necessary for each role.

4. **Permission Approval Workflow**: For sensitive permissions, implement a multi-step approval process.

5. **Limit Admin Roles**: Restrict the number of users with administrative privileges.

6. **Protect Against Privilege Escalation**: Be careful with dynamic role assignment to prevent unauthorized elevation of privileges.


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
# rbac
