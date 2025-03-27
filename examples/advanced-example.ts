/**
 * Advanced Example: Full E-commerce Platform Permission System
 *
 * This example demonstrates a comprehensive setup of the RABAC library
 * for an e-commerce platform with complex role hierarchies and permission structures.
 */

import { RBACManager, RBACBuilder } from "../src";

// Define application resources and permissions as constants
// for better type safety and consistency
const RESOURCES = {
  // Core business objects
  PRODUCTS: "Products",
  ORDERS: "Orders",
  CUSTOMERS: "Customers",
  INVENTORY: "Inventory",
  PROMOTIONS: "Promotions",
  
  // Content management
  CONTENT: "Content",
  BLOG: "Blog",
  MEDIA: "Media",
  
  // Store settings
  SETTINGS: "Settings",
  USERS: "Users",
  ANALYTICS: "Analytics",
  
  // Support features
  TICKETS: "Tickets",
  REVIEWS: "Reviews",
  MESSAGES: "Messages"
};

const PERMISSIONS = {
  // Standard CRUD operations
  CREATE: "CREATE",
  READ: "READ",
  UPDATE: "UPDATE",
  DELETE: "DELETE",
  
  // Specialized actions
  VIEW: "VIEW",
  APPROVE: "APPROVE",
  REJECT: "REJECT",
  PUBLISH: "PUBLISH",
  UNPUBLISH: "UNPUBLISH",
  EXPORT: "EXPORT",
  IMPORT: "IMPORT",
  ASSIGN: "ASSIGN",
  REFUND: "REFUND",
  CANCEL: "CANCEL"
};

// Create the RBAC configuration using the fluent builder API
const builder = new RBACBuilder();

// 1. Super Admin - Has access to everything
builder
  .role("SUPER_ADMIN", "Super administrator with unrestricted access")
  .grantFullAccess(RESOURCES.PRODUCTS)
  .grantFullAccess(RESOURCES.ORDERS)
  .grantFullAccess(RESOURCES.CUSTOMERS)
  .grantFullAccess(RESOURCES.INVENTORY)
  .grantFullAccess(RESOURCES.PROMOTIONS)
  .grantFullAccess(RESOURCES.CONTENT)
  .grantFullAccess(RESOURCES.BLOG)
  .grantFullAccess(RESOURCES.MEDIA)
  .grantFullAccess(RESOURCES.SETTINGS)
  .grantFullAccess(RESOURCES.USERS)
  .grantFullAccess(RESOURCES.ANALYTICS)
  .grantFullAccess(RESOURCES.TICKETS)
  .grantFullAccess(RESOURCES.REVIEWS)
  .grantFullAccess(RESOURCES.MESSAGES);

// 2. Admin - Standard administrator with most permissions but some restrictions
builder
  .role("ADMIN", "Standard administrator")
  .grantFullAccess(RESOURCES.PRODUCTS)
  .grantFullAccess(RESOURCES.ORDERS)
  .grantFullAccess(RESOURCES.CUSTOMERS)
  .grantFullAccess(RESOURCES.INVENTORY)
  .grantFullAccess(RESOURCES.PROMOTIONS)
  .grantFullAccess(RESOURCES.CONTENT)
  .grantFullAccess(RESOURCES.BLOG)
  .grantFullAccess(RESOURCES.MEDIA)
  .forResource(RESOURCES.SETTINGS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.USERS)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE)
    .and()
  .grantFullAccess(RESOURCES.ANALYTICS)
  .grantFullAccess(RESOURCES.TICKETS)
  .grantFullAccess(RESOURCES.REVIEWS)
  .grantFullAccess(RESOURCES.MESSAGES);

// 3. Content Manager - Focused on content creation and management
builder
  .role("CONTENT_MANAGER", "Content creation and management")
  .forResource(RESOURCES.PRODUCTS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.CONTENT)
    .grantAll()
    .and()
  .forResource(RESOURCES.BLOG)
    .grantAll()
    .and()
  .forResource(RESOURCES.MEDIA)
    .grantAll()
    .and()
  .forResource(RESOURCES.PROMOTIONS)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.ANALYTICS)
    .grant(PERMISSIONS.READ, PERMISSIONS.EXPORT)
    .and()
  .forResource(RESOURCES.REVIEWS)
    .grant(PERMISSIONS.READ, PERMISSIONS.APPROVE, PERMISSIONS.REJECT)
    .and()
  .forResource(RESOURCES.MESSAGES)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE);

// 4. Sales Manager - Focused on orders and customers
builder
  .role("SALES_MANAGER", "Sales and order management")
  .forResource(RESOURCES.PRODUCTS)
    .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
    .and()
  .forResource(RESOURCES.ORDERS)
    .grantAll()
    .and()
  .forResource(RESOURCES.CUSTOMERS)
    .grantAll()
    .and()
  .forResource(RESOURCES.INVENTORY)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.PROMOTIONS)
    .grantAll()
    .and()
  .forResource(RESOURCES.ANALYTICS)
    .grant(PERMISSIONS.READ, PERMISSIONS.EXPORT)
    .and()
  .forResource(RESOURCES.TICKETS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE, PERMISSIONS.ASSIGN)
    .and()
  .forResource(RESOURCES.MESSAGES)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE);

// 5. Support Agent - Customer service and support
builder
  .role("SUPPORT_AGENT", "Customer service representative")
  .forResource(RESOURCES.PRODUCTS)
    .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
    .and()
  .forResource(RESOURCES.ORDERS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE, PERMISSIONS.CANCEL)
    .and()
  .forResource(RESOURCES.CUSTOMERS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.TICKETS)
    .grantAll()
    .and()
  .forResource(RESOURCES.REVIEWS)
    .grant(PERMISSIONS.READ)
    .and()
  .forResource(RESOURCES.MESSAGES)
    .grantAll();

// 6. Inventory Manager - Stock and product management
builder
  .role("INVENTORY_MANAGER", "Inventory and product stock management")
  .forResource(RESOURCES.PRODUCTS)
    .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.INVENTORY)
    .grantAll()
    .and()
  .forResource(RESOURCES.ORDERS)
    .grant(PERMISSIONS.READ)
    .and()
  .forResource(RESOURCES.ANALYTICS)
    .grant(PERMISSIONS.READ, PERMISSIONS.EXPORT)
    .and()
  .forResource(RESOURCES.MESSAGES)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE);

// 7. Customer - Regular authenticated user
builder
  .role("CUSTOMER", "Registered customer account")
  .forResource(RESOURCES.PRODUCTS)
    .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
    .and()
  .forResource(RESOURCES.ORDERS)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.CANCEL)
    .and()
  .forResource(RESOURCES.REVIEWS)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE, PERMISSIONS.DELETE)
    .and()
  .forResource(RESOURCES.TICKETS)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.UPDATE)
    .and()
  .forResource(RESOURCES.MESSAGES)
    .grant(PERMISSIONS.READ, PERMISSIONS.CREATE);

// Set default role
builder.setDefaultRole("CUSTOMER");

// Build the final configuration
const config = builder.build();

// Create the RBAC manager with caching enabled for production performance
const rbac = new RBACManager(config, {
  cache: {
    enabled: true,
    maxSize: 2000,
    ttl: 5 * 60 * 1000, // 5 minutes cache TTL
  },
  strict: false, // For production use, set to false to avoid throwing errors
  logger: {
    debug: (msg) => console.debug(`[RBAC] ${msg}`),
    info: (msg) => console.info(`[RBAC] ${msg}`),
    warn: (msg) => console.warn(`[RBAC] ${msg}`),
    error: (msg) => console.error(`[RBAC] ${msg}`),
  }
});

// Set up role hierarchy (inheritance)
// IMPORTANT: Each key (child role) inherits permissions from the values (parent roles)
// Example: 'CONTENT_MANAGER': ['ADMIN'] means CONTENT_MANAGER inherits from ADMIN
rbac.setRoleHierarchy({
  // SUPER_ADMIN doesn't inherit from anyone
  
  // ADMIN inherits from SUPER_ADMIN
  'ADMIN': ['SUPER_ADMIN'],
  
  // Role managers inherit from ADMIN
  'CONTENT_MANAGER': ['ADMIN'],
  'SALES_MANAGER': ['ADMIN'],
  'INVENTORY_MANAGER': ['ADMIN'],
  
  // SUPPORT_AGENT only inherits specific permissions
  'SUPPORT_AGENT': ['SALES_MANAGER'],
  
  // CUSTOMER doesn't inherit from anyone
});

// Demonstration function to test various permission scenarios
function demoPermissions() {
  console.log("=== RABAC Permissions Demonstration ===\n");

  // Example users with different roles
  const users = [
    { id: 1, name: "Alice (Super Admin)", roles: ["SUPER_ADMIN"] },
    { id: 2, name: "Bob (Admin)", roles: ["ADMIN"] },
    { id: 3, name: "Carol (Content Manager)", roles: ["CONTENT_MANAGER"] },
    { id: 4, name: "Dave (Sales Manager)", roles: ["SALES_MANAGER"] },
    { id: 5, name: "Eve (Support Agent)", roles: ["SUPPORT_AGENT"] },
    { id: 6, name: "Frank (Inventory Manager)", roles: ["INVENTORY_MANAGER"] },
    { id: 7, name: "Grace (Customer)", roles: ["CUSTOMER"] },
    { id: 8, name: "Heidi (Support + Content)", roles: ["SUPPORT_AGENT", "CONTENT_MANAGER"] },
  ];

  // Test common permission scenarios
  const scenarios = [
    {
      resource: RESOURCES.SETTINGS,
      permission: PERMISSIONS.UPDATE,
      description: "can update system settings",
    },
    {
      resource: RESOURCES.USERS,
      permission: PERMISSIONS.DELETE,
      description: "can delete user accounts",
    },
    {
      resource: RESOURCES.ORDERS,
      permission: PERMISSIONS.REFUND,
      description: "can process refunds",
    },
    {
      resource: RESOURCES.BLOG,
      permission: PERMISSIONS.PUBLISH,
      description: "can publish blog articles",
    },
    {
      resource: RESOURCES.PRODUCTS,
      permission: PERMISSIONS.CREATE,
      description: "can create new products",
    },
    {
      resource: RESOURCES.INVENTORY,
      permission: PERMISSIONS.IMPORT,
      description: "can import inventory data",
    },
  ];

  // Check permissions for each user
  for (const user of users) {
    console.log(`\n--- ${user.name} ---`);
    
    for (const scenario of scenarios) {
      const allowed = rbac.userCan(user, scenario.resource, scenario.permission);
      console.log(`- ${scenario.description}: ${allowed ? "✅ YES" : "❌ NO"}`);
    }
  }

  // Demonstrate inherited permissions through role hierarchy
  console.log("\n=== Role Hierarchy Demonstration ===\n");
  
  // Test cases to demonstrate inheritance
  const inheritanceTests = [
    {
      role: "CONTENT_MANAGER",
      resource: RESOURCES.SETTINGS,
      permission: PERMISSIONS.UPDATE,
      expected: true,
      explanation: "Content Manager inherits Settings UPDATE from Admin"
    },
    {
      role: "SALES_MANAGER",
      resource: RESOURCES.PRODUCTS,
      permission: PERMISSIONS.DELETE,
      expected: true,
      explanation: "Sales Manager inherits Products DELETE from Admin"
    },
    {
      role: "SUPPORT_AGENT",
      resource: RESOURCES.ORDERS,
      permission: PERMISSIONS.REFUND,
      expected: true,
      explanation: "Support Agent inherits Orders REFUND capability from Sales Manager"
    },
    {
      role: "CUSTOMER",
      resource: RESOURCES.SETTINGS,
      permission: PERMISSIONS.READ,
      expected: false,
      explanation: "Customer doesn't inherit from any role with Settings access"
    }
  ];
  
  for (const test of inheritanceTests) {
    const allowed = rbac.can(test.role, test.resource, test.permission);
    console.log(`${test.role} ${allowed ? "CAN" : "CANNOT"} ${test.permission} ${test.resource}`);
    console.log(`- Expected: ${test.expected ? "YES" : "NO"}`);
    console.log(`- Explanation: ${test.explanation}`);
    console.log("");
  }

  // Demonstrate dynamic permission updates
  console.log("\n=== Dynamic Permission Updates ===\n");

  // Grant new permission to Customer role
  console.log("Granting CUSTOMER role permission to EXPORT their own analytics data...");
  rbac.grant("CUSTOMER", RESOURCES.ANALYTICS, PERMISSIONS.EXPORT);

  // Check if the permission was granted
  const customerCanExport = rbac.can("CUSTOMER", RESOURCES.ANALYTICS, PERMISSIONS.EXPORT);
  console.log(`Customer can now export analytics: ${customerCanExport ? "✅ YES" : "❌ NO"}`);

  // Revoke a permission
  console.log("\nRevoking SUPPORT_AGENT permission to CANCEL orders...");
  rbac.revoke("SUPPORT_AGENT", RESOURCES.ORDERS, PERMISSIONS.CANCEL);

  // Check if the permission was revoked
  const supportCanCancelOrders = rbac.can("SUPPORT_AGENT", RESOURCES.ORDERS, PERMISSIONS.CANCEL);
  console.log(`Support Agent can cancel orders: ${supportCanCancelOrders ? "✅ YES" : "❌ NO"}`);

  // Add a new role entirely
  console.log("\nAdding a new GUEST role with minimal permissions...");
  rbac.addRole("GUEST", {
    description: "Unauthenticated visitor",
    permissions: {
      [RESOURCES.PRODUCTS]: [PERMISSIONS.READ, PERMISSIONS.VIEW],
      [RESOURCES.BLOG]: [PERMISSIONS.READ],
      [RESOURCES.REVIEWS]: [PERMISSIONS.READ]
    }
  });

  // Check new role permissions
  const guestCanReadProducts = rbac.can("GUEST", RESOURCES.PRODUCTS, PERMISSIONS.READ);
  const guestCanCreateOrders = rbac.can("GUEST", RESOURCES.ORDERS, PERMISSIONS.CREATE);
  console.log(`Guest can view products: ${guestCanReadProducts ? "✅ YES" : "❌ NO"}`);
  console.log(`Guest can create orders: ${guestCanCreateOrders ? "✅ YES" : "❌ NO"}`);
  
  // Policy evaluation example
  console.log("\n=== Policy Evaluation Example ===\n");
  
  const policy = {
    role: "INVENTORY_MANAGER",
    resource: RESOURCES.PRODUCTS,
    permission: PERMISSIONS.DELETE
  };
  
  const result = rbac.evaluatePolicy(policy);
  console.log(`Policy check result: ${result.allowed ? "ALLOWED" : "DENIED"}`);
  console.log(`Reason: ${result.reason}`);
  
  // Performance and caching statistics
  console.log("\n=== Performance Statistics ===\n");
  console.log("Cache stats:", rbac.getCacheStats());
}

// Run the demonstration
demoPermissions();

// Export for use in other modules
export { rbac, RESOURCES, PERMISSIONS };
