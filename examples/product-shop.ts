/**
 * Example: E-commerce platform selling products
 *
 * This example demonstrates how to set up RBAC for a product sales platform
 * with different user roles and permissions.
 */

import { RBACManager, RBACBuilder } from "../src";

// Define the modules (resources) in our application
const RESOURCES = {
  PRODUCTS: "Products",
  NEWS: "News",
  BOOKINGS: "Bookings",
  ADDITIONAL_SERVICES: "AdditionalServices",
  LOCATIONS: "Locations",
  USERS: "Users",
  REPORTS: "Reports",
  SETTINGS: "Settings",
};

// Define the permission types
const PERMISSIONS = {
  CREATE: "CREATE",
  READ: "READ",
  UPDATE: "UPDATE",
  DELETE: "DELETE",
  VIEW: "VIEW",
  APPROVE: "APPROVE",
  REJECT: "REJECT",
  PUBLISH: "PUBLISH",
  EXPORT: "EXPORT",
};

// Build the RBAC configuration using the fluent builder API
const builder = new RBACBuilder();

// Configure ADMIN role - has access to everything
builder
  .role("ADMIN", "Administrator with full access")
  .grantFullAccess(RESOURCES.PRODUCTS)
  .grantFullAccess(RESOURCES.NEWS)
  .grantFullAccess(RESOURCES.BOOKINGS)
  .grantFullAccess(RESOURCES.ADDITIONAL_SERVICES)
  .grantFullAccess(RESOURCES.LOCATIONS)
  .grantFullAccess(RESOURCES.USERS)
  .grantFullAccess(RESOURCES.REPORTS)
  .grantFullAccess(RESOURCES.SETTINGS);

// Configure EDITOR role - access to content management
builder
  .role("EDITOR", "Content editor")
  .forResource(RESOURCES.PRODUCTS)
  .grantAll()
  .and()
  .forResource(RESOURCES.NEWS)
  .grantAll()
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.ADDITIONAL_SERVICES)
  .grantAll()
  .and()
  .forResource(RESOURCES.LOCATIONS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.REPORTS)
  .grant(PERMISSIONS.READ, PERMISSIONS.EXPORT);

// Configure SALES role - focus on bookings and customer interactions
builder
  .role("SALES", "Sales representative")
  .forResource(RESOURCES.PRODUCTS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.NEWS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grantAll()
  .and()
  .forResource(RESOURCES.ADDITIONAL_SERVICES)
  .grant(
    PERMISSIONS.READ,
    PERMISSIONS.VIEW,
    PERMISSIONS.CREATE,
    PERMISSIONS.UPDATE
  )
  .and()
  .forResource(RESOURCES.LOCATIONS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.REPORTS)
  .grant(PERMISSIONS.READ);

// Configure CUSTOMER role - limited access to booking their own products
builder
  .role("CUSTOMER", "Registered customer")
  .forResource(RESOURCES.PRODUCTS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.NEWS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grant(PERMISSIONS.READ, PERMISSIONS.CREATE, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.ADDITIONAL_SERVICES)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
  .and()
  .forResource(RESOURCES.LOCATIONS)
  .grant(PERMISSIONS.READ, PERMISSIONS.VIEW);

// Set a default role
builder.setDefaultRole("CUSTOMER");

// Build the final configuration
const config = builder.build();

// Create the RBAC manager with caching enabled for performance
const rbac = new RBACManager(config, {
  cache: {
    enabled: true,
    maxSize: 1000,
    ttl: 5 * 60 * 1000, // 5 minutes cache TTL
  },
  strict: false, // For production use, set to false to avoid throwing errors
});

// Set up role hierarchy (inheritance)
rbac.setRoleHierarchy({
  EDITOR: ["ADMIN"], // EDITOR inherits from ADMIN
  SALES: ["ADMIN"], // SALES inherits from ADMIN
  CUSTOMER: ["EDITOR", "SALES"], // CUSTOMER inherits from both Editor and Sales
});

// Example users
const users = [
  {
    id: 1,
    name: "John Admin",
    roles: ["ADMIN"],
  },
  {
    id: 2,
    name: "Sarah Editor",
    roles: ["EDITOR"],
  },
  {
    id: 3,
    name: "Mike Sales",
    roles: ["SALES"],
  },
  {
    id: 4,
    name: "Emily Customer",
    roles: ["CUSTOMER"],
  },
  {
    id: 5,
    name: "David MultiRole",
    roles: ["EDITOR", "SALES"], // User with multiple roles
  },
];

// Demonstration function
function demonstratePermissions() {
  console.log("=== RBAC Permissions Demonstration ===\n");

  // Test scenarios for each user
  for (const user of users) {
    console.log(`\n--- ${user.name} (${user.roles.join(", ")}) ---`);

    // Check common operations
    const scenarios = [
      {
        resource: RESOURCES.PRODUCTS,
        permission: PERMISSIONS.CREATE,
        action: "create a new product listing",
      },
      {
        resource: RESOURCES.BOOKINGS,
        permission: PERMISSIONS.UPDATE,
        action: "modify a booking",
      },
      {
        resource: RESOURCES.NEWS,
        permission: PERMISSIONS.PUBLISH,
        action: "publish news articles",
      },
      {
        resource: RESOURCES.USERS,
        permission: PERMISSIONS.DELETE,
        action: "delete user accounts",
      },
      {
        resource: RESOURCES.REPORTS,
        permission: PERMISSIONS.EXPORT,
        action: "export sales reports",
      },
      {
        resource: RESOURCES.SETTINGS,
        permission: PERMISSIONS.UPDATE,
        action: "change system settings",
      },
    ];

    for (const scenario of scenarios) {
      const allowed = rbac.userCan(
        user,
        scenario.resource,
        scenario.permission
      );
      console.log(`- Can ${scenario.action}? ${allowed ? "✅ YES" : "❌ NO"}`);
    }

    // Show all available permissions for this user's primary role
    const primaryRole = user.roles[0];
    console.log(`\nAll permissions for ${primaryRole}:`);

    for (const resource of Object.values(RESOURCES)) {
      const permissions = rbac.getPermissions(primaryRole, resource);
      if (permissions.length > 0) {
        console.log(`- ${resource}: ${permissions.join(", ")}`);
      }
    }
  }

  // Demonstrate dynamic permission updates
  console.log("\n=== Dynamic Permission Updates ===\n");

  // Grant new permission
  console.log(
    "Granting CUSTOMER role permission to UPDATE their own bookings..."
  );
  rbac.grant("CUSTOMER", RESOURCES.BOOKINGS, PERMISSIONS.UPDATE);

  // Check the updated permission
  const customerCanUpdateBookings = rbac.can(
    "CUSTOMER",
    RESOURCES.BOOKINGS,
    PERMISSIONS.UPDATE
  );
  console.log(
    `Customer can now update bookings: ${customerCanUpdateBookings ? "✅ YES" : "❌ NO"}`
  );

  // Revoke permission
  console.log("\nRevoking EDITOR permission to modify Additional Services...");
  rbac.revoke("EDITOR", RESOURCES.ADDITIONAL_SERVICES, PERMISSIONS.UPDATE);

  // Check the updated permission
  const editorCanUpdateServices = rbac.can(
    "EDITOR",
    RESOURCES.ADDITIONAL_SERVICES,
    PERMISSIONS.UPDATE
  );
  console.log(
    `Editor can now update additional services: ${editorCanUpdateServices ? "✅ YES" : "❌ NO"}`
  );

  // Performance statistics
  console.log("\n=== Performance Statistics ===\n");
  console.log("Cache stats:", rbac.getCacheStats());
}

// Run the demonstration
demonstratePermissions();

// Export the configured RBAC instance
export { rbac, RESOURCES, PERMISSIONS };
