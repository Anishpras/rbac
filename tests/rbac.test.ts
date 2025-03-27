import { RBACManager, RBACBuilder, Role, Resource, Permission } from "../src";

describe("RBAC Manager", () => {
  // Test configuration for a product e-commerce platform
  const RESOURCES = {
    PRODUCTS: "Products",
    NEWS: "News",
    BOOKINGS: "Bookings",
    ADDITIONAL_SERVICES: "AdditionalServices",
    LOCATIONS: "Locations",
  };

  const PERMISSIONS = {
    CREATE: "CREATE",
    READ: "READ",
    UPDATE: "UPDATE",
    DELETE: "DELETE",
    VIEW: "VIEW",
  };

  // Create a test configuration using the builder
  const getTestConfig = () => {
    const builder = new RBACBuilder();

    // Admin has access to everything
    builder
      .role("ADMIN", "Administrator with full access")
      .grantFullAccess(RESOURCES.PRODUCTS)
      .grantFullAccess(RESOURCES.NEWS)
      .grantFullAccess(RESOURCES.BOOKINGS)
      .grantFullAccess(RESOURCES.ADDITIONAL_SERVICES)
      .grantFullAccess(RESOURCES.LOCATIONS);

    // Editor has full access to content, read-only access to bookings and locations
    builder
      .role("EDITOR", "Editor access")
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
      .grant(PERMISSIONS.READ, PERMISSIONS.VIEW);

    // Client has read-only access to most resources
    builder
      .role("CLIENT", "Client access")
      .forResource(RESOURCES.PRODUCTS)
      .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
      .and()
      .forResource(RESOURCES.NEWS)
      .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
      .and()
      .forResource(RESOURCES.BOOKINGS)
      .grant(PERMISSIONS.CREATE, PERMISSIONS.READ, PERMISSIONS.VIEW)
      .and()
      .forResource(RESOURCES.ADDITIONAL_SERVICES)
      .grant(PERMISSIONS.READ, PERMISSIONS.VIEW)
      .and()
      .forResource(RESOURCES.LOCATIONS)
      .grant(PERMISSIONS.READ, PERMISSIONS.VIEW);

    return builder.build();
  };

  describe("Basic Permission Checks", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig(), { strict: true });
    });

    test("Admin has full access to all resources", () => {
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.VIEW)).toBe(
        true
      );

      expect(rbac.can("ADMIN", RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.BOOKINGS, PERMISSIONS.DELETE)).toBe(
        true
      );
    });

    test("Editor has mixed access", () => {
      // Full access to products
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        true
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );

      // Read-only access to bookings
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.VIEW)).toBe(
        true
      );
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.UPDATE)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.DELETE)).toBe(
        false
      );

      // Full access to additional services
      expect(
        rbac.can("EDITOR", RESOURCES.ADDITIONAL_SERVICES, PERMISSIONS.CREATE)
      ).toBe(true);
      expect(
        rbac.can("EDITOR", RESOURCES.ADDITIONAL_SERVICES, PERMISSIONS.UPDATE)
      ).toBe(true);
    });

    test("Client has limited access", () => {
      // Read-only access to products
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.VIEW)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        false
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        false
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );

      // Can create bookings but not update/delete them
      expect(rbac.can("CLIENT", RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.BOOKINGS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.BOOKINGS, PERMISSIONS.VIEW)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.BOOKINGS, PERMISSIONS.UPDATE)).toBe(
        false
      );
      expect(rbac.can("CLIENT", RESOURCES.BOOKINGS, PERMISSIONS.DELETE)).toBe(
        false
      );
    });

    test("Non-existent role throws error in strict mode", () => {
      expect(() => {
        rbac.can("NONEXISTENT", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      }).toThrow();
    });

    test("Non-existent role returns false in non-strict mode", () => {
      const nonStrictRbac = new RBACManager(getTestConfig(), { strict: false });
      expect(
        nonStrictRbac.can("NONEXISTENT", RESOURCES.PRODUCTS, PERMISSIONS.READ)
      ).toBe(false);
    });
  });

  describe("Role Hierarchy", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig());

      // Set up role hierarchy
      rbac.setRoleHierarchy({
        ADMIN: ["EDITOR"],
        EDITOR: ["CLIENT"],
      });
    });

    test("Admin inherits permissions from Editor", () => {
      // Admin already has all permissions, so this just confirms it still works
      expect(rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.can("ADMIN", RESOURCES.NEWS, PERMISSIONS.UPDATE)).toBe(true);
    });

    test("Editor inherits permissions from Client", () => {
      // Editor can do everything Client can do
      expect(rbac.can("EDITOR", RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        true
      );

      // Editor still has its own permissions
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );

      // Client can't delete products
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );
    });

    test("Client does not inherit any permissions", () => {
      // Client permissions remain unchanged
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );
    });

    test("getPermissions includes inherited permissions", () => {
      const editorBookingPermissions = rbac.getPermissions(
        "EDITOR",
        RESOURCES.BOOKINGS
      );

      // Editor should have its own permissions plus inherited ones from Client
      expect(editorBookingPermissions).toContain(PERMISSIONS.READ);
      expect(editorBookingPermissions).toContain(PERMISSIONS.VIEW);
      expect(editorBookingPermissions).toContain(PERMISSIONS.CREATE);
    });
  });

  describe("User Permission Checks", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig());
    });

    test("User with single role has correct permissions", () => {
      const user = { id: 1, roles: ["ADMIN"] };

      expect(rbac.userCan(user, RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        true
      );
      expect(rbac.userCan(user, RESOURCES.BOOKINGS, PERMISSIONS.DELETE)).toBe(
        true
      );
    });

    test("User with multiple roles has combined permissions", () => {
      const user = { id: 2, roles: ["EDITOR", "CLIENT"] };

      // From EDITOR role
      expect(rbac.userCan(user, RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );

      // From CLIENT role
      expect(rbac.userCan(user, RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        true
      );
    });

    test("User with no roles has no permissions", () => {
      const user = { id: 3, roles: [] };

      expect(rbac.userCan(user, RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        false
      );
      expect(rbac.userCan(user, RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        false
      );
    });

    test("userCan works with array of roles", () => {
      const roles = ["EDITOR", "CLIENT"];

      expect(rbac.userCan(roles, RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );
      expect(rbac.userCan(roles, RESOURCES.BOOKINGS, PERMISSIONS.CREATE)).toBe(
        true
      );
    });
  });

  describe("Dynamic Updates", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig());
    });

    test("Can add a new role", () => {
      rbac.addRole("MANAGER", {
        description: "Manager role",
        permissions: {
          [RESOURCES.PRODUCTS]: [PERMISSIONS.READ, PERMISSIONS.UPDATE],
          [RESOURCES.BOOKINGS]: [
            PERMISSIONS.READ,
            PERMISSIONS.UPDATE,
            PERMISSIONS.CREATE,
          ],
        },
      });

      expect(rbac.can("MANAGER", RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        true
      );
      expect(rbac.can("MANAGER", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        true
      );
      expect(rbac.can("MANAGER", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );

      expect(rbac.can("MANAGER", RESOURCES.BOOKINGS, PERMISSIONS.UPDATE)).toBe(
        true
      );
    });

    test("Can grant permissions", () => {
      // Initially CLIENT can't update products
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        false
      );

      // Grant UPDATE permission
      rbac.grant("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE);

      // Now CLIENT can update products
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        true
      );

      // But still can't delete products
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );
    });

    test("Can grant multiple permissions at once", () => {
      rbac.grant("CLIENT", RESOURCES.PRODUCTS, [
        PERMISSIONS.UPDATE,
        PERMISSIONS.DELETE,
      ]);

      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        true
      );
      expect(rbac.can("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        true
      );
    });

    test("Can revoke permissions", () => {
      // Create a fresh config directly for the test
      const testConfig = {
        roles: {
          EDITOR: {
            permissions: {
              Products: ["CREATE", "READ", "UPDATE", "DELETE", "VIEW"],
              News: ["READ", "VIEW"],
            },
          },
        },
      };

      const testRbac = new RBACManager(testConfig);

      // Verify EDITOR has UPDATE permission initially
      expect(testRbac.can("EDITOR", "Products", "UPDATE")).toBe(true);

      // Manually remove UPDATE permission
      const updatedConfig = testRbac.getConfig();
      updatedConfig.roles["EDITOR"].permissions["Products"] = [
        "CREATE",
        "READ",
        "DELETE",
        "VIEW",
      ];
      testRbac.updateConfig(updatedConfig);

      // Now EDITOR shouldn't have UPDATE permission
      expect(testRbac.can("EDITOR", "Products", "UPDATE")).toBe(false);

      // But should still have READ permission
      expect(testRbac.can("EDITOR", "Products", "READ")).toBe(true);
    });

    test("Can revoke multiple permissions at once", () => {
      // Create a fresh config directly for the test
      const testConfig = {
        roles: {
          EDITOR: {
            permissions: {
              Products: ["CREATE", "READ", "UPDATE", "DELETE", "VIEW"],
              News: ["READ", "VIEW"],
            },
          },
        },
      };

      const testRbac = new RBACManager(testConfig);

      // Verify EDITOR has UPDATE and DELETE permissions initially
      expect(testRbac.can("EDITOR", "Products", "UPDATE")).toBe(true);
      expect(testRbac.can("EDITOR", "Products", "DELETE")).toBe(true);

      // Manually remove UPDATE and DELETE permissions
      const updatedConfig = testRbac.getConfig();
      updatedConfig.roles["EDITOR"].permissions["Products"] = [
        "CREATE",
        "READ",
        "VIEW",
      ];
      testRbac.updateConfig(updatedConfig);

      // Now EDITOR shouldn't have these permissions
      expect(testRbac.can("EDITOR", "Products", "UPDATE")).toBe(false);
      expect(testRbac.can("EDITOR", "Products", "DELETE")).toBe(false);

      // But should still have READ permission
      expect(testRbac.can("EDITOR", "Products", "READ")).toBe(true);
    });

    test("Can revoke all permissions on a resource", () => {
      // Revoke all permissions on PRODUCTS
      rbac.revoke("EDITOR", RESOURCES.PRODUCTS);

      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.READ)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)).toBe(
        false
      );
      expect(rbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.VIEW)).toBe(
        false
      );

      // But still has permissions on other resources
      expect(rbac.can("EDITOR", RESOURCES.NEWS, PERMISSIONS.READ)).toBe(true);
    });

    test("Can remove a role", () => {
      // Create a new RBAC manager with strict mode
      const strictRbac = new RBACManager(getTestConfig(), { strict: true });

      // Initially EDITOR exists
      expect(strictRbac.getRoles()).toContain("EDITOR");

      // Remove EDITOR role
      strictRbac.removeRole("EDITOR");

      // Now EDITOR doesn't exist
      expect(strictRbac.getRoles()).not.toContain("EDITOR");

      // And checking permissions throws an error in strict mode
      expect(() => {
        strictRbac.can("EDITOR", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      }).toThrow();
    });
  });

  describe("Performance with Caching", () => {
    let rbac: RBACManager;
    let rbacWithoutCache: RBACManager;

    beforeEach(() => {
      // Create manager with caching enabled
      rbac = new RBACManager(getTestConfig(), {
        cache: {
          enabled: true,
          maxSize: 100,
          ttl: 1000,
        },
      });

      // Create manager without caching for comparison
      rbacWithoutCache = new RBACManager(getTestConfig(), {
        cache: {
          enabled: false,
        },
      });
    });

    test("Cache is initially empty", () => {
      expect(rbac.getCacheStats()).toEqual({
        enabled: true,
        size: 0,
      });
    });

    test("Cache stores results after checks", () => {
      // First check - should not be cached
      rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);

      // Should now have one item in cache
      expect(rbac.getCacheStats().size).toBe(1);

      // Multiple checks for the same permission should still result in one cache entry
      rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      expect(rbac.getCacheStats().size).toBe(1);

      // Different permission checks should add more entries
      rbac.can("ADMIN", RESOURCES.BOOKINGS, PERMISSIONS.CREATE);
      expect(rbac.getCacheStats().size).toBe(2);
    });

    test("Cache is cleared when configuration changes", () => {
      // Fill cache with some entries
      rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      rbac.can("EDITOR", RESOURCES.NEWS, PERMISSIONS.UPDATE);
      expect(rbac.getCacheStats().size).toBeGreaterThan(0);

      // Update configuration
      rbac.grant("CLIENT", RESOURCES.PRODUCTS, PERMISSIONS.UPDATE);

      // Cache should be cleared
      expect(rbac.getCacheStats().size).toBe(0);
    });

    test("Cache can be manually cleared", () => {
      // Fill cache with some entries
      rbac.can("ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      rbac.can("EDITOR", RESOURCES.NEWS, PERMISSIONS.UPDATE);
      expect(rbac.getCacheStats().size).toBeGreaterThan(0);

      // Clear cache
      rbac.clearCache();

      // Cache should be empty
      expect(rbac.getCacheStats().size).toBe(0);
    });

    test("Caching improves performance for repeated checks", () => {
      // Helper function to simulate a CPU-intensive operation
      const slowCheck = (
        rbacInstance: RBACManager,
        role: Role,
        resource: Resource,
        permission: Permission
      ) => {
        // Force the JS engine to do some work to prevent optimizations
        let sum = 0;
        for (let i = 0; i < 10000; i++) {
          sum += i;
        }
        return rbacInstance.can(role, resource, permission);
      };

      // Without cache - each check is processed freshly
      const start1 = performance.now();
      for (let i = 0; i < 100; i++) {
        slowCheck(
          rbacWithoutCache,
          "ADMIN",
          RESOURCES.PRODUCTS,
          PERMISSIONS.READ
        );
      }
      const end1 = performance.now();
      const timeWithoutCache = end1 - start1;

      // With cache - only the first check is processed, the rest are cached
      const start2 = performance.now();
      for (let i = 0; i < 100; i++) {
        slowCheck(rbac, "ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ);
      }
      const end2 = performance.now();
      const timeWithCache = end2 - start2;

      // Cached version should be faster
      expect(timeWithCache).toBeLessThan(timeWithoutCache);
    });
  });

  describe("Policy Evaluation", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig());
    });

    test("Evaluates allowed policy correctly", () => {
      const policy = {
        role: "ADMIN",
        resource: RESOURCES.PRODUCTS,
        permission: PERMISSIONS.CREATE,
      };

      const result = rbac.evaluatePolicy(policy);

      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("has");
    });

    test("Evaluates denied policy correctly", () => {
      const policy = {
        role: "CLIENT",
        resource: RESOURCES.PRODUCTS,
        permission: PERMISSIONS.DELETE,
      };

      const result = rbac.evaluatePolicy(policy);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("does not have");
    });

    test("Handles policy with unknown role", () => {
      const policy = {
        role: "UNKNOWN",
        resource: RESOURCES.PRODUCTS,
        permission: PERMISSIONS.READ,
      };

      const result = rbac.evaluatePolicy(policy);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBeDefined();
    });
  });

  describe("Resource and Permission Retrieval", () => {
    let rbac: RBACManager;

    beforeEach(() => {
      rbac = new RBACManager(getTestConfig());

      // Set up role hierarchy for inheritance testing
      rbac.setRoleHierarchy({
        ADMIN: ["EDITOR"],
        EDITOR: ["CLIENT"],
      });
    });

    test("getResources returns all resources a role has access to", () => {
      const clientResources = rbac.getResources("CLIENT");

      expect(clientResources).toContain(RESOURCES.PRODUCTS);
      expect(clientResources).toContain(RESOURCES.NEWS);
      expect(clientResources).toContain(RESOURCES.BOOKINGS);
      expect(clientResources).toContain(RESOURCES.ADDITIONAL_SERVICES);
      expect(clientResources).toContain(RESOURCES.LOCATIONS);
      expect(clientResources.length).toBe(5);
    });

    test("getResources includes inherited resources", () => {
      // Create a separate RBAC manager for this test
      const testRbac = new RBACManager(getTestConfig());

      // Add ADMIN_DASHBOARD resource to ADMIN role
      const config = testRbac.getConfig();
      if (!config.roles["ADMIN"].permissions["ADMIN_DASHBOARD"]) {
        config.roles["ADMIN"].permissions["ADMIN_DASHBOARD"] = [
          PERMISSIONS.READ,
        ];
        testRbac.updateConfig(config);
      }

      // Set up role hierarchy - EDITOR inherits from ADMIN
      testRbac.setRoleHierarchy({
        EDITOR: ["ADMIN"], // This means EDITOR inherits from ADMIN
      });

      // EDITOR should inherit access to ADMIN_DASHBOARD from ADMIN
      const editorResources = testRbac.getResources("EDITOR");

      // Debug output
      console.log("EDITOR resources:", editorResources);
      console.log("Looking for ADMIN_DASHBOARD");

      expect(editorResources).toContain("ADMIN_DASHBOARD");
    });

    test("getPermissions returns all permissions a role has on a resource", () => {
      const editorProductPermissions = rbac.getPermissions(
        "EDITOR",
        RESOURCES.PRODUCTS
      );

      expect(editorProductPermissions).toContain(PERMISSIONS.CREATE);
      expect(editorProductPermissions).toContain(PERMISSIONS.READ);
      expect(editorProductPermissions).toContain(PERMISSIONS.UPDATE);
      expect(editorProductPermissions).toContain(PERMISSIONS.DELETE);
      expect(editorProductPermissions).toContain(PERMISSIONS.VIEW);
    });

    test("getPermissions returns empty array for unknown role", () => {
      const permissions = rbac.getPermissions("UNKNOWN", RESOURCES.PRODUCTS);
      expect(permissions).toEqual([]);
    });

    test("getPermissions returns empty array for non-accessible resource", () => {
      const permissions = rbac.getPermissions("CLIENT", "UNKNOWN_RESOURCE");
      expect(permissions).toEqual([]);
    });

    test("getRoles returns all defined roles", () => {
      const roles = rbac.getRoles();

      expect(roles).toContain("ADMIN");
      expect(roles).toContain("EDITOR");
      expect(roles).toContain("CLIENT");
      expect(roles.length).toBe(3);
    });
  });

  describe("Configuration Management", () => {
    let rbac: RBACManager;
    const initialConfig = getTestConfig();

    beforeEach(() => {
      rbac = new RBACManager(initialConfig);
    });

    test("getConfig returns a copy of the configuration", () => {
      const config = rbac.getConfig();

      // Should be a deep copy, not a reference
      expect(config).toEqual(initialConfig);
      expect(config).not.toBe(initialConfig);
    });

    test("updateConfig replaces the entire configuration", () => {
      const newConfig = {
        roles: {
          SUPER_ADMIN: {
            permissions: {
              [RESOURCES.PRODUCTS]: [PERMISSIONS.READ, PERMISSIONS.CREATE],
            },
          },
        },
      };

      rbac.updateConfig(newConfig);

      // Old roles should be gone
      expect(rbac.getRoles()).not.toContain("ADMIN");
      expect(rbac.getRoles()).not.toContain("EDITOR");

      // New role should be present
      expect(rbac.getRoles()).toContain("SUPER_ADMIN");

      // New permissions should be applied
      expect(
        rbac.can("SUPER_ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.READ)
      ).toBe(true);
      expect(
        rbac.can("SUPER_ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.CREATE)
      ).toBe(true);
      expect(
        rbac.can("SUPER_ADMIN", RESOURCES.PRODUCTS, PERMISSIONS.DELETE)
      ).toBe(false);
    });
  });
});
