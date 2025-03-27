/**
 * Example: Express.js Integration
 *
 * This example demonstrates how to integrate the RBAC system with Express.js
 * to protect API routes based on user roles and permissions.
 */

import express from "express";
import { RBACManager, RBACBuilder } from "../src";

// Mock express app (this would be your actual Express application)
const app = express();

// Define resources and permissions
const RESOURCES = {
  PRODUCTS: "Products",
  BOOKINGS: "Bookings",
  USERS: "Users",
};

const PERMISSIONS = {
  CREATE: "CREATE",
  READ: "READ",
  UPDATE: "UPDATE",
  DELETE: "DELETE",
};

// Build RBAC configuration
const config = new RBACBuilder()
  .role("ADMIN")
  .grantFullAccess(RESOURCES.PRODUCTS)
  .grantFullAccess(RESOURCES.BOOKINGS)
  .grantFullAccess(RESOURCES.USERS)
  .done()
  .role("MANAGER")
  .forResource(RESOURCES.PRODUCTS)
  .grantAll()
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grantAll()
  .and()
  .forResource(RESOURCES.USERS)
  .grant(PERMISSIONS.READ)
  .done()
  .role("STAFF")
  .forResource(RESOURCES.PRODUCTS)
  .grant(PERMISSIONS.READ)
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grant(PERMISSIONS.READ, PERMISSIONS.UPDATE)
  .and()
  .forResource(RESOURCES.USERS)
  .grant(PERMISSIONS.READ)
  .done()
  .role("CUSTOMER")
  .forResource(RESOURCES.PRODUCTS)
  .grant(PERMISSIONS.READ)
  .and()
  .forResource(RESOURCES.BOOKINGS)
  .grant(PERMISSIONS.READ, PERMISSIONS.CREATE)
  .done()
  .build();

// Create RBAC manager
const rbac = new RBACManager(config, {
  cache: { enabled: true },
  strict: false, // Avoid runtime errors in production
  logger: {
    debug: (message) => console.debug(`[RABAC] ${message}`),
    info: (message) => console.info(`[RABAC] ${message}`),
    warn: (message) => console.warn(`[RABAC] ${message}`),
    error: (message) => console.error(`[RABAC] ${message}`),
  },
});

// Mock authentication middleware (this would be your actual auth logic)
const authenticate = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  // This is where you would verify JWT tokens, session cookies, etc.
  // For this example, we'll use a simple API key header to identify the user

  const apiKey = req.headers["x-api-key"] as string;

  if (!apiKey) {
    return res.status(401).json({ error: "Authentication required" });
  }

  // Mock user database lookup
  const users: Record<string, { id: number; name: string; roles: string[] }> = {
    "admin-key": { id: 1, name: "Admin User", roles: ["ADMIN"] },
    "manager-key": { id: 2, name: "Manager User", roles: ["MANAGER"] },
    "staff-key": { id: 3, name: "Staff User", roles: ["STAFF"] },
    "customer-key": { id: 4, name: "Customer User", roles: ["CUSTOMER"] },
  };

  const user = users[apiKey];

  if (!user) {
    return res.status(401).json({ error: "Invalid API key" });
  }

  // Attach the user to the request object
  (req as any).user = user;

  next();
};

// Create RBAC middleware functions for different routes
const yachtListAccess = rbac.middleware({
  getUserRoles: (req) => (req as any).user.roles,
  resource: RESOURCES.PRODUCTS,
  permission: PERMISSIONS.READ,
  onDenied: (req, res) => {
    res.status(403).json({
      error: "Access denied",
      message: "You do not have permission to view product listings",
    });
  },
});

const yachtCreateAccess = rbac.middleware({
  getUserRoles: (req) => (req as any).user.roles,
  resource: RESOURCES.PRODUCTS,
  permission: PERMISSIONS.CREATE,
  onDenied: (req, res) => {
    res.status(403).json({
      error: "Access denied",
      message: "You do not have permission to create product listings",
    });
  },
});

const bookingManageAccess = rbac.middleware({
  getUserRoles: (req) => (req as any).user.roles,
  resource: RESOURCES.BOOKINGS,
  permission: (req) => {
    // Determine the required permission based on the HTTP method
    switch (req.method) {
      case "GET":
        return PERMISSIONS.READ;
      case "POST":
        return PERMISSIONS.CREATE;
      case "PUT":
      case "PATCH":
        return PERMISSIONS.UPDATE;
      case "DELETE":
        return PERMISSIONS.DELETE;
      default:
        return PERMISSIONS.READ;
    }
  },
  onDenied: (req, res) => {
    res.status(403).json({
      error: "Access denied",
      message: `You do not have permission to ${req.method} bookings`,
    });
  },
});

// Owner check middleware - ensure users can only manage their own bookings
const ownerCheckMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  const user = (req as any).user;
  const bookingId = parseInt(req.params.id);

  // Mock booking database
  const bookings = [
    { id: 1, userId: 1, product: "Luxury Product 1" },
    { id: 2, userId: 4, product: "Economy Product 1" }, // Owned by customer
  ];

  const booking = bookings.find((b) => b.id === bookingId);

  if (!booking) {
    return res.status(404).json({ error: "Booking not found" });
  }

  // Check if the user is the owner of this booking
  const isOwner = booking.userId === user.id;

  // Allow admins and managers to bypass ownership check
  if (user.roles.includes("ADMIN") || user.roles.includes("MANAGER")) {
    return next();
  }

  if (!isOwner) {
    return res.status(403).json({
      error: "Access denied",
      message: "You can only manage your own bookings",
    });
  }

  next();
};

// Define API routes with RBAC protection

// Public routes (no authentication required)
app.get("/", (_req, res) => {
  res.json({ message: "Welcome to the Product Shop API" });
});

// Protected routes with different permission requirements
app.get("/api/yachts", authenticate, yachtListAccess, (req, res) => {
  // Return product listings
  res.json({
    yachts: [
      { id: 1, name: "Luxury Product 1", price: 500000 },
      { id: 2, name: "Luxury Product 2", price: 750000 },
      { id: 3, name: "Economy Product 1", price: 250000 },
    ],
  });
});

app.post("/api/yachts", authenticate, yachtCreateAccess, (req, res) => {
  // Create a new product listing
  res.status(201).json({
    message: "Product created successfully",
    product: {
      id: 4,
      name: "New Product",
      price: 350000,
    },
  });
});

app.get("/api/bookings", authenticate, bookingManageAccess, (req, res) => {
  const user = (req as any).user;

  // For non-admin users, only return their own bookings
  const isAdmin =
    user.roles.includes("ADMIN") || user.roles.includes("MANAGER");

  const allBookings = [
    { id: 1, userId: 1, product: "Luxury Product 1", date: "2023-10-15" },
    { id: 2, userId: 4, product: "Economy Product 1", date: "2023-10-20" },
  ];

  const bookings = isAdmin
    ? allBookings
    : allBookings.filter((booking) => booking.userId === user.id);

  res.json({ bookings });
});

app.post("/api/bookings", authenticate, bookingManageAccess, (req, res) => {
  // Create a new booking
  res.status(201).json({
    message: "Booking created successfully",
    booking: {
      id: 3,
      userId: (req as any).user.id,
      product: "Economy Product 2",
      date: "2023-11-01",
    },
  });
});

app.put(
  "/api/bookings/:id",
  authenticate,
  ownerCheckMiddleware,
  bookingManageAccess,
  (req, res) => {
    // Update a booking
    res.json({
      message: "Booking updated successfully",
      booking: {
        id: parseInt(req.params.id),
        userId: (req as any).user.id,
        product: "Luxury Product 3",
        date: "2023-11-15",
      },
    });
  }
);

app.delete(
  "/api/bookings/:id",
  authenticate,
  ownerCheckMiddleware,
  bookingManageAccess,
  (req, res) => {
    // Delete a booking
    res.json({
      message: "Booking deleted successfully",
      id: parseInt(req.params.id),
    });
  }
);

// Demonstrate how to access user information within a route handler
app.get("/api/user/profile", authenticate, (req, res) => {
  const user = (req as any).user;

  // Get all permissions for this user across all resources
  const userPermissions: Record<string, string[]> = {};

  for (const role of user.roles) {
    for (const resource of Object.values(RESOURCES)) {
      const permissions = rbac.getPermissions(role, resource);

      if (permissions.length > 0) {
        if (!userPermissions[resource]) {
          userPermissions[resource] = [];
        }

        userPermissions[resource] = [
          ...userPermissions[resource],
          ...permissions,
        ];
      }
    }
  }

  // Remove duplicates
  for (const resource in userPermissions) {
    userPermissions[resource] = [...new Set(userPermissions[resource])];
  }

  res.json({
    profile: {
      id: user.id,
      name: user.name,
      roles: user.roles,
    },
    permissions: userPermissions,
  });
});

// Dynamic permission management routes (admin only)
const adminOnly = rbac.middleware({
  getUserRoles: (req) => (req as any).user.roles,
  resource: RESOURCES.USERS,
  permission: PERMISSIONS.UPDATE,
  onDenied: (req, res) => {
    res.status(403).json({
      error: "Access denied",
      message: "Only administrators can manage permissions",
    });
  },
});

app.post("/api/admin/permissions", authenticate, adminOnly, (req, res) => {
  const { role, resource, permissions } = req.body;

  try {
    // Grant new permissions
    rbac.grant(role, resource, permissions);

    res.json({
      message: "Permissions granted successfully",
      role,
      resource,
      permissions,
    });
  } catch (error) {
    res.status(400).json({
      error: "Failed to grant permissions",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

app.delete("/api/admin/permissions", authenticate, adminOnly, (req, res) => {
  const { role, resource, permissions } = req.body;

  try {
    // Revoke permissions
    rbac.revoke(role, resource, permissions);

    res.json({
      message: "Permissions revoked successfully",
      role,
      resource,
      permissions,
    });
  } catch (error) {
    res.status(400).json({
      error: "Failed to revoke permissions",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log("API endpoints:");
    console.log(
      "- GET    /api/yachts                (all authenticated users)"
    );
    console.log("- POST   /api/yachts                (admin, manager)");
    console.log(
      "- GET    /api/bookings              (all authenticated users)"
    );
    console.log(
      "- POST   /api/bookings              (all authenticated users)"
    );
    console.log(
      "- PUT    /api/bookings/:id          (admin, manager, staff, owner)"
    );
    console.log("- DELETE /api/bookings/:id          (admin, manager, owner)");
    console.log(
      "- GET    /api/user/profile          (all authenticated users)"
    );
    console.log("- POST   /api/admin/permissions     (admin only)");
    console.log("- DELETE /api/admin/permissions     (admin only)");
    console.log("\nUse the following API keys for testing:");
    console.log("- Admin:    x-api-key: admin-key");
    console.log("- Manager:  x-api-key: manager-key");
    console.log("- Staff:    x-api-key: staff-key");
    console.log("- Customer: x-api-key: customer-key");
  });
}

export { app, rbac, RESOURCES, PERMISSIONS };
