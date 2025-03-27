/**
 * Permission represents a single action that can be performed on a resource
 * String literals like 'CREATE', 'READ', etc. are preferred over arbitrary strings for type safety
 */
export type Permission = "CREATE" | "READ" | "UPDATE" | "DELETE" | "VIEW" | string;

/**
 * Resource represents a module or entity in the system
 * Prefer using predefined constants for resources rather than arbitrary strings for consistency
 */
export type Resource = string;

/**
 * Role represents a role in the system (e.g., "ADMIN", "CLIENT")
 * Prefer using predefined constants for roles rather than arbitrary strings for security
 */
export type Role = string;

/**
 * ResourcePermissions maps permissions to a specific resource
 */
export interface ResourcePermissions {
  [resource: Resource]: Permission[];
}

/**
 * RoleDefinition represents the set of permissions assigned to a role
 */
export interface RoleDefinition {
  description?: string;
  permissions: ResourcePermissions;
}

/**
 * RBACConfig represents the complete RBAC configuration
 */
export interface RBACConfig {
  roles: {
    [role: Role]: RoleDefinition;
  };
  defaultRole?: Role;
}

/**
 * Policy represents a decision on whether an action is permitted
 */
export interface Policy {
  role: Role;
  resource: Resource;
  permission: Permission;
}

/**
 * PolicyResult represents the outcome of a policy check
 */
export interface PolicyResult {
  allowed: boolean;
  reason?: string;
}

/**
 * CacheOptions for configuring the permission cache
 */
export interface CacheOptions {
  enabled: boolean;
  maxSize?: number;
  ttl?: number; // Time-to-live in milliseconds
}

/**
 * RBACOptions for configuring the RBAC instance
 */
export interface RBACOptions {
  cache?: CacheOptions;
  strict?: boolean; // If true, throws errors on undefined roles/resources/permissions
  logger?: {
    debug: (message: string, ...args: unknown[]) => void;
    info: (message: string, ...args: unknown[]) => void;
    warn: (message: string, ...args: unknown[]) => void;
    error: (message: string, ...args: unknown[]) => void;
  };
}

/**
 * PermissionCheck is a function that determines if a permission is granted
 */
export type PermissionCheck = (
  role: Role,
  resource: Resource,
  permission: Permission,
) => boolean | Promise<boolean>;

/**
 * RoleHierarchy defines parent-child relationships between roles
 */
export interface RoleHierarchy {
  [role: Role]: Role[];
}

/**
 * User represents a user in the system
 * Must have an id and an array of roles
 */
export interface User {
  id: string | number;
  roles: Role[]; // Array of role identifiers
  [key: string]: unknown; // Additional user properties
}
