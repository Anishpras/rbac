import type {
  Permission,
  Policy,
  PolicyResult,
  RBACConfig,
  RBACOptions,
  Resource,
  Role,
  RoleHierarchy,
} from "../types";
import { PermissionCache } from "../utils/cache";
import { defaultLogger, silentLogger } from "../utils/logger";

/**
 * RBAC Engine - Core implementation of the role-based access control system
 */
export class RBACEngine {
  private config: RBACConfig;
  private cache: PermissionCache | null;
  private strict: boolean;
  private logger: Required<RBACOptions>["logger"];
  private roleHierarchy: RoleHierarchy = {};

  /**
   * Creates a new RBAC engine instance
   */
  constructor(config: RBACConfig, options: RBACOptions = {}) {
    this.config = config;
    this.strict = options.strict || false;
    this.logger = options.logger || (options.strict ? defaultLogger : silentLogger);

    // Initialize cache if enabled
    if (options.cache?.enabled) {
      this.cache = new PermissionCache(options.cache.maxSize, options.cache.ttl);
      this.logger.debug("Permission cache initialized");
    } else {
      this.cache = null;
    }

    // Validate the configuration
    this.validateConfig();
  }

  /**
   * Validates the RBAC configuration
   */
  private validateConfig(): void {
    if (!this.config.roles || Object.keys(this.config.roles).length === 0) {
      throw new Error("RBAC configuration must contain at least one role");
    }

    if (this.config.defaultRole && !this.config.roles[this.config.defaultRole]) {
      throw new Error(
        `Default role "${this.config.defaultRole}" is not defined in the configuration`,
      );
    }

    this.logger.debug("RBAC configuration validated successfully");
  }

  /**
   * Sets up role hierarchy relationships
   */
  public setRoleHierarchy(hierarchy: RoleHierarchy): void {
    this.roleHierarchy = hierarchy;
    this.logger.debug("Role hierarchy configured", hierarchy);

    // Clear cache when hierarchy changes
    if (this.cache) {
      this.cache.clear();
    }
  }

  /**
   * Updates the RBAC configuration
   */
  public updateConfig(config: RBACConfig): void {
    this.config = config;
    this.validateConfig();
    this.logger.info("RBAC configuration updated");

    // Clear cache when configuration changes
    if (this.cache) {
      this.cache.clear();
    }
  }

  /**
   * Checks if a role has a specific permission on a resource
   */
  public can(role: Role, resource: Resource, permission: Permission): boolean {
    // Check cache first if enabled
    if (this.cache) {
      const cached = this.cache.get(role, resource, permission);
      if (cached !== undefined) {
        this.logger.debug(`Cache hit for ${role}:${resource}:${permission} = ${cached}`);
        return cached;
      }
    }

    // Direct permission check
    const allowed = this.checkPermission(role, resource, permission);

    // Check inherited roles if not allowed directly
    let inheritedAllowed = false;
    if (!allowed && this.roleHierarchy[role]) {
      // Depth-first search through the role hierarchy
      for (const parentRole of this.roleHierarchy[role]) {
        if (this.can(parentRole, resource, permission)) {
          inheritedAllowed = true;
          break;
        }
      }
    }

    const result = allowed || inheritedAllowed;

    // Cache the result if caching is enabled
    this.cacheResult(role, resource, permission, result);

    return result;
  }

  /**
   * Stores a permission check result in the cache
   */
  private cacheResult(
    role: Role,
    resource: Resource,
    permission: Permission,
    result: boolean,
  ): void {
    if (this.cache) {
      this.cache.set(role, resource, permission, result);
    }
  }

  /**
   * Internal method to check if a role has a permission on a resource
   */
  private checkPermission(role: Role, resource: Resource, permission: Permission): boolean {
    const roleDefinition = this.config.roles[role];

    // Check if the role exists
    if (!roleDefinition) {
      if (this.strict) {
        throw new Error(`Role "${role}" does not exist`);
      }
      this.logger.warn(`Unknown role: ${role}`);
      return false;
    }

    // Check if the role has permissions for the resource
    const resourcePermissions = roleDefinition.permissions[resource];
    if (!resourcePermissions) {
      this.logger.debug(`Role ${role} has no permissions defined for resource ${resource}`);
      return false;
    }

    // Check if the permission is granted
    const hasPermission =
      resourcePermissions.includes(permission) || resourcePermissions.includes("*");

    this.logger.debug(
      `Direct permission check: ${role} ${hasPermission ? "has" : "does not have"} ${permission} permission on ${resource}`,
    );

    return hasPermission;
  }

  /**
   * Checks if a user has permission on a resource based on their roles
   */
  public userCan(userRoles: Role[], resource: Resource, permission: Permission): boolean {
    if (!userRoles || userRoles.length === 0) {
      if (this.config.defaultRole) {
        return this.can(this.config.defaultRole, resource, permission);
      }
      return false;
    }

    // Use a fast loop rather than Array.some() for better performance
    for (let i = 0; i < userRoles.length; i++) {
      if (this.can(userRoles[i], resource, permission)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Gets all permissions a role has on a specific resource
   */
  public getPermissions(role: Role, resource: Resource): Permission[] {
    const roleDefinition = this.config.roles[role];

    if (!roleDefinition) {
      if (this.strict) {
        throw new Error(`Role "${role}" does not exist`);
      }
      return [];
    }

    const directPermissions = roleDefinition.permissions[resource] || [];

    // Get inherited permissions if applicable
    let inheritedPermissions: Permission[] = [];
    if (this.roleHierarchy[role]) {
      for (const parentRole of this.roleHierarchy[role]) {
        inheritedPermissions = [
          ...inheritedPermissions,
          ...this.getPermissions(parentRole, resource),
        ];
      }
    }

    // Combine and deduplicate permissions
    return [...new Set([...directPermissions, ...inheritedPermissions])];
  }

  /**
   * Gets all resources a role has access to
   */
  public getResources(role: Role): Resource[] {
    const roleDefinition = this.config.roles[role];

    if (!roleDefinition) {
      if (this.strict) {
        throw new Error(`Role "${role}" does not exist`);
      }
      return [];
    }

    const directResources = Object.keys(roleDefinition.permissions);

    // Get inherited resources if applicable
    let inheritedResources: Resource[] = [];
    if (this.roleHierarchy[role]) {
      for (const parentRole of this.roleHierarchy[role]) {
        inheritedResources = [...inheritedResources, ...this.getResources(parentRole)];
      }
    }

    // Combine and deduplicate resources
    const allResources = [...new Set([...directResources, ...inheritedResources])];
    this.logger.debug(`Resources for role ${role}: ${allResources.join(", ")}`);

    return allResources;
  }

  /**
   * Evaluates a policy against the RBAC configuration
   */
  public evaluatePolicy(policy: Policy): PolicyResult {
    const { role, resource, permission } = policy;

    try {
      const allowed = this.can(role, resource, permission);
      return {
        allowed,
        reason: allowed
          ? `Role "${role}" has "${permission}" permission on resource "${resource}"`
          : `Role "${role}" does not have "${permission}" permission on resource "${resource}"`,
      };
    } catch (error) {
      return {
        allowed: false,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Returns all defined roles in the configuration
   */
  public getRoles(): Role[] {
    return Object.keys(this.config.roles);
  }

  /**
   * Returns the complete configuration
   */
  public getConfig(): RBACConfig {
    return { ...this.config };
  }

  /**
   * Returns cache statistics if caching is enabled
   */
  public getCacheStats(): { enabled: boolean; size?: number } {
    if (!this.cache) {
      return { enabled: false };
    }

    return {
      enabled: true,
      size: this.cache.size(),
    };
  }

  /**
   * Clears the permission cache
   */
  public clearCache(): void {
    if (this.cache) {
      this.cache.clear();
      this.logger.debug("Permission cache cleared");
    }
  }
}
