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
    // Validate hierarchy for circular references
    this.validateHierarchy(hierarchy);

    this.roleHierarchy = hierarchy;
    this.logger.debug("Role hierarchy configured", hierarchy);

    // Clear cache when hierarchy changes
    if (this.cache) {
      this.cache.clear();
    }
  }

  /**
   * Validates the role hierarchy to prevent circular references
   * @private
   */
  private validateHierarchy(hierarchy: RoleHierarchy): void {
    // For each role, check if there's a path back to itself
    for (const role in hierarchy) {
      const visited = new Set<Role>();
      const stack = new Set<Role>();

      if (this.detectCycle(role, hierarchy, visited, stack)) {
        throw new Error(`Circular reference detected in role hierarchy involving role "${role}"`);
      }
    }
  }

  /**
   * Detects cycles in the role hierarchy using depth-first search
   * @private
   */
  private detectCycle(
    role: Role,
    hierarchy: RoleHierarchy,
    visited: Set<Role>,
    stack: Set<Role>,
  ): boolean {
    // If role is already in the stack, we found a cycle
    if (stack.has(role)) {
      return true;
    }

    // If we've already checked this role and found no cycles, skip it
    if (visited.has(role)) {
      return false;
    }

    // Add role to both visited and the current traversal stack
    visited.add(role);
    stack.add(role);

    // Check all parent roles that this role inherits from
    const parentRoles = hierarchy[role] || [];
    for (const parentRole of parentRoles) {
      if (this.detectCycle(parentRole, hierarchy, visited, stack)) {
        return true;
      }
    }

    // Remove role from current traversal stack as we backtrack
    stack.delete(role);
    return false;
  }

  /**
   * Updates the RBAC configuration
   */
  public updateConfig(config: RBACConfig): void {
    // Create a deep copy of the config to prevent external modifications
    this.config = this.deepCloneConfig(config);

    // Validate the configuration
    this.validateConfig();
    this.logger.info("RBAC configuration updated");

    // Clear cache when configuration changes
    if (this.cache) {
      this.cache.clear();
    }
  }

  /**
   * Creates a deep clone of the configuration to prevent external references and mutations
   * @private
   */
  private deepCloneConfig(config: RBACConfig): RBACConfig {
    if (!config || typeof config !== "object") {
      throw new Error("Invalid RBAC configuration");
    }

    // Start with a fresh object
    const clonedConfig: RBACConfig = {
      roles: {},
    };

    // Clone default role if present
    if (config.defaultRole) {
      clonedConfig.defaultRole = String(config.defaultRole);
    }

    // Deep clone each role and its permissions
    if (config.roles) {
      for (const role in config.roles) {
        if (Object.prototype.hasOwnProperty.call(config.roles, role)) {
          const roleDefinition = config.roles[role];

          // Create new role definition
          clonedConfig.roles[role] = {
            description: roleDefinition.description
              ? String(roleDefinition.description)
              : undefined,
            permissions: {},
          };

          // Clone all permissions for each resource
          for (const resource in roleDefinition.permissions) {
            if (Object.prototype.hasOwnProperty.call(roleDefinition.permissions, resource)) {
              const permissions = roleDefinition.permissions[resource];
              if (Array.isArray(permissions)) {
                // Create a new array for permissions
                clonedConfig.roles[role].permissions[resource] = [...permissions];
              }
            }
          }
        }
      }
    }

    return clonedConfig;
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
    // Validate inputs to prevent injection or manipulation
    this.validateInput(role, "role");
    this.validateInput(resource, "resource");
    this.validateInput(permission, "permission");

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
    // Only allow if the permission is explicitly in the list or wildcard (*) is included
    const hasPermission =
      resourcePermissions.includes(permission) || resourcePermissions.includes("*");

    if (!hasPermission) {
      this.logger.debug(
        `Permission "${permission}" not granted for role ${role} on resource ${resource}`,
      );
    }

    this.logger.debug(
      `Direct permission check: ${role} ${hasPermission ? "has" : "does not have"} ${permission} permission on ${resource}`,
    );

    return hasPermission;
  }

  /**
   * Validates a string input to prevent security issues
   * @private
   */
  private validateInput(input: string, field: string): void {
    if (typeof input !== "string") {
      throw new Error(`${field} must be a string`);
    }

    if (input.trim() === "") {
      throw new Error(`${field} cannot be empty`);
    }

    // Check for potentially dangerous input patterns or SQL/NoSQL injection attempts
    // biome-ignore lint/suspicious/noControlCharactersInRegex: This checks for control characters that could be used in injection attacks
    const dangerousPatterns = /[\x00-\x1F\x7F]|\$\{|\$\(|\{\{|\}\}|--|;\'|\";|<script>|<\/script>/i;
    if (dangerousPatterns.test(input)) {
      this.logger.error(`Potentially malicious ${field} value detected: ${input}`);
      throw new Error(`Invalid ${field} format`);
    }
  }

  /**
   * Checks if a user has permission on a resource based on their roles
   */
  public userCan(userRoles: Role[], resource: Resource, permission: Permission): boolean {
    try {
      // Validate inputs
      this.validateInput(resource, "resource");
      this.validateInput(permission, "permission");

      // Default deny for empty roles
      if (!userRoles || userRoles.length === 0) {
        this.logger.warn("Access check attempted with empty roles array");
        if (this.config.defaultRole) {
          this.logger.debug(`Falling back to default role: ${this.config.defaultRole}`);
          return this.can(this.config.defaultRole, resource, permission);
        }
        return false;
      }

      // Validate each role
      for (const role of userRoles) {
        this.validateInput(role, "role");
      }

      // Check each role for permission
      for (let i = 0; i < userRoles.length; i++) {
        if (this.can(userRoles[i], resource, permission)) {
          return true;
        }
      }

      return false;
    } catch (error) {
      // Log the error but default to deny on any exception
      this.logger.error("Error in userCan check", error);
      return false;
    }
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
    try {
      // Validate the policy object
      if (!policy || typeof policy !== "object") {
        return {
          allowed: false,
          reason: "Invalid policy object",
        };
      }

      const { role, resource, permission } = policy;

      // Validate each field exists and is a string
      if (!role || !resource || !permission) {
        return {
          allowed: false,
          reason: "Policy must include role, resource, and permission",
        };
      }

      // Validate inputs to prevent injection
      try {
        this.validateInput(role, "role");
        this.validateInput(resource, "resource");
        this.validateInput(permission, "permission");
      } catch (validationError) {
        return {
          allowed: false,
          reason:
            validationError instanceof Error ? validationError.message : "Invalid policy input",
        };
      }

      // Check if the role is allowed
      const allowed = this.can(role, resource, permission);

      return {
        allowed,
        reason: allowed
          ? `Role "${role}" has "${permission}" permission on resource "${resource}"`
          : `Role "${role}" does not have "${permission}" permission on resource "${resource}"`,
      };
    } catch (error) {
      // Default to deny on any errors
      this.logger.error("Error in policy evaluation", error);
      return {
        allowed: false,
        reason: "Policy evaluation error",
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
   * Gets the current role hierarchy
   */
  public getRoleHierarchy(): RoleHierarchy | undefined {
    return this.roleHierarchy;
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
