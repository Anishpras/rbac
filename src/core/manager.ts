import type {
  Permission,
  Policy,
  PolicyResult,
  RBACConfig,
  RBACOptions,
  Resource,
  Role,
  RoleDefinition,
  RoleHierarchy,
  User,
} from "../types";
import type { Middleware, NextFunction, Request, Response } from "../types/express";
import { RBACEngine } from "./engine";

/**
 * RBAC Manager - Main interface for the RBAC system
 */
export class RBACManager {
  private engine: RBACEngine;
  private options: RBACOptions;

  /**
   * Creates a new RBAC manager instance
   */
  constructor(config: RBACConfig, options: RBACOptions = {}) {
    this.options = options;
    this.engine = new RBACEngine(config, options);
  }

  /**
   * Checks if a role has a specific permission on a resource
   */
  public can(role: Role, resource: Resource, permission: Permission): boolean {
    return this.engine.can(role, resource, permission);
  }

  /**
   * Checks if a user has permission on a resource based on their roles
   */
  public userCan(user: User | Role[], resource: Resource, permission: Permission): boolean {
    const roles = Array.isArray(user) ? user : user.roles;
    return this.engine.userCan(roles, resource, permission);
  }

  /**
   * Sets up role hierarchy relationships
   */
  public setRoleHierarchy(hierarchy: RoleHierarchy): void {
    this.engine.setRoleHierarchy(hierarchy);
  }

  /**
   * Updates the RBAC configuration
   */
  public updateConfig(config: RBACConfig): void {
    this.engine.updateConfig(config);
    // Clear cache after config update
    this.clearCache();
  }

  /**
   * Adds a new role to the configuration
   */
  public addRole(role: Role, definition: RoleDefinition): void {
    const config = this.engine.getConfig();

    config.roles = {
      ...config.roles,
      [role]: definition,
    };

    this.engine.updateConfig(config);
  }

  /**
   * Removes a role from the configuration
   */
  public removeRole(role: Role): void {
    const config = this.engine.getConfig();

    if (!config.roles[role]) {
      return;
    }

    const { [role]: _, ...roles } = config.roles;

    config.roles = roles;

    if (config.defaultRole === role) {
      config.defaultRole = undefined;
    }

    this.engine.updateConfig(config);
  }

  /**
   * Grants a permission to a role on a resource
   */
  public grant(role: Role, resource: Resource, permission: Permission | Permission[]): void {
    const config = this.engine.getConfig();

    if (!config.roles[role]) {
      throw new Error(`Role "${role}" does not exist`);
    }

    const permissions = Array.isArray(permission) ? permission : [permission];
    const currentPermissions = config.roles[role].permissions[resource] || [];

    config.roles[role].permissions[resource] = [
      ...new Set([...currentPermissions, ...permissions]),
    ];

    this.engine.updateConfig(config);
  }

  /**
   * Revokes a permission from a role on a resource
   */
  public revoke(role: Role, resource: Resource, permission?: Permission | Permission[]): void {
    const config = this.engine.getConfig();

    if (!config.roles[role] || !config.roles[role].permissions[resource]) {
      return;
    }

    // If no permission specified, revoke all permissions on the resource
    if (!permission) {
      delete config.roles[role].permissions[resource];
      this.engine.updateConfig(config);
      return;
    }

    const permissions = Array.isArray(permission) ? permission : [permission];
    config.roles[role].permissions[resource] = config.roles[role].permissions[resource].filter(
      (p) => !permissions.includes(p),
    );

    // If no permissions left, remove the resource entry
    if (config.roles[role].permissions[resource].length === 0) {
      delete config.roles[role].permissions[resource];
    }

    this.engine.updateConfig(config);

    // Also clear cache for this role
    this.clearCache();
  }

  /**
   * Evaluates a policy against the RBAC configuration
   */
  public evaluatePolicy(policy: Policy): PolicyResult {
    return this.engine.evaluatePolicy(policy);
  }

  /**
   * Gets all permissions a role has on a specific resource
   */
  public getPermissions(role: Role, resource: Resource): Permission[] {
    return this.engine.getPermissions(role, resource);
  }

  /**
   * Gets all resources a role has access to
   */
  public getResources(role: Role): Resource[] {
    return this.engine.getResources(role);
  }

  /**
   * Returns all defined roles in the configuration
   */
  public getRoles(): Role[] {
    return this.engine.getRoles();
  }

  /**
   * Returns the complete configuration
   */
  public getConfig(): RBACConfig {
    return this.engine.getConfig();
  }

  /**
   * Clears the permission cache
   */
  public clearCache(): void {
    this.engine.clearCache();
  }

  /**
   * Returns cache statistics if caching is enabled
   */
  public getCacheStats(): { enabled: boolean; size?: number } {
    return this.engine.getCacheStats();
  }

  /**
   * Creates a middleware function for Express/Connect compatible frameworks
   */
  public middleware(options: {
    getUserRoles: (req: Request) => Role[] | Promise<Role[]>;
    resource: Resource | ((req: Request) => Resource);
    permission: Permission | ((req: Request) => Permission);
    onDenied?: (req: Request, res: Response, next: NextFunction) => void;
  }): Middleware {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Get user roles
        const roles = await options.getUserRoles(req);

        // Determine resource and permission from request
        const resource =
          typeof options.resource === "function" ? options.resource(req) : options.resource;

        const permission =
          typeof options.permission === "function" ? options.permission(req) : options.permission;

        // Check if user has permission
        const allowed = this.engine.userCan(roles, resource, permission);

        if (allowed) {
          next();
        } else if (options.onDenied) {
          options.onDenied(req, res, next);
        } else {
          res.status(403).json({
            error: "Forbidden",
            message: `You don't have permission to ${permission} on ${resource}`,
          });
        }
      } catch (error) {
        next(error);
      }
    };
  }
}
