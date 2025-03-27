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
  public userCan(user: User | Role[] | null | undefined, resource: Resource, permission: Permission): boolean {
    try {
      // Handle null or undefined user
      if (!user) {
        return false;
      }
      
      const roles = Array.isArray(user) ? user : user.roles;
      return this.engine.userCan(roles, resource, permission);
    } catch (error) {
      // Log error but default to deny for any exception
      console.error('Error checking user permissions:', error);
      return false;
    }
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
   * Adds a new role to the configuration with enhanced security
   */
  public addRole(role: Role, definition: RoleDefinition): void {
    // Input validation
    if (!role || typeof role !== 'string') {
      throw new Error('Role must be a non-empty string');
    }
    
    if (!definition || typeof definition !== 'object') {
      throw new Error('Role definition must be an object');
    }
    
    if (!definition.permissions || typeof definition.permissions !== 'object') {
      throw new Error('Role definition must include permissions object');
    }
    
    // Get a fresh copy of the config
    const config = this.engine.getConfig();

    // Create a sanitized definition with validated permissions
    const sanitizedDefinition: RoleDefinition = {
      description: definition.description ? String(definition.description) : undefined,
      permissions: {}
    };
    
    // Validate and copy all permissions
    for (const resource in definition.permissions) {
      if (Object.prototype.hasOwnProperty.call(definition.permissions, resource)) {
        const permissions = definition.permissions[resource];
        
        // Ensure permissions is an array
        if (!Array.isArray(permissions)) {
          throw new Error(`Permissions for resource "${resource}" must be an array`);
        }
        
        // Validate each permission in the array
        sanitizedDefinition.permissions[resource] = permissions.map(p => {
          if (!p || typeof p !== 'string') {
            throw new Error(`Invalid permission in resource "${resource}": ${p}`);
          }
          return p;
        });
      }
    }

    // Create a new roles object with the new role
    config.roles = {
      ...config.roles,
      [role]: sanitizedDefinition,
    };

    // Update configuration atomically
    this.engine.updateConfig(config);
    
    // Audit log
    console.info(`Role added: ${role}`, {
      description: sanitizedDefinition.description,
      permissionCount: Object.keys(sanitizedDefinition.permissions).length
    });
  }

  /**
   * Removes a role from the configuration with enhanced security
   */
  public removeRole(role: Role): void {
    // Input validation
    if (!role || typeof role !== 'string') {
      throw new Error('Role must be a non-empty string');
    }
    
    // Get a fresh copy of the config
    const config = this.engine.getConfig();

    if (!config.roles[role]) {
      // Log attempt to remove non-existent role but don't throw
      console.warn(`Attempted to remove non-existent role: ${role}`);
      return;
    }

    // Create a new roles object excluding the role to be removed
    const newRoles: typeof config.roles = {};
    for (const r in config.roles) {
      if (r !== role && Object.prototype.hasOwnProperty.call(config.roles, r)) {
        newRoles[r] = config.roles[r];
      }
    }
    
    config.roles = newRoles;

    // Handle default role safely
    if (config.defaultRole === role) {
      config.defaultRole = undefined;
    }

    // Update configuration atomically
    this.engine.updateConfig(config);
    
    // Audit log
    console.info(`Role removed: ${role}`);
    
    // Check if any role inherits from the removed role and warn
    this.checkRoleHierarchyIntegrity(role);
  }
  
  /**
   * Checks if any roles in the hierarchy depend on a removed role
   * @private
   */
  private checkRoleHierarchyIntegrity(removedRole: Role): void {
    try {
      const config = this.engine.getConfig();
      const hierarchy = this.engine.getRoleHierarchy();
      
      if (!hierarchy) return;
      
      // Check if any role inherits from the removed role
      const dependentRoles: Role[] = [];
      
      for (const role in hierarchy) {
        if (Object.prototype.hasOwnProperty.call(hierarchy, role)) {
          const parents = hierarchy[role];
          if (parents?.includes(removedRole)) {
            dependentRoles.push(role);
          }
        }
      }
      
      if (dependentRoles.length > 0) {
        console.warn(`Role hierarchy integrity warning: Roles [${dependentRoles.join(', ')}] inherit from removed role ${removedRole}`);
      }
    } catch (error) {
      console.error('Error checking role hierarchy integrity:', error);
    }
  }

  /**
   * Grants a permission to a role on a resource with enhanced security
   */
  public grant(role: Role, resource: Resource, permission: Permission | Permission[]): void {
    // Input validation
    if (!role || typeof role !== 'string') {
      throw new Error('Role must be a non-empty string');
    }
    
    if (!resource || typeof resource !== 'string') {
      throw new Error('Resource must be a non-empty string');
    }
    
    if (!permission || (Array.isArray(permission) && permission.length === 0)) {
      throw new Error('Permission cannot be empty');
    }
    
    // Get a fresh copy of the config to prevent concurrent modification issues
    const config = this.engine.getConfig();

    if (!config.roles[role]) {
      throw new Error(`Role "${role}" does not exist`);
    }

    const permissions = Array.isArray(permission) ? permission : [permission];
    
    // Validate each permission value
    for (const p of permissions) {
      if (!p || typeof p !== 'string') {
        throw new Error('Each permission must be a non-empty string');
      }
    }
    
    // Get current permissions or initialize empty array
    const currentPermissions = config.roles[role].permissions[resource] || [];

    // Create a new array with deduplicated permissions
    config.roles[role].permissions[resource] = [
      ...new Set([...currentPermissions, ...permissions])
    ];

    // Update the configuration atomically
    this.engine.updateConfig(config);
    
    // Audit log the permission change
    console.info(`Grant: Role=${role}, Resource=${resource}, Permissions=${permissions.join(',')}`);
  }

  /**
   * Revokes a permission from a role on a resource with enhanced security
   */
  public revoke(role: Role, resource: Resource, permission?: Permission | Permission[]): void {
    // Input validation
    if (!role || typeof role !== 'string') {
      throw new Error('Role must be a non-empty string');
    }
    
    if (!resource || typeof resource !== 'string') {
      throw new Error('Resource must be a non-empty string');
    }
    
    // Get a fresh copy of the config
    const config = this.engine.getConfig();

    // Early return if role or resource doesn't exist
    if (!config.roles[role] || !config.roles[role].permissions[resource]) {
      return;
    }

    // If no permission specified, revoke all permissions on the resource
    if (!permission) {
      // Use a safer approach than 'delete'
      config.roles[role].permissions[resource] = [];
      this.engine.updateConfig(config);
      
      // Audit log
      console.info(`Revoke all: Role=${role}, Resource=${resource}`);
      
      // Clear cache for this role
      this.clearCache();
      return;
    }

    const permissions = Array.isArray(permission) ? permission : [permission];
    
    // Validate each permission
    for (const p of permissions) {
      if (!p || typeof p !== 'string') {
        throw new Error('Each permission must be a non-empty string');
      }
    }
    
    // Filter out permissions to revoke
    config.roles[role].permissions[resource] = config.roles[role].permissions[resource].filter(
      (p) => !permissions.includes(p),
    );

    // If no permissions left, set to empty array instead of deleting
    if (config.roles[role].permissions[resource].length === 0) {
      config.roles[role].permissions[resource] = [];
    }

    // Update the configuration atomically
    this.engine.updateConfig(config);

    // Audit log the permission change
    console.info(`Revoke: Role=${role}, Resource=${resource}, Permissions=${permissions.join(',')}`);
    
    // Clear cache for this role
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
    auditLog?: boolean; // Whether to log access attempts
  }): Middleware {
    return async (req: Request, res: Response, next: NextFunction) => {
      let resource: Resource = '';
      let permission: Permission = '';
      
      try {
        // Get user roles
        let roles: Role[] = [];
        try {
          roles = await options.getUserRoles(req);
          // Validate each role is a string
          if (!Array.isArray(roles)) {
            throw new Error('User roles must be an array');
          }
        } catch (roleError) {
          // Log the error but proceed with empty roles (will deny access)
          console.error('Error getting user roles:', roleError);
          roles = [];
        }

        // Determine resource and permission from request
        try {
          resource = typeof options.resource === 'function' 
            ? options.resource(req) 
            : options.resource;
        } catch (resourceError) {
          // Log the error but deny access
          console.error('Error determining resource:', resourceError);
          RBACManager.denyAccess('Invalid resource', res, req, next, options.onDenied);
          return;
        }

        try {
          permission = typeof options.permission === 'function'
            ? options.permission(req)
            : options.permission;
        } catch (permissionError) {
          // Log the error but deny access
          console.error('Error determining permission:', permissionError);
          RBACManager.denyAccess('Invalid permission', res, req, next, options.onDenied);
          return;
        }
        
        // Audit logging
        if (options.auditLog) {
          const userId = (req.user?.id) ? req.user.id : 'unknown';
          console.info(`Access attempt: User=${userId}, Roles=${JSON.stringify(roles)}, Resource=${resource}, Permission=${permission}`);
        }

        // Check if user has permission with secure error handling
        let allowed = false;
        try {
          allowed = this.engine.userCan(roles, resource, permission);
        } catch (permissionCheckError) {
          console.error('Error checking permissions:', permissionCheckError);
          // Default to deny on errors
          allowed = false;
        }

        if (allowed) {
          if (options.auditLog) {
            console.info(`Access granted: Resource=${resource}, Permission=${permission}`);
          }
          next();
        } else {
          if (options.auditLog) {
            console.info(`Access denied: Resource=${resource}, Permission=${permission}`);
          }
          RBACManager.denyAccess(`You don't have permission to ${permission} on ${resource}`, res, req, next, options.onDenied);
        }
      } catch (error) {
        // Catch-all error handler to ensure we always deny on errors
        console.error('Middleware error:', error);
        RBACManager.denyAccess('Access denied due to an internal error', res, req, next, options.onDenied);
      }
    };
  }
  
  /**
   * Helper function to handle access denial
   * @private
   */
  private static denyAccess(
    message: string,
    res: Response,
    req: Request,
    next: NextFunction,
    onDenied?: (req: Request, res: Response, next: NextFunction) => void
  ): void {
    if (onDenied) {
      try {
        onDenied(req, res, next);
      } catch (error) {
        // If custom onDenied handler fails, fall back to default
        console.error('Error in onDenied handler:', error);
        res.status(403).json({
          error: 'Forbidden',
          message: message
        });
      }
    } else {
      res.status(403).json({
        error: 'Forbidden',
        message: message
      });
    }
  }
}
