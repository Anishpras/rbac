import type { Permission, RBACConfig, Resource, Role } from "../types";

/**
 * RBAC Configuration Builder - Fluent API for building RBAC configurations
 */
export class RBACBuilder {
  private config: RBACConfig = {
    roles: {},
  };

  /**
   * Internal method to get the config reference (not a copy)
   * This is used by the builder methods to modify the config directly
   */
  public getConfigRef(): RBACConfig {
    return this.config;
  }

  /**
   * Creates a new role with optional description
   */
  public role(name: Role, description?: string): RoleBuilder {
    const roleBuilder = new RoleBuilder(this, name, description);

    this.config.roles[name] = {
      description,
      permissions: {},
    };

    return roleBuilder;
  }

  /**
   * Sets the default role
   */
  public setDefaultRole(role: Role): RBACBuilder {
    if (!this.config.roles[role]) {
      throw new Error(`Cannot set default role: Role "${role}" does not exist`);
    }

    this.config.defaultRole = role;
    return this;
  }

  /**
   * Extends a role with permissions from another role
   */
  public extendRole(role: Role, baseRole: Role): RBACBuilder {
    if (!this.config.roles[role]) {
      throw new Error(`Cannot extend role: Role "${role}" does not exist`);
    }

    if (!this.config.roles[baseRole]) {
      throw new Error(`Cannot extend role: Base role "${baseRole}" does not exist`);
    }

    // Copy permissions from base role
    const basePermissions = this.config.roles[baseRole].permissions;

    for (const resource in basePermissions) {
      if (!this.config.roles[role].permissions[resource]) {
        this.config.roles[role].permissions[resource] = [...basePermissions[resource]];
      } else {
        this.config.roles[role].permissions[resource] = [
          ...new Set([
            ...this.config.roles[role].permissions[resource],
            ...basePermissions[resource],
          ]),
        ];
      }
    }

    return this;
  }

  /**
   * Builds and returns the complete RBAC configuration
   */
  public build(): RBACConfig {
    // Return a deep copy to prevent external modifications
    return JSON.parse(JSON.stringify(this.config));
  }
}

/**
 * Role Builder - Fluent API for configuring a role
 */
export class RoleBuilder {
  private builder: RBACBuilder;
  private role: Role;
  private resource: Resource | null = null;

  constructor(builder: RBACBuilder, role: Role, description?: string) {
    this.builder = builder;
    this.role = role;
  }

  /**
   * Selects a resource to configure permissions for
   */
  public forResource(resource: Resource): ResourceBuilder {
    this.resource = resource;
    return new ResourceBuilder(this.builder, this.role, resource);
  }

  /**
   * Grants full access (all permissions) to a resource
   */
  public grantFullAccess(resource: Resource): RoleBuilder {
    // Removed wildcard (*) permission for better security
    const permissions: Permission[] = ["CREATE", "READ", "UPDATE", "DELETE", "VIEW"];
    const config = this.builder.getConfigRef();

    if (!config.roles[this.role].permissions[resource]) {
      config.roles[this.role].permissions[resource] = [];
    }

    config.roles[this.role].permissions[resource] = permissions;
    return this;
  }

  /**
   * Grants read-only access to a resource
   */
  public grantReadOnly(resource: Resource): RoleBuilder {
    const permissions: Permission[] = ["READ", "VIEW"];
    const config = this.builder.getConfigRef();

    if (!config.roles[this.role].permissions[resource]) {
      config.roles[this.role].permissions[resource] = [];
    }

    config.roles[this.role].permissions[resource] = permissions;
    return this;
  }

  /**
   * Returns the parent builder to continue building the configuration
   */
  public done(): RBACBuilder {
    return this.builder;
  }
}

/**
 * Resource Builder - Fluent API for configuring permissions on a resource
 */
export class ResourceBuilder {
  private builder: RBACBuilder;
  private role: Role;
  private resource: Resource;

  constructor(builder: RBACBuilder, role: Role, resource: Resource) {
    this.builder = builder;
    this.role = role;
    this.resource = resource;
  }

  /**
   * Grants specific permissions on the resource
   */
  public grant(...permissions: Permission[]): ResourceBuilder {
    const config = this.builder.getConfigRef();

    if (!config.roles[this.role].permissions[this.resource]) {
      config.roles[this.role].permissions[this.resource] = [];
    }

    config.roles[this.role].permissions[this.resource] = [
      ...new Set([...config.roles[this.role].permissions[this.resource], ...permissions]),
    ];

    return this;
  }

  /**
   * Grants all permissions on the resource
   */
  public grantAll(): ResourceBuilder {
    const config = this.builder.getConfigRef();

    if (!config.roles[this.role].permissions[this.resource]) {
      config.roles[this.role].permissions[this.resource] = [];
    }

    // Removed wildcard (*) permission for better security
    config.roles[this.role].permissions[this.resource] = [
      "CREATE",
      "READ",
      "UPDATE",
      "DELETE",
      "VIEW",
    ];
    return this;
  }

  /**
   * Grants read-only permissions on the resource
   */
  public grantReadOnly(): ResourceBuilder {
    const config = this.builder.getConfigRef();

    if (!config.roles[this.role].permissions[this.resource]) {
      config.roles[this.role].permissions[this.resource] = [];
    }

    config.roles[this.role].permissions[this.resource] = ["READ", "VIEW"];
    return this;
  }

  /**
   * Returns to the role builder to configure more resources
   */
  public forResource(resource: Resource): ResourceBuilder {
    this.resource = resource;
    return new ResourceBuilder(this.builder, this.role, resource);
  }

  /**
   * Returns to the role builder
   */
  public and(): RoleBuilder {
    return new RoleBuilder(this.builder, this.role);
  }

  /**
   * Returns the parent builder to continue building the configuration
   */
  public done(): RBACBuilder {
    return this.builder;
  }
}
