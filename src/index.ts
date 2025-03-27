/**
 * RABAC - Role and Attribute Based Access Control
 * A fast, flexible, and type-safe authorization system for TypeScript/JavaScript applications
 */

// Export core components
export { RBACManager } from './core/manager';
export { RBACEngine } from './core/engine';
export { RBACBuilder, RoleBuilder, ResourceBuilder } from './core/builder';

// Export types
export * from './types';

// Export utilities
export { PermissionCache } from './utils/cache';
export { defaultLogger, silentLogger } from './utils/logger';

// Default export for easier imports
import { RBACManager } from './core/manager';
export default RBACManager;
