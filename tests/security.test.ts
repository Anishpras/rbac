/**
 * Security-focused tests for the RBAC system
 */
import { RBACManager, RBACBuilder } from '../src';

describe('RBAC Security Tests', () => {
  describe('Input Validation', () => {
    let rbac: RBACManager;

    beforeEach(() => {
      const config = new RBACBuilder()
        .role('ADMIN', 'Administrator')
          .grantFullAccess('Products')
          .done()
        .role('EDITOR', 'Editor')
          .forResource('Products').grant('READ', 'UPDATE').done()
        .build();

      rbac = new RBACManager(config);
    });

    test('rejects invalid role names', () => {
      expect(() => {
        rbac.grant('', 'Products', 'READ');
      }).toThrow();

      expect(() => {
        rbac.grant(null as any, 'Products', 'READ');
      }).toThrow();
    });

    test('rejects invalid resource names', () => {
      expect(() => {
        rbac.grant('EDITOR', '', 'READ');
      }).toThrow();

      expect(() => {
        rbac.grant('EDITOR', null as any, 'READ');
      }).toThrow();
    });

    test('rejects invalid permission values', () => {
      expect(() => {
        rbac.grant('EDITOR', 'Products', '');
      }).toThrow();

      expect(() => {
        rbac.grant('EDITOR', 'Products', null as any);
      }).toThrow();

      expect(() => {
        rbac.grant('EDITOR', 'Products', [] as any[]);
      }).toThrow();
    });
  });

  describe('Role Hierarchy Security', () => {
    let rbac: RBACManager;

    beforeEach(() => {
      const config = new RBACBuilder()
        .role('ADMIN', 'Administrator')
          .grantFullAccess('Products')
          .done()
        .role('EDITOR', 'Editor')
          .forResource('Products').grant('READ', 'UPDATE').done()
        .role('VIEWER', 'Viewer')
          .forResource('Products').grant('READ').done()
        .build();

      rbac = new RBACManager(config);
    });

    test('detects circular role references', () => {
      expect(() => {
        rbac.setRoleHierarchy({
          'ADMIN': ['EDITOR'],
          'EDITOR': ['ADMIN'] // Circular reference
        });
      }).toThrow(/circular reference/i);
    });

    test('detects indirect circular role references', () => {
      expect(() => {
        rbac.setRoleHierarchy({
          'ADMIN': ['EDITOR'],
          'EDITOR': ['VIEWER'],
          'VIEWER': ['ADMIN'] // Indirect circular reference
        });
      }).toThrow(/circular reference/i);
    });

    test('allows valid role hierarchies', () => {
      expect(() => {
        rbac.setRoleHierarchy({
          'VIEWER': ['EDITOR'],
          'EDITOR': ['ADMIN']
        });
      }).not.toThrow();
    });
  });

  describe('Default Deny Behavior', () => {
    let rbac: RBACManager;

    beforeEach(() => {
      const config = new RBACBuilder()
        .role('ADMIN', 'Administrator')
          // Use specific permissions instead of grantFullAccess
          .forResource('Products').grant('CREATE', 'READ', 'UPDATE', 'DELETE').done()
        .build();

      rbac = new RBACManager(config);
    });

    test('denies access for unknown roles', () => {
      expect(rbac.can('UNKNOWN_ROLE', 'Products', 'READ')).toBe(false);
    });

    test('denies access for unknown resources', () => {
      expect(rbac.can('ADMIN', 'UNKNOWN_RESOURCE', 'READ')).toBe(false);
    });

    test('denies access for unknown permissions', () => {
      expect(rbac.can('ADMIN', 'Products', 'UNKNOWN_PERMISSION')).toBe(false);
    });

    test('denies access when user has empty roles', () => {
      expect(rbac.userCan([], 'Products', 'READ')).toBe(false);
    });

    test('safely handles errors in user can check', () => {
      const user = null as any;
      // Should not throw but return false
      expect(rbac.userCan(user, 'Products', 'READ')).toBe(false);
    });
  });

  describe('Secure Policy Evaluation', () => {
    let rbac: RBACManager;

    beforeEach(() => {
      const config = new RBACBuilder()
        .role('ADMIN', 'Administrator')
          // Use specific permissions instead of grantFullAccess
          .forResource('Products').grant('CREATE', 'READ', 'UPDATE', 'DELETE').done()
        .build();

      rbac = new RBACManager(config);
    });

    test('safely handles invalid policies', () => {
      const result = rbac.evaluatePolicy({} as any);
      expect(result.allowed).toBe(false);
    });

    test('safely handles policies with missing fields', () => {
      const result = rbac.evaluatePolicy({
        role: 'ADMIN',
        // Missing resource and permission
      } as any);
      expect(result.allowed).toBe(false);
    });

    test('does not expose error details in policy result', () => {
      const result = rbac.evaluatePolicy({
        role: 'ADMIN',
        resource: null as any,
        permission: 'READ'
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).not.toContain('TypeError');
      expect(result.reason).not.toContain('undefined');
    });
  });
});
