import { describe, expect, it } from 'vitest';
import { allowedKeys, computeEffectivePermissions } from './effective-permissions.js';

describe('computeEffectivePermissions', () => {
  const roleGrants = [
    { key: 'cve:read', roleName: 'viewer' },
    { key: 'cve:read', roleName: 'analyst' },
    { key: 'dashboard:view', roleName: 'viewer' },
  ];

  it('unions permissions from all roles and tracks their sources', () => {
    const result = computeEffectivePermissions(roleGrants, []);
    expect(allowedKeys(result)).toEqual(['cve:read', 'dashboard:view']);
    expect(result[0]?.source).toEqual({ type: 'role', roles: ['viewer', 'analyst'] });
  });

  it('adds user grants on top of roles', () => {
    const result = computeEffectivePermissions(roleGrants, [{ key: 'user:read', effect: 'grant' }]);
    expect(allowedKeys(result)).toContain('user:read');
  });

  it('deny wins over a role grant and over a user grant', () => {
    const result = computeEffectivePermissions(roleGrants, [
      { key: 'cve:read', effect: 'deny' },
      { key: 'x:y', effect: 'grant' },
      { key: 'x:y', effect: 'deny' },
    ]);
    expect(allowedKeys(result)).toEqual(['dashboard:view']);
    expect(result.find((p) => p.key === 'cve:read')?.allowed).toBe(false);
  });
});
