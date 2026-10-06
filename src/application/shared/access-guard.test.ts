import { describe, expect, it } from 'vitest';
import { assertCanGrant, assertCanManageUser } from './access-guard.js';
import type { EffectivePermissionService } from './effective-permission.service.js';

const permsOf = (target: string[]) =>
  ({ getDetailed: async () => target.map((key) => ({ key, allowed: true, source: { type: 'grant' } })) }) as unknown as EffectivePermissionService;

describe('assertCanManageUser', () => {
  it('rejects managing a user who holds permissions the actor lacks (admin → super_admin takeover)', async () => {
    await expect(assertCanManageUser(permsOf(['user:read', 'role:manage']), ['user:read', 'user:update'], 'x')).rejects.toMatchObject({
      code: 'INSUFFICIENT_PRIVILEGE',
    });
  });

  it('allows managing users whose permissions are a subset of the actor’s', async () => {
    await expect(assertCanManageUser(permsOf(['cve:read']), ['cve:read', 'user:update'], 'x')).resolves.toBeUndefined();
  });
});

describe('assertCanGrant', () => {
  it('rejects granting permissions the actor does not hold', () => {
    expect(() => assertCanGrant(['cve:read'], ['cve:read', 'role:manage'])).toThrowError(/role:manage/);
  });
});
