import { describe, expect, it } from 'vitest';
import { assertCanGrant, assertCanManageUser, assertPlatformKeysAllowed, assertRolesAssignable, loadCompanyUser } from './access-guard.js';
import { tenant } from '../../shared/tenant.js';
import type { IUserRepository } from '../../domain/user/user.repository.interface.js';
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

describe('company isolation', () => {
  const inCompany = <T>(platform: boolean, fn: () => T) => tenant.run({ companyId: 'c1', platform }, fn);

  it('hides users of another company', async () => {
    const users = { findById: async () => ({ id: 'u', companyId: 'c2' }) } as unknown as IUserRepository;
    await expect(inCompany(false, () => loadCompanyUser(users, 'u'))).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const own = { findById: async () => ({ id: 'u', companyId: 'c1' }) } as unknown as IUserRepository;
    await expect(inCompany(false, () => loadCompanyUser(own, 'u'))).resolves.toMatchObject({ id: 'u' });
  });

  it('refuses a company scope that is missing instead of leaking everything', () => {
    expect(() => tenant.id()).toThrowError(/No company in scope/);
  });

  it('keeps company management permissions inside the platform company', () => {
    expect(() => inCompany(false, () => assertPlatformKeysAllowed(['company:manage']))).toThrowError(/company:manage/);
    expect(() => inCompany(true, () => assertPlatformKeysAllowed(['company:manage']))).not.toThrow();
    expect(() => inCompany(false, () => assertPlatformKeysAllowed(['asset:read']))).not.toThrow();
  });

  it('reserves super_admin for the platform company', () => {
    const superAdmin = [{ name: 'super_admin', permissionKeys: ['asset:read'] }];
    expect(() => inCompany(false, () => assertRolesAssignable(superAdmin))).toThrowError(/super_admin/);
    expect(() => inCompany(true, () => assertRolesAssignable(superAdmin))).not.toThrow();
    expect(() => inCompany(false, () => assertRolesAssignable([{ name: 'company_admin', permissionKeys: ['asset:read'] }]))).not.toThrow();
  });
});
