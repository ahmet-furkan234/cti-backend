export type OverrideEffect = 'grant' | 'deny';

export interface PermissionOverride {
  key: string;
  effect: OverrideEffect;
}

export interface RoleGrant {
  key: string;
  roleName: string;
}

export interface EffectivePermission {
  key: string;
  /** How the permission was resolved. */
  source: { type: 'role'; roles: string[] } | { type: 'grant' } | { type: 'deny' };
  allowed: boolean;
}

/**
 * effective = (role permissions ∪ user grants) − user denies. Deny always wins.
 */
export function computeEffectivePermissions(
  roleGrants: RoleGrant[],
  overrides: PermissionOverride[],
): EffectivePermission[] {
  const byKey = new Map<string, EffectivePermission>();

  for (const g of roleGrants) {
    const existing = byKey.get(g.key);
    if (existing && existing.source.type === 'role') {
      existing.source.roles.push(g.roleName);
    } else {
      byKey.set(g.key, { key: g.key, source: { type: 'role', roles: [g.roleName] }, allowed: true });
    }
  }
  for (const o of overrides) {
    if (o.effect === 'grant') {
      if (!byKey.has(o.key)) byKey.set(o.key, { key: o.key, source: { type: 'grant' }, allowed: true });
    } else {
      byKey.set(o.key, { key: o.key, source: { type: 'deny' }, allowed: false });
    }
  }
  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export function allowedKeys(list: EffectivePermission[]): string[] {
  return list.filter((p) => p.allowed).map((p) => p.key);
}
