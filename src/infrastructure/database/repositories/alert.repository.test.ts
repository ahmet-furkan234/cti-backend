import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { PgDialect } from 'drizzle-orm/pg-core';
import type { SQL } from 'drizzle-orm';
import { AlertRepository } from './alert.repository.js';
import type { Database } from '../client.js';
import type { Rule } from '../../../domain/alerts/alert.repository.interface.js';
import { tenant } from '../../../shared/tenant.js';
import { ruleBody, updateRuleBody } from '../../http/schemas/schemas.js';

const assetId = '00000000-0000-4000-8000-000000000001';
const base = { name: 'Selected assets', trigger: 'critical' as const, envs: [], minRisk: 0, exposedOnly: false, tag: '', channelIds: [], throttle: 'every' as const, enabled: true };
describe('alert asset scope', () => {
  it('accepts asset IDs, rejects invalid IDs, and preserves scope on unrelated patches', () => {
    expect(ruleBody.parse({ ...base, assetIds: [assetId] }).assetIds).toEqual([assetId]);
    expect(ruleBody.safeParse({ ...base, assetIds: ['invalid'] }).success).toBe(false);
    expect(updateRuleBody.parse({ enabled: false })).not.toHaveProperty('assetIds');
  });
  for (const mode of ['critical', 'sla'] as const) {
    it(`restricts ${mode} matches to selected assets within the current company`, async () => {
      const execute = vi.fn(async (_query: SQL) => ({ rows: [] }));
      const repo = new AlertRepository({ execute } as unknown as Database);
      const rule = { ...base, assetIds: [assetId], envs: ['prod'], id: 'rule', lastFiredAt: null, evaluatedAt: new Date(), fired30: 0 } satisfies Rule;
      await tenant.run({ companyId: 'company-a', platform: false }, () => mode === 'sla' ? repo.slaMatches(rule, 24) : repo.newMatches(rule, new Date(), 'critical'));
      const query = new PgDialect().sqlToQuery(execute.mock.calls[0]![0]);
      expect(query.sql).toContain('a.id = any(');
      expect(query.sql).toContain('a.company_id =');
      expect(query.params).toEqual(expect.arrayContaining([assetId, 'company-a', 'prod']));
    });
  }
  it('leaves legacy all-asset rules unrestricted by asset ID', async () => {
    const execute = vi.fn(async (_query: SQL) => ({ rows: [] }));
    const repo = new AlertRepository({ execute } as unknown as Database);
    const rule = { ...base, id: 'rule', lastFiredAt: null, evaluatedAt: new Date(), fired30: 0 } satisfies Rule;
    await tenant.run({ companyId: 'company-a', platform: false }, () => repo.newMatches(rule, new Date(), 'critical'));
    expect(new PgDialect().sqlToQuery(execute.mock.calls[0]![0]).sql).not.toContain('a.id = any(');
  });
});
