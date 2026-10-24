import { describe, expect, it } from 'vitest';
import type { Channel, NewLogEntry, Rule } from '../../domain/alerts/alert.repository.interface.js';
import { AlertEvaluatorService } from './alert-evaluator.service.js';

const channel: Channel = { id: 'ch-1', kind: 'push', name: 'phone', values: {}, status: 'healthy', problem: null, lastTestAt: null };

const rule = (trigger: Rule['trigger']): Rule => ({
  id: 'rule-1', name: 'r', trigger, envs: [], minRisk: 0, exposedOnly: false, tag: '', channelIds: [channel.id],
  throttle: trigger === 'digest' ? 'daily' : 'every', enabled: true, lastFiredAt: null, evaluatedAt: new Date('2026-01-01'),
});

function setup(newMatches: { assetId: string; host: string; cveId: string; risk: number; line: string }[] = []) {
  const logs: NewLogEntry[] = [];
  const evaluated: { id: string; fired: boolean }[] = [];
  const sent: { subject: string; data?: Record<string, string> }[] = [];
  const repo = {
    findChannel: async () => channel,
    updateChannel: async () => channel,
    addLog: async (e: NewLogEntry) => { logs.push(e); },
    markEvaluated: async (id: string, _at: Date, fired: boolean) => { evaluated.push({ id, fired }); },
    digestCounts: async () => ({ open: 4, kev: 1, critical: 2 }),
    newMatches: async () => newMatches,
  };
  const dispatcher = { send: async (_c: unknown, m: { subject: string; data?: Record<string, string> }) => { sent.push(m); } };
  const service = new AlertEvaluatorService(repo as never, {} as never, dispatcher as never, { error: () => undefined } as never);
  return { service, logs, evaluated, sent };
}

describe('AlertEvaluatorService', () => {
  it('logs a digest without an asset id (it is about no asset, and the log column is a uuid)', async () => {
    const { service, logs, evaluated } = setup();

    await service.evaluate(rule('digest'));

    expect(logs).toHaveLength(1);
    expect(logs[0]?.assetId).toBeNull();
    // The watermark moves on, so the rule does not fire again on the next tick.
    expect(evaluated).toEqual([{ id: 'rule-1', fired: true }]);
  });

  it('puts the CVE in the push data and the asset in the log when exactly one match fired', async () => {
    const { service, logs, sent } = setup([{ assetId: 'asset-1', host: 'fw-01', cveId: 'CVE-2024-1', risk: 90, line: 'CVE-2024-1 × fw-01' }]);

    await service.evaluate(rule('kev'));

    expect(sent[0]?.data).toEqual({ cve: 'CVE-2024-1' });
    expect(logs[0]?.assetId).toBe('asset-1');
  });

  it('sends no CVE data and logs no asset for several matches at once', async () => {
    const m = (n: number) => ({ assetId: `a${n}`, host: `h${n}`, cveId: `CVE-2024-${n}`, risk: 80, line: `l${n}` });
    const { service, logs, sent } = setup([m(1), m(2)]);

    await service.evaluate(rule('kev'));

    expect(sent[0]?.data).toBeUndefined();
    expect(logs[0]?.assetId).toBeNull();
  });
});
