import type { BatchResponse, MulticastMessage } from 'firebase-admin/messaging';
import { describe, expect, it } from 'vitest';
import { deliverToTokens, pushBody, pushTitle, type FcmMessaging } from './fcm-push.js';

const ok = { success: true } as const;
const fail = (code: string, message = code) => ({ success: false, error: { code, message } }) as never;

const batch = (responses: unknown[]): BatchResponse => ({
  responses: responses as BatchResponse['responses'],
  successCount: responses.filter((r) => (r as { success: boolean }).success).length,
  failureCount: responses.filter((r) => !(r as { success: boolean }).success).length,
});

const message = { subject: '[CTI] KEV', text: 'CVE-2024-1 on fw-edge-01', data: { cve: 'CVE-2024-1' } };

describe('deliverToTokens', () => {
  it('sends a high-priority notification with the CVE in data', async () => {
    const sent: MulticastMessage[] = [];
    const messaging: FcmMessaging = { sendEachForMulticast: async (m) => { sent.push(m); return batch([ok]); } };

    const res = await deliverToTokens(messaging, ['t1'], message);

    expect(res).toEqual({ delivered: 1, dead: [], lastError: null });
    expect(sent[0]).toMatchObject({
      tokens: ['t1'],
      notification: { title: 'KEV', body: 'CVE-2024-1 on fw-edge-01' },
      data: { cve: 'CVE-2024-1' },
      android: { priority: 'high', notification: { channelId: 'alerts', color: '#5EB1FF' } },
    });
  });

  it('reports permanently dead tokens so they can be purged, and keeps the delivered count', async () => {
    const messaging: FcmMessaging = {
      sendEachForMulticast: async () => batch([ok, fail('messaging/registration-token-not-registered'), fail('messaging/internal-error')]),
    };

    const res = await deliverToTokens(messaging, ['a', 'b', 'c'], message);

    expect(res.delivered).toBe(1);
    expect(res.dead).toEqual(['b']);
    expect(res.lastError).toBe('messaging/internal-error');
  });

  it('splits more than 500 tokens into batches', async () => {
    const sizes: number[] = [];
    const messaging: FcmMessaging = {
      sendEachForMulticast: async (m) => { sizes.push(m.tokens.length); return batch(m.tokens.map(() => ok)); },
    };

    const res = await deliverToTokens(messaging, Array.from({ length: 1100 }, (_, i) => `t${i}`), message);

    expect(sizes).toEqual([500, 500, 100]);
    expect(res.delivered).toBe(1100);
  });

  it('survives a failing batch and reports its error', async () => {
    let calls = 0;
    const messaging: FcmMessaging = {
      sendEachForMulticast: async (m) => {
        if (calls++ === 0) throw new Error('quota exceeded');
        return batch(m.tokens.map(() => ok));
      },
    };

    const res = await deliverToTokens(messaging, Array.from({ length: 501 }, (_, i) => `t${i}`), message);

    expect(res.delivered).toBe(1);
    expect(res.lastError).toBe('quota exceeded');
  });

  it('truncates a long title and body to what a notification can show', async () => {
    const sent: MulticastMessage[] = [];
    const messaging: FcmMessaging = { sendEachForMulticast: async (m) => { sent.push(m); return batch([ok]); } };

    await deliverToTokens(messaging, ['t'], { subject: 'x'.repeat(300), text: 'y'.repeat(2000) });

    expect(sent[0]?.notification?.title).toHaveLength(100);
    expect(sent[0]?.notification?.body).toHaveLength(500);
  });
});

describe('push text', () => {
  it('drops the [CTI] prefix from the title, whatever its case or spacing', () => {
    expect(pushTitle('[CTI] Push · KEV')).toBe('Push · KEV');
    expect(pushTitle('  [cti]   Test message')).toBe('Test message');
    expect(pushTitle('No prefix')).toBe('No prefix');
    expect(pushTitle('[CTI]')).toBe('CTI');
  });

  it('turns chat-style lines into short notification lines and drops the bullets', () => {
    const text = ['• CVE-2023-44487 × test-web-01 (CVSS 7.5, risk 92)', '• CVE-2024-23897 × jenkins-ci (CVSS 9.8, risk 84)', '…and 4 more'].join('\n');
    expect(pushBody(text)).toBe(
      ['CVE-2023-44487 · test-web-01 · CVSS 7.5 · risk 92', 'CVE-2024-23897 · jenkins-ci · CVSS 9.8 · risk 84', '…and 4 more'].join('\n'),
    );
  });

  it('keeps lines of any other shape untouched apart from the bullet', () => {
    expect(pushBody('229 open · 9 known-exploited · 9 critical')).toBe('229 open · 9 known-exploited · 9 critical');
    expect(pushBody('• nvd: HTTP 503')).toBe('nvd: HTTP 503');
    expect(pushBody('CVE-2024-23897 × fw-01 (6 h overdue)')).toBe('CVE-2024-23897 · fw-01 · 6 h overdue');
    // not a CVE id: left as it is
    expect(pushBody('CVE-2024-1 × fw-01 (x)')).toBe('CVE-2024-1 × fw-01 (x)');
  });
});
