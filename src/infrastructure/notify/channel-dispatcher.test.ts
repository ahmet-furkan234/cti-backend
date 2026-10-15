import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHmac } from 'node:crypto';
import { ChannelDispatcher } from './channel-dispatcher.js';

const url = 'https://discord.com/api/webhooks/123/test-token';
afterEach(() => vi.unstubAllGlobals());

function mockPost() {
  const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('webhook delivery', () => {
  it('sends Discord content without triggering mentions', async () => {
    const fetch = mockPost();
    await new ChannelDispatcher().send({ kind: 'webhook', values: { url } }, { subject: 'Test', text: '@everyone hello' });
    expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({ content: 'Test\n@everyone hello', allowed_mentions: { parse: [] } });
  });

  it('splits long messages without losing text or breaking emoji', async () => {
    const fetch = mockPost();
    const text = 'a'.repeat(1997) + '😀' + 'b'.repeat(2200);
    await new ChannelDispatcher().send({ kind: 'webhook', values: { url } }, { subject: 'S', text });
    const parts = fetch.mock.calls.map((call) => JSON.parse(call[1].body).content as string);
    expect(parts.join('')).toBe(`S\n${text}`);
    expect(parts.every((part) => part.length <= 2000 && part.isWellFormed())).toBe(true);
  });

  it.each(['https://example.com/hook', 'https://discord.com.evil.test/api/webhooks/123/token'])('preserves generic signed webhook format for %s', async (url) => {
    const fetch = mockPost();
    await new ChannelDispatcher().send({ kind: 'webhook', values: { url, secret: 'test-secret' } }, { subject: 'Test', text: 'Body' });
    const request = fetch.mock.calls[0]![1];
    expect(JSON.parse(request.body)).toEqual({ subject: 'Test', text: 'Body', at: expect.any(String) });
    expect(request.headers['x-cti-signature']).toBe(createHmac('sha256', 'test-secret').update(request.body).digest('hex'));
  });

  it('propagates a rejected delivery', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 400 })));
    await expect(new ChannelDispatcher().send({ kind: 'webhook', values: { url } }, { subject: 'Test', text: 'Body' })).rejects.toThrow('HTTP 400');
  });
});
