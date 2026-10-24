import { createHmac } from 'crypto';
import { inject, injectable } from 'inversify';
import nodemailer from 'nodemailer';
import type { IChannelDispatcher, IPushSender } from '../../application/ports/ports.js';
import { TYPES } from '../../shared/tokens.js';

const TIMEOUT_MS = 10_000;

function isDiscordWebhook(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:'
      && /^(?:(?:canary|ptb)\.)?discord(?:app)?\.com$/.test(url.hostname)
      && /^\/api\/(?:v\d+\/)?webhooks\/\d+\/[^/]+\/?$/.test(url.pathname);
  } catch {
    return false;
  }
}

async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<void> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(err instanceof Error && err.name === 'TimeoutError' ? 'timed out' : 'could not connect');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

@injectable()
export class ChannelDispatcher implements IChannelDispatcher {
  constructor(@inject(TYPES.IPushSender) private readonly pusher?: IPushSender) {}

  async send(
    channel: Parameters<IChannelDispatcher['send']>[0],
    message: Parameters<IChannelDispatcher['send']>[1],
  ): Promise<void> {
    const v = channel.values;
    const full = `${message.subject}\n${message.text}`;
    switch (channel.kind) {
      case 'push':
        if (!this.pusher) throw new Error('push is not available');
        return this.pusher.send({ subject: message.subject, text: message.text, ...(message.data ? { data: message.data } : {}) });
      case 'slack':
        return post(v['url'] ?? '', { text: full, ...(v['channel'] ? { channel: v['channel'] } : {}) });
      case 'telegram':
        return post(`https://api.telegram.org/bot${encodeURIComponent(v['token'] ?? '')}/sendMessage`, { chat_id: v['chat'], text: full });
      case 'webhook': {
        if (isDiscordWebhook(v['url'] ?? '')) {
          // Discord accepts content instead of the generic CTI webhook envelope.
          let remaining = full;
          while (remaining.length) {
            let end = Math.min(2000, remaining.length);
            // Keep UTF-16 surrogate pairs together at message boundaries.
            if (end < remaining.length && /[\uD800-\uDBFF]/.test(remaining[end - 1]!)) end--;
            await post(v['url']!, { content: remaining.slice(0, end), allowed_mentions: { parse: [] } });
            remaining = remaining.slice(end);
          }
          return;
        }
        const body = { subject: message.subject, text: message.text, at: new Date().toISOString() };
        const sig: Record<string, string> = v['secret'] ? { 'x-cti-signature': createHmac('sha256', v['secret']).update(JSON.stringify(body)).digest('hex') } : {};
        return post(v['url'] ?? '', body, sig);
      }
      case 'smtp': {
        const port = Number(v['port']);
        const transport = nodemailer.createTransport({
          host: v['host'], port, secure: port === 465, connectionTimeout: TIMEOUT_MS, greetingTimeout: TIMEOUT_MS, socketTimeout: TIMEOUT_MS,
        });
        try {
          await transport.sendMail({
            from: v['from'], to: message.to ?? v['to'], subject: message.subject, text: message.text, attachments: message.attachments,
          });
        } catch (err) {
          throw new Error(err instanceof Error ? err.message : 'delivery failed');
        }
        return;
      }
    }
  }
}
