import { createHmac } from 'crypto';
import { injectable } from 'inversify';
import nodemailer from 'nodemailer';
import type { IChannelDispatcher } from '../../application/ports/ports.js';

const TIMEOUT_MS = 10_000;

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
  async send(
    channel: Parameters<IChannelDispatcher['send']>[0],
    message: Parameters<IChannelDispatcher['send']>[1],
  ): Promise<void> {
    const v = channel.values;
    const full = `${message.subject}\n${message.text}`;
    switch (channel.kind) {
      case 'slack':
        return post(v['url'] ?? '', { text: full, ...(v['channel'] ? { channel: v['channel'] } : {}) });
      case 'telegram':
        return post(`https://api.telegram.org/bot${encodeURIComponent(v['token'] ?? '')}/sendMessage`, { chat_id: v['chat'], text: full });
      case 'webhook': {
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
