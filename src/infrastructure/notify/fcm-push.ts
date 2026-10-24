import { readFileSync } from 'node:fs';
import { cert, getApps, initializeApp, type App } from 'firebase-admin/app';
import { getMessaging, type BatchResponse, type MulticastMessage } from 'firebase-admin/messaging';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IPushSender } from '../../application/ports/ports.js';
import type { IPushDeviceRepository } from '../../domain/alerts/push-device.repository.interface.js';
import type { EnvConfig } from '../common/env.config.js';

/** FCM accepts at most 500 tokens per multicast call. */
const BATCH = 500;

/** Error codes that mean the token will never work again (app uninstalled, data cleared, token rotated). */
const DEAD_TOKEN_CODES = new Set(['messaging/registration-token-not-registered', 'messaging/invalid-registration-token', 'messaging/invalid-argument']);

/** The one FCM call this module makes; narrowed so tests can stand in for Firebase. */
export interface FcmMessaging {
  sendEachForMulticast(message: MulticastMessage): Promise<BatchResponse>;
}

/** Accent color of the notification (the app's blue); Android tints the small icon and the app name with it. */
const ACCENT = '#5EB1FF';

/** "[CTI] KEV rule" -> "KEV rule": the app name is already shown above every notification. */
export function pushTitle(subject: string): string {
  return subject.replace(/^\s*\[CTI\]\s*/i, '').trim().slice(0, 100) || 'CTI';
}

/**
 * Chat-style lines ("• CVE-2024-1 × fw-01 (CVSS 9.8, risk 92)") become short notification lines
 * ("CVE-2024-1 · fw-01 · CVSS 9.8 · risk 92"). Lines in any other shape are kept as they are, minus the bullet.
 */
export function pushBody(text: string): string {
  return text
    .split('\n')
    .map((raw) => {
      const line = raw.replace(/^\s*[•\-*]\s*/, '').trim();
      const m = /^(CVE-\d{4}-\d{4,}) × (.+?) \((.+)\)$/.exec(line);
      return m ? `${m[1]} · ${m[2]} · ${m[3]!.split(/,\s*/).join(' · ')}` : line;
    })
    .filter(Boolean)
    .join('\n')
    .slice(0, 500);
}

export interface PushMessage {
  subject: string;
  text: string;
  data?: Record<string, string>;
}

/** Sends `message` to every token, in batches, and returns the tokens FCM reported as permanently dead. */
export async function deliverToTokens(
  messaging: FcmMessaging,
  tokens: string[],
  message: PushMessage,
): Promise<{ delivered: number; dead: string[]; lastError: string | null }> {
  let delivered = 0;
  let lastError: string | null = null;
  const dead: string[] = [];

  for (let i = 0; i < tokens.length; i += BATCH) {
    const chunk = tokens.slice(i, i + BATCH);
    let res: BatchResponse;
    try {
      res = await messaging.sendEachForMulticast({
        tokens: chunk,
        notification: { title: pushTitle(message.subject), body: pushBody(message.text) },
        data: message.data ?? {},
        android: { priority: 'high', notification: { channelId: 'alerts', color: ACCENT } },
      });
    } catch (err) {
      lastError = err instanceof Error ? err.message : 'delivery failed';
      continue;
    }
    delivered += res.successCount;
    res.responses.forEach((r, idx) => {
      if (r.success) return;
      lastError = r.error?.message ?? lastError;
      const token = chunk[idx];
      if (token && r.error && DEAD_TOKEN_CODES.has(r.error.code)) dead.push(token);
    });
  }
  return { delivered, dead, lastError };
}

/** Sends alerts to the company's mobile app installs through Firebase Cloud Messaging (HTTP v1). */
@injectable()
export class FcmPushSender implements IPushSender {
  private app: App | null = null;

  constructor(
    @inject(TYPES.IPushDeviceRepository) private readonly devices: IPushDeviceRepository,
    @inject(TYPES.EnvConfig) private readonly config: EnvConfig,
  ) {}

  /** Lazily creates the Firebase app; a missing key is a readable channel error, not a startup crash. */
  private messaging(): FcmMessaging {
    if (!this.app) {
      const raw = this.config.FIREBASE_SERVICE_ACCOUNT_JSON ?? (this.config.FIREBASE_SERVICE_ACCOUNT_FILE ? readFileSync(this.config.FIREBASE_SERVICE_ACCOUNT_FILE, 'utf8') : null);
      if (!raw) throw new Error('Firebase is not configured (set FIREBASE_SERVICE_ACCOUNT_FILE or FIREBASE_SERVICE_ACCOUNT_JSON)');
      let account: Record<string, unknown>;
      try {
        account = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        throw new Error('Firebase service account is not valid JSON');
      }
      this.app = getApps().find((a) => a.name === 'cti') ?? initializeApp({ credential: cert(account as Parameters<typeof cert>[0]) }, 'cti');
    }
    return getMessaging(this.app);
  }

  async send(message: PushMessage): Promise<void> {
    const messaging = this.messaging();
    const tokens = await this.devices.tokensForCurrentCompany();
    if (tokens.length === 0) throw new Error('no devices registered');

    const { delivered, dead, lastError } = await deliverToTokens(messaging, tokens, message);
    if (dead.length) await this.devices.purge(dead);
    if (delivered === 0) throw new Error(lastError ?? 'delivery failed');
  }
}
