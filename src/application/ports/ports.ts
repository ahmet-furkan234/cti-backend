import type { SyncJobData } from '../../domain/sync/sync-job.js';

export interface ILogger {
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
  debug(obj: unknown, msg?: string): void;
}

export interface IPasswordHasher {
  hash(plain: string): Promise<string>;
  verify(hash: string, plain: string): Promise<boolean>;
}

export interface AccessTokenClaims {
  sub: string;
}

export interface ITokenService {
  signAccessToken(userId: string): { token: string; expiresInSeconds: number };
  verifyAccessToken(token: string): AccessTokenClaims | null;
  /** Opaque random token (refresh / invite / reset) and its storage hash. */
  generateOpaqueToken(): { token: string; hash: string };
  hashOpaqueToken(token: string): string;
}

/** Hands sync requests to the cti-sync-worker service (BullMQ over Redis). */
export interface ISyncJobQueue {
  /** Rejects when the queue backend is unreachable so callers can answer 503 instead of pretending it worked. */
  enqueue(job: SyncJobData): Promise<void>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

/** Delivers a message through one configured alert channel; rejects with a human-readable reason. */
export interface IChannelDispatcher {
  send(channel: { kind: 'slack' | 'smtp' | 'telegram' | 'webhook'; values: Record<string, string> }, message: {
    subject: string;
    text: string;
    /** e-mail only: overrides the channel's own recipient */
    to?: string;
    attachments?: { filename: string; content: string }[];
  },
  ): Promise<void>;
}
