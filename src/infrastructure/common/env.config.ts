import { injectable } from 'inversify';
import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((v) => v === 'true');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().default(4000),
  DATABASE_URL: z.string().min(1),
  ALLOWED_ORIGINS: z.string().default('http://localhost:5173'),
  WEB_BASE_URL: z.string().default('http://localhost:5173'),
  TRUST_PROXY: z.coerce.number().int().default(0),
  /** BullMQ backing store shared with cti-sync-worker. */
  REDIS_URL: z.string().default('redis://localhost:6390'),
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 chars'),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(14),
  COOKIE_SECURE: bool.default(false),
  SEED_ADMIN_EMAIL: z.string().email().optional(),
  SEED_ADMIN_PASSWORD: z.string().min(12).optional(),
  LOG_LEVEL: z.string().default('info'),
});

@injectable()
export class EnvConfig {
  readonly NODE_ENV: 'development' | 'production' | 'test';
  readonly PORT: number;
  readonly DATABASE_URL: string;
  readonly ALLOWED_ORIGINS: string[];
  readonly WEB_BASE_URL: string;
  readonly TRUST_PROXY: number;
  readonly REDIS_URL: string;
  readonly JWT_ACCESS_SECRET: string;
  readonly JWT_ACCESS_EXPIRES_IN: string;
  readonly REFRESH_TOKEN_TTL_DAYS: number;
  readonly COOKIE_SECURE: boolean;
  readonly SEED_ADMIN_EMAIL: string | undefined;
  readonly SEED_ADMIN_PASSWORD: string | undefined;
  readonly LOG_LEVEL: string;

  constructor() {
    const parsed = envSchema.safeParse(process.env);
    if (!parsed.success) {
      const lines = parsed.error.issues.map((i) => `  [${i.path.join('.')}] ${i.message}`).join('\n');
      throw new Error(`Invalid environment configuration:\n${lines}`);
    }
    const e = parsed.data;
    this.NODE_ENV = e.NODE_ENV;
    this.PORT = e.PORT;
    this.DATABASE_URL = e.DATABASE_URL;
    this.ALLOWED_ORIGINS = e.ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
    this.WEB_BASE_URL = e.WEB_BASE_URL.replace(/\/$/, '');
    this.TRUST_PROXY = e.TRUST_PROXY;
    this.REDIS_URL = e.REDIS_URL;
    this.JWT_ACCESS_SECRET = e.JWT_ACCESS_SECRET;
    this.JWT_ACCESS_EXPIRES_IN = e.JWT_ACCESS_EXPIRES_IN;
    this.REFRESH_TOKEN_TTL_DAYS = e.REFRESH_TOKEN_TTL_DAYS;
    this.COOKIE_SECURE = e.COOKIE_SECURE;
    this.SEED_ADMIN_EMAIL = e.SEED_ADMIN_EMAIL;
    this.SEED_ADMIN_PASSWORD = e.SEED_ADMIN_PASSWORD;
    this.LOG_LEVEL = e.LOG_LEVEL;
  }
}
