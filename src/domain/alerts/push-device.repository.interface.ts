export type PushPlatform = 'ios' | 'android';

/** Mobile app installs that may receive push alerts. */
export interface IPushDeviceRepository {
  /** Binds the token to this user in the current company (a token moves with whoever signed in last). */
  upsert(token: string, userId: string, platform: PushPlatform): Promise<void>;
  remove(token: string, userId: string): Promise<void>;
  /** Tokens of the current company's active users that can read alerts. */
  tokensForCurrentCompany(): Promise<string[]>;
  /** Drops tokens FCM reported as dead (app uninstalled, permission revoked). */
  purge(tokens: string[]): Promise<void>;
}
