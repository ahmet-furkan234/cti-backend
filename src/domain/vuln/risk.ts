export type VulnStatus = 'open' | 'in_progress' | 'accepted' | 'mitigated';

const ENV_POINTS: Record<string, number> = { prod: 10, staging: 6, dev: 3 };

export interface RiskInput {
  cvss: number;
  kev: boolean;
  epss: number;
  exposed: boolean;
  env: string;
}

/** Additive 0-100 score: CVSS 30 · KEV 25 · EPSS 20 · internet-facing 15 · environment 10. */
export function riskScore(r: RiskInput): number {
  const points =
    Math.round(r.cvss * 3) + (r.kev ? 25 : 0) + Math.round(r.epss * 20) + (r.exposed ? 15 : 0) + (ENV_POINTS[r.env] ?? 5);
  return Math.min(100, points);
}

const DAY = 24;
/** Fix window in hours: known-exploited first, then by CVSS band. */
export function slaWindowHours(r: { cvss: number; kev: boolean }): number {
  if (r.kev) return 3 * DAY;
  if (r.cvss >= 9) return 7 * DAY;
  if (r.cvss >= 7) return 30 * DAY;
  if (r.cvss >= 4) return 90 * DAY;
  return 180 * DAY;
}

/** Hours left on the fix window (negative = overdue); null once the match is mitigated or its risk accepted. */
export function slaHoursLeft(r: { cvss: number; kev: boolean; firstSeenAt: Date; status: VulnStatus }, now = Date.now()): number | null {
  if (r.status === 'mitigated' || r.status === 'accepted') return null;
  const due = r.firstSeenAt.getTime() + slaWindowHours(r) * 3_600_000;
  return Math.round((due - now) / 3_600_000);
}
