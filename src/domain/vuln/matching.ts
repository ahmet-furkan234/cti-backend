import type { CpeMatch } from '../cve/cve.repository.interface.js';
import { compareVersions } from './version.js';

/** Splits a CPE 2.3 string into vendor, product and the pinned version ('*' / '-' = none). */
export function parseCpe(c: string): { vendor: string; product: string; version: string } | null {
  const parts = c.split(/(?<!\\):/);
  if (parts.length < 6 || parts[0] !== 'cpe') return null;
  return { vendor: parts[3]!, product: parts[4]!, version: parts[5]! };
}

export interface VersionVerdict {
  vulnerable: boolean;
  /** first version without the flaw, when the range says so */
  fixedIn: string | null;
}

/** Whether `installed` of `vendor:product` falls inside any vulnerable CPE range of a CVE. */
export function matchVersion(matches: CpeMatch[], pair: string, installed: string): VersionVerdict {
  for (const m of matches) {
    const cpe = parseCpe(m.c);
    if (!cpe || `${cpe.vendor}:${cpe.product}` !== pair) continue;
    if (cpe.version !== '*' && cpe.version !== '-') {
      if (compareVersions(installed, cpe.version) === 0) return { vulnerable: true, fixedIn: null };
      continue;
    }
    if (m.vsi && compareVersions(installed, m.vsi) < 0) continue;
    if (m.vse && compareVersions(installed, m.vse) <= 0) continue;
    if (m.vei && compareVersions(installed, m.vei) > 0) continue;
    if (m.vee && compareVersions(installed, m.vee) >= 0) continue;
    return { vulnerable: true, fixedIn: m.vee ?? null };
  }
  return { vulnerable: false, fixedIn: null };
}
