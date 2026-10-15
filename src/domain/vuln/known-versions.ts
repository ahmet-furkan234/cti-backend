import type { CpeMatch } from '../cve/cve.repository.interface.js';
import { compareVersions } from './version.js';

/** "9.6p1" → "9.6": the plain release number people recognise. Pre-releases ("rc1", "beta") and non-versions give null. */
export function simpleVersion(raw: string): string | null {
  const v = raw.trim().replace(/p\d+$/i, '');
  return /^\d+(\.\d+){0,3}$/.test(v) ? v : null;
}

/** Plain versions the CVE data mentions for a product: exact CPE versions and the ends of its version ranges. */
export function versionsFromMatches(matches: CpeMatch[], pairs: string[]): string[] {
  const out = new Set<string>();
  const add = (raw: string | undefined) => {
    const v = raw ? simpleVersion(raw) : null;
    if (v) out.add(v);
  };
  for (const m of matches) {
    const parts = m.c.split(':'); // cpe:2.3:part:vendor:product:version:...
    if (!pairs.includes(`${parts[3]}:${parts[4]}`)) continue;
    add(parts[5]);
    add(m.vsi); add(m.vse); add(m.vei); add(m.vee);
  }
  return [...out];
}

/** Versions of the release tags in a git ref advertisement (`refs/tags/<name>` entries, peeled `^{}` duplicates skipped). */
export function tagVersions(advertisement: string, tag: (t: string) => string | null): string[] {
  const out = new Set<string>();
  for (const m of advertisement.matchAll(/refs\/tags\/([^\s^]+)(?!\^\{\})/g)) {
    const v = tag(m[1]!);
    if (v) out.add(v);
  }
  return [...out];
}

/** Newest first, without duplicates, capped. */
export function newestFirst(versions: Iterable<string>, limit = 80): string[] {
  return [...new Set(versions)].sort((a, b) => compareVersions(b, a)).slice(0, limit);
}

/**
 * Where to read the latest releases of popular products (the CVE data lags: a new release has no CVE yet).
 * `tag` turns a git tag into a version, or null when the tag is not a release.
 */
export const RELEASE_SOURCES: Record<string, { repo: string; tag: (t: string) => string | null }> = {
  openssh: { repo: 'openssh/openssh-portable', tag: (t) => /^V_(\d+)_(\d+)_P\d+$/.exec(t)?.slice(1, 3).join('.') ?? null },
  nginx: { repo: 'nginx/nginx', tag: (t) => /^release-(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  redis: { repo: 'redis/redis', tag: (t) => /^(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  'node.js': { repo: 'nodejs/node', tag: (t) => /^v(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  php: { repo: 'php/php-src', tag: (t) => /^php-(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  curl: { repo: 'curl/curl', tag: (t) => /^curl-(\d+)_(\d+)_(\d+)$/.exec(t)?.slice(1, 4).join('.') ?? null },
  openssl: { repo: 'openssl/openssl', tag: (t) => /^openssl-(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  git: { repo: 'git/git', tag: (t) => /^v(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  postgresql: { repo: 'postgres/postgres', tag: (t) => /^REL_(\d+)_(\d+)$/.exec(t)?.slice(1, 3).join('.') ?? null },
  mariadb: { repo: 'MariaDB/server', tag: (t) => /^mariadb-(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  grafana: { repo: 'grafana/grafana', tag: (t) => /^v(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  jenkins: { repo: 'jenkinsci/jenkins', tag: (t) => /^jenkins-(\d+\.\d+(\.\d+)?)$/.exec(t)?.[1] ?? null },
  wordpress: { repo: 'WordPress/WordPress', tag: (t) => /^(\d+\.\d+(\.\d+)?)$/.exec(t)?.[1] ?? null },
  docker: { repo: 'moby/moby', tag: (t) => /^v(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  kubernetes: { repo: 'kubernetes/kubernetes', tag: (t) => /^v(\d+\.\d+\.\d+)$/.exec(t)?.[1] ?? null },
  sudo: { repo: 'sudo-project/sudo', tag: (t) => /^SUDO_(\d+)_(\d+)_(\d+)$/.exec(t)?.slice(1, 4).join('.') ?? /^v(\d+\.\d+\.\d+)(p\d+)?$/.exec(t)?.[1] ?? null },
};
