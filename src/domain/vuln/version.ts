/** Loose software-version comparison: numeric runs compare by value, letter runs lexically ("8.9p1" < "9.2p1"). */
const tokens = (v: string): (number | string)[] =>
  (v.match(/\d+|[a-z]+/gi) ?? []).map((t) => (/^\d+$/.test(t) ? Number(t) : t.toLowerCase()));

/** Drops a Debian/RPM epoch and keeps the upstream part: "1:8.9p1-3ubuntu0.6" → "8.9p1". */
export function upstreamVersion(v: string): string {
  const noEpoch = v.trim().replace(/^\d+:/, '');
  return (noEpoch.match(/^[0-9][0-9a-zA-Z.]*/) ?? [noEpoch])[0]!;
}

export function compareVersions(a: string, b: string): number {
  const x = tokens(upstreamVersion(a));
  const y = tokens(upstreamVersion(b));
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const l = x[i];
    const r = y[i];
    if (l === undefined) return typeof r === 'number' ? (r === 0 ? 0 : -1) : 1; // "1.0" > "1.0rc1"
    if (r === undefined) return typeof l === 'number' ? (l === 0 ? 0 : 1) : -1;
    if (l === r) continue;
    if (typeof l === 'number' && typeof r === 'number') return l < r ? -1 : 1;
    if (typeof l === 'number') return 1;
    if (typeof r === 'number') return -1;
    return l < r ? -1 : 1;
  }
  return 0;
}
