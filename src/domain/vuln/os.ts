import type { Component } from './components.js';

/** Windows: the CVE data names a product per release, and its versions are build numbers (10.0.<build>.<revision>). */
const SERVER_BUILDS: Record<string, string> = {
  '14393': 'windows_server_2016', '17763': 'windows_server_2019', '20348': 'windows_server_2022',
  '25398': 'windows_server_2022_23h2', '26100': 'windows_server_2025',
};
const CLIENT_BUILDS: Record<string, string> = {
  '10240': 'windows_10_1507', '14393': 'windows_10_1607', '17763': 'windows_10_1809', '18363': 'windows_10_1909',
  '19041': 'windows_10_2004', '19042': 'windows_10_20h2', '19044': 'windows_10_21h2', '19045': 'windows_10_22h2',
  '22000': 'windows_11_21h2', '22621': 'windows_11_22h2', '22631': 'windows_11_23h2', '26100': 'windows_11_24h2', '26200': 'windows_11_25h2',
};

const major = (v: string) => /^\d+/.exec(v.trim())?.[0] ?? null;

/**
 * The operating system an asset form describes, as something the CVE data can be searched for.
 * Only what can be matched reliably is returned: a Windows needs its build number, a Debian or Red Hat its
 * major release (the CVE data lists "12.0", "9.0"), Ubuntu and macOS the version as written.
 */
export function osComponent(os: string | null, version: string | null): Component | null {
  const name = os?.trim().toLowerCase();
  const v = version?.trim();
  if (!name || !v) return null;
  const mk = (label: string, vendor: string, product: string, ver: string): Component => ({ label, vendor, product, version: ver });

  if (name.startsWith('windows')) {
    const build = /^10\.0\.(\d+)\.\d+/.exec(v);
    if (!build) return null;
    const product = (name.includes('server') ? SERVER_BUILDS : CLIENT_BUILDS)[build[1]!];
    return product ? mk(`Windows ${build[1]}`, 'microsoft', product, v) : null;
  }
  if (name === 'ubuntu') return mk('Ubuntu', 'canonical', 'ubuntu_linux', v);
  if (name === 'debian') {
    const m = major(v);
    return m ? mk('Debian', 'debian', 'debian_linux', `${m}.0`) : null;
  }
  if (name.startsWith('red hat')) {
    const m = major(v);
    return m ? mk('Red Hat Enterprise Linux', 'redhat', 'enterprise_linux', `${m}.0`) : null;
  }
  if (name === 'macos') return mk('macOS', 'apple', 'macos', v);
  return null;
}
