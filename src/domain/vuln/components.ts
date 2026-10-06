import { osComponent } from './os.js';
/**
 * Turns what the inventory says about an asset into "vendor:product" + version pairs the CVE database knows.
 * Free-text software names are normalised; a few well-known products map to their NVD names.
 */
export interface Component {
  /** display name as entered */
  label: string;
  /** known vendor, otherwise resolved against the CVE data */
  vendor: string | null;
  product: string;
  version: string | null;
}

/** product alias → NVD "vendor:product" */
const KNOWN: Record<string, string> = {
  openssh: 'openbsd:openssh', openssl: 'openssl:openssl', nginx: 'f5:nginx', 'apache http server': 'apache:http_server',
  apache: 'apache:http_server', httpd: 'apache:http_server', iis: 'microsoft:internet_information_services',
  'microsoft iis': 'microsoft:internet_information_services', 'apache tomcat': 'apache:tomcat', tomcat: 'apache:tomcat',
  postgresql: 'postgresql:postgresql', postgres: 'postgresql:postgresql', mysql: 'oracle:mysql', 'mysql / mariadb': 'oracle:mysql',
  mariadb: 'mariadb:mariadb', mongodb: 'mongodb:mongodb', redis: 'redis:redis', elasticsearch: 'elastic:elasticsearch',
  'microsoft sql server': 'microsoft:sql_server', 'oracle database': 'oracle:database_server', jenkins: 'jenkins:jenkins',
  xz: 'tukaani:xz', 'xz-utils': 'tukaani:xz', libwebp: 'webmproject:libwebp', curl: 'haxx:curl', sudo: 'sudo_project:sudo',
};

const FIREWALL_OS: Record<string, string> = {
  fortinet: 'fortinet:fortios', 'palo alto networks': 'paloaltonetworks:pan-os', cisco: 'cisco:ios',
  'check point': 'checkpoint:gaia_os', sonicwall: 'sonicwall:sonicos', juniper: 'juniper:junos',
};

export const slug = (s: string) => s.trim().toLowerCase().replace(/[^a-z0-9.+\-]+/g, '_').replace(/^_+|_+$/g, '');

export function toComponent(name: string, version: string | null, vendor: string | null = null): Component | null {
  const label = name.trim();
  if (!label) return null;
  const hit = KNOWN[label.toLowerCase()];
  if (hit) {
    const [v, p] = hit.split(':') as [string, string];
    return { label, vendor: v, product: p, version };
  }
  return { label, vendor: vendor ? slug(vendor) : null, product: slug(label), version };
}

interface AssetShape {
  type: string;
  os: string | null;
  attrs: Record<string, string | boolean>;
  software: { vendor: string | null; product: string; version: string | null }[];
}

const str = (v: string | boolean | undefined) => (typeof v === 'string' && v.trim() && v !== 'other' ? v.trim() : null);

export function componentsOf(a: AssetShape): Component[] {
  const out: Component[] = [];
  const push = (c: Component | null) => c && out.push(c);
  if (a.type === 'server' || a.type === 'laptop') push(osComponent(str(a.attrs['os']) ?? null, str(a.attrs['os_version']) ?? null));
  for (const s of a.software) push(toComponent(s.product, s.version, s.vendor));
  const at = a.attrs;
  if (a.type === 'web') {
    const ws = str(at['webserver']);
    if (ws) push(toComponent(ws, str(at['webserver_version'])));
  }
  if (a.type === 'db') {
    const engine = str(at['engine']);
    if (engine) push(toComponent(engine, str(at['version'])));
  }
  if (a.type === 'fw') {
    const vendor = str(at['vendor']);
    const pair = vendor ? FIREWALL_OS[vendor.toLowerCase()] : undefined;
    const fw = str(at['firmware']);
    if (pair && fw) {
      const [v, p] = pair.split(':') as [string, string];
      out.push({ label: `${vendor} firmware`, vendor: v, product: p, version: fw });
    }
  }
  return out.filter((c, i) => out.findIndex((d) => d.vendor === c.vendor && d.product === c.product && d.version === c.version) === i);
}
