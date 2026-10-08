import { z } from 'zod';
import { Validation } from '../../../shared/strings.js';

const password = z.string().min(12, Validation.passwordMin).max(128);
const email = z.string().trim().toLowerCase().pipe(z.email().max(254));
const uuid = z.uuid();
const bool = z.enum(['true', 'false']).transform((v) => v === 'true');

export const loginBody = z.object({ email, password: z.string().min(1).max(128) });
export const registerBody = z.object({ token: z.string().min(20).max(200), name: z.string().trim().min(1).max(100), password });
export const resetPasswordBody = z.object({ token: z.string().min(20).max(200), password });
export const changePasswordBody = z.object({ currentPassword: z.string().min(1).max(128), newPassword: password });
export const tokenParams = z.object({ token: z.string().min(20).max(200) });
export const idParams = z.object({ id: uuid });
export const userSessionParams = z.object({ id: uuid, sessionId: uuid });

export const listUsersQuery = z.object({
  q: z.string().trim().max(100).optional(),
  status: z.enum(['active', 'disabled']).optional(),
  roleId: uuid.optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});
export const createCompanyBody = z.object({ name: z.string().trim().min(2).max(100), adminEmail: email.optional() });
export const updateCompanyBody = z.object({
  name: z.string().trim().min(2).max(100).optional(),
  status: z.enum(['active', 'suspended']).optional(),
});
export const inviteBody = z.object({ email, roleIds: z.array(uuid).min(1).max(20) });
export const createUserBody = z.object({
  name: z.string().trim().min(1).max(100),
  email,
  password,
  roleIds: z.array(uuid).min(1).max(20),
  overrides: z.array(z.object({ key: z.string().min(1).max(100), effect: z.enum(['grant', 'deny']) })).max(200).default([]),
});
export const updateUserBody = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  status: z.enum(['active', 'disabled']).optional(),
  roleIds: z.array(uuid).min(1).max(20).optional(),
});
export const overridesBody = z.object({
  overrides: z.array(z.object({ key: z.string().min(1).max(100), effect: z.enum(['grant', 'deny']) })).max(200),
});

const roleName = z.string().trim().min(2).max(50).regex(/^[a-zA-Z0-9_\- ]+$/, Validation.roleNameChars);
const permissionKeys = z.array(z.string().min(1).max(100)).max(200);
export const createRoleBody = z.object({
  name: roleName,
  description: z.string().trim().max(300).default(''),
  permissionKeys,
});
export const updateRoleBody = z.object({
  name: roleName.optional(),
  description: z.string().trim().max(300).optional(),
  permissionKeys: permissionKeys.optional(),
});

export const auditQuery = z.object({
  actorId: uuid.optional(),
  action: z.string().max(100).optional(),
  targetId: z.string().max(200).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(300).optional(),
});

const SEVERITY_LEVEL = { none: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
export const searchCvesQuery = z
  .object({
    q: z.string().trim().max(200).optional(),
    severity: z
      .string()
      .transform((s) => s.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean))
      .pipe(z.array(z.enum(['none', 'low', 'medium', 'high', 'critical'])).max(5))
      .transform((names) => names.map((n) => SEVERITY_LEVEL[n]))
      .optional(),
    cvssMin: z.coerce.number().min(0).max(10).optional(),
    cvssMax: z.coerce.number().min(0).max(10).optional(),
    kev: bool.optional(),
    epssMin: z.coerce.number().min(0).max(1).optional(),
    publishedFrom: z.coerce.date().optional(),
    publishedTo: z.coerce.date().optional(),
    vendor: z.string().trim().max(100).optional(),
    product: z.string().trim().max(100).optional(),
    cwe: z.string().trim().max(20).optional(),
    /** needs asset:read; see CveRouter */
    assets: z.enum(['affecting']).optional(),
    assetExposed: bool.optional(),
    assetEnv: z.string().trim().max(30).optional(),
    assetCounts: bool.optional(),
    sort: z.enum(['published', 'modified', 'cvss', 'epss']).default('published'),
    order: z.enum(['asc', 'desc']).default('desc'),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    cursor: z.string().max(500).optional(),
    includeTotal: bool.optional(),
  })
  .refine((q) => !q.product || q.vendor, { message: Validation.productNeedsVendor, path: ['product'] });
export const cveIdParams = z.object({ id: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, Validation.invalidCveId) });
export const syncSourceParams = z.object({ source: z.enum(['nvd', 'kev', 'epss']) });

// ---- inventory
const assetType = z.enum(['fw', 'server', 'web', 'db', 'container', 'cloud', 'laptop']);
const criticality = z.enum(['critical', 'high', 'medium', 'low']);
const short = (max: number) => z.string().trim().max(max);
const softwareItem = z.object({
  vendor: short(100).nullish().transform((v) => v || null),
  product: z.string().trim().min(1).max(200),
  version: short(100).nullish().transform((v) => v || null),
});
const attrs = z.record(z.string().max(60), z.union([z.string().max(300), z.boolean()])).refine((o) => Object.keys(o).length <= 40);

export const listAssetsQuery = z.object({
  q: short(200).optional(),
  tab: z.enum(['all', 'srv', 'ep', 'net', 'ctr', 'cld']).default('all'),
  exposed: bool.optional(),
  criticalVulns: bool.optional(),
  stale: bool.optional(),
  env: short(30).optional(),
  criticality: criticality.optional(),
  sort: z.enum(['risk', 'seen', 'name']).default('risk'),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});
export const createAssetBody = z.object({
  type: assetType,
  name: short(200).default(''),
  addr: short(300).nullish(),
  os: short(200).nullish(),
  env: short(30).default('prod'),
  criticality: criticality.default('medium'),
  exposed: z.boolean().default(false),
  owner: short(100).nullish(),
  tags: z.array(short(50)).max(30).default([]),
  attrs: attrs.default({}),
  software: z.array(softwareItem).max(2000).default([]),
});
export const updateAssetBody = z.object({
  name: short(200).min(1).optional(),
  addr: short(300).nullish().transform((v) => (v === undefined ? undefined : v || null)),
  os: short(200).nullish().transform((v) => (v === undefined ? undefined : v || null)),
  env: short(30).optional(),
  criticality: criticality.optional(),
  exposed: z.boolean().optional(),
  owner: short(100).nullish().transform((v) => (v === undefined ? undefined : v || null)),
  tags: z.array(short(50)).max(30).optional(),
  attrs: attrs.optional(),
  software: z.array(softwareItem).max(2000).optional(),
  archived: z.boolean().optional(),
});
export const importAssetsBody = z.object({
  source: short(200).min(1),
  kind: short(60).min(1),
  dryRun: z.boolean().default(false),
  skipInvalid: z.boolean().default(false),
  rows: z
    .array(
      z.object({
        row: z.number().int().min(1),
        type: assetType.optional(),
        name: short(200).optional(),
        addr: short(300).optional(),
        os: short(200).optional(),
        env: short(30).optional(),
        criticality: criticality.optional(),
        owner: short(100).optional(),
        tags: z.array(short(50)).max(30).optional(),
        exposed: z.boolean().optional(),
        software: z.array(softwareItem).max(2000).optional(),
      }),
    )
    .min(1)
    .max(5000),
});

// ---- vulnerabilities
const vulnStatus = z.enum(['open', 'in_progress', 'accepted', 'mitigated']);
export const listVulnsQuery = z.object({
  q: short(200).optional(),
  status: vulnStatus.optional(),
  kev: bool.optional(),
  exposed: bool.optional(),
  assetId: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(2000).default(500),
});
export const setVulnStatusBody = z.object({ ids: z.array(uuid).min(1).max(500), status: vulnStatus });

// ---- alerts
export const channelBody = z.object({
  kind: z.enum(['slack', 'smtp', 'telegram', 'webhook']),
  name: short(100).min(1),
  values: z.record(z.string().max(40), z.string().max(500)).default({}),
});
export const updateChannelBody = z.object({
  name: short(100).min(1).optional(),
  values: z.record(z.string().max(40), z.string().max(500)).optional(),
});
const ruleFields = {
  name: short(150).min(1),
  trigger: z.enum(['kev', 'critical', 'sla', 'epss', 'sync', 'digest']),
  envs: z.array(short(30)).max(10),
  minRisk: z.number().int().min(0).max(100),
  exposedOnly: z.boolean(),
  tag: short(50),
  channelIds: z.array(uuid).max(20),
  throttle: z.enum(['every', 'asset6h', 'daily']),
  enabled: z.boolean(),
};
export const ruleBody = z.object(ruleFields);
export const updateRuleBody = z.object(ruleFields).partial();

// ---- intel
const iocType = z.enum(['ipv4', 'ipv6', 'cidr', 'domain', 'url', 'email', 'sha256', 'sha1', 'md5']);
const lower = (max: number) => z.string().trim().toLowerCase().min(1).max(max);
const watchlistFields = {
  name: short(100).min(1),
  vendors: z.array(lower(100)).max(50),
  products: z.array(lower(100)).max(50),
  tag: short(50),
  minCvss: z.number().min(0).max(10),
  kevOnly: z.boolean(),
  minEpss: z.number().int().min(0).max(100),
  channelId: uuid.nullable(),
  enabled: z.boolean(),
};
export const watchlistBody = z.object(watchlistFields);
export const updateWatchlistBody = z.object(watchlistFields).partial();

const IPV4_RE = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IOC_SHAPE: Record<string, (v: string) => boolean> = {
  ipv4: (v) => IPV4_RE.test(v),
  ipv6: (v) => /^[0-9a-f:]+$/i.test(v) && v.includes(':'),
  cidr: (v) => { const [ip, bits] = v.split('/'); return !!ip && IPV4_RE.test(ip) && /^\d{1,2}$/.test(bits ?? '') && Number(bits) <= 32; },
  domain: (v) => /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v),
  url: (v) => /^(hxxps?|https?|ftp):\/\/\S+$/i.test(v),
  email: (v) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v),
  sha256: (v) => /^[a-f0-9]{64}$/i.test(v),
  sha1: (v) => /^[a-f0-9]{40}$/i.test(v),
  md5: (v) => /^[a-f0-9]{32}$/i.test(v),
};
export const addIocsBody = z.object({
  items: z
    .array(
      z.object({
        type: iocType,
        value: z.string().trim().min(1).max(2000),
        source: short(100).default('Manual'),
        confidence: z.number().int().min(0).max(100).default(60),
        expiresAt: z.coerce.date().nullish().transform((v) => v ?? null),
      }).refine((i) => IOC_SHAPE[i.type]!(i.value), { message: 'value does not match the indicator type', path: ['value'] }),
    )
    .min(1)
    .max(5000),
});
export const listIocsQuery = z.object({
  q: short(200).optional(),
  types: z.string().transform((s) => s.split(',').map((v) => v.trim()).filter(Boolean)).pipe(z.array(iocType).max(9)).optional(),
  onlyMatches: bool.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(100),
  offset: z.coerce.number().int().min(0).default(0),
});

// ---- reports
const template = z.enum(['exec', 'kev', 'sla', 'owner']);
const formats = z.array(z.enum(['csv'])).min(1).max(1);
const recipients = z.array(z.string().trim().toLowerCase().pipe(z.email().max(254))).max(30);
const scheduleFields = {
  template,
  scope: short(100).nullish().transform((v) => v || null),
  freq: z.enum(['daily', 'weekly-mon', 'weekly-fri', 'monthly']),
  recipients: recipients.min(1),
  formats,
  enabled: z.boolean().default(true),
};
export const scheduleBody = z.object(scheduleFields);
export const updateScheduleBody = z.object(scheduleFields).partial();
export const generateReportBody = z.object({
  template,
  scope: short(100).nullish().transform((v) => v || null),
  formats,
  periodDays: z.number().int().min(1).max(365).default(30),
  recipients: recipients.default([]),
});

export const checkSoftwareBody = z.object({
  items: z.array(z.object({ product: z.string().trim().min(1).max(200), version: short(100).nullish() })).min(1).max(100),
});

export const productSearchQuery = z.object({ q: z.string().trim().max(100).default('') });
export const aliasBody = z.object({
  name: short(100).min(2),
  pair: z.string().trim().toLowerCase().regex(/^[^:\s]+:[^:\s]+$/, 'expected vendor:product'),
});
