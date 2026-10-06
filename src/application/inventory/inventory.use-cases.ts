import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type {
  AssetAttrs, AssetPatch, AssetType, Criticality, IAssetRepository, ListAssetsQuery, NewAsset, SoftwareItem,
} from '../../domain/inventory/inventory.repository.interface.js';
import { AlreadyExistsException, InvalidValueException, NotFoundException } from '../../domain/common/exceptions.js';
import { AuditService } from '../audit/audit.service.js';
import { toComponent } from '../../domain/vuln/components.js';
import type { ProductSuggestion } from '../../domain/vuln/product-index.js';
import { ProductCatalogService } from '../vuln/product-catalog.service.js';
import { MatchAssetsService } from '../vuln/match-assets.service.js';
import type { IVulnRepository } from '../../domain/vuln/vuln.repository.interface.js';
import type { ILogger } from '../ports/ports.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { AuditAction, Entity, Errors } from '../../shared/strings.js';

export interface AssetInput {
  type: AssetType;
  name: string;
  addr?: string | null | undefined;
  os?: string | null | undefined;
  env?: string | undefined;
  criticality?: Criticality | undefined;
  exposed?: boolean | undefined;
  owner?: string | null | undefined;
  tags?: string[] | undefined;
  attrs?: AssetAttrs | undefined;
  software?: SoftwareItem[] | undefined;
}

const blank = (v: string | null | undefined) => (v && v.trim() ? v.trim() : null);

/** Types that are described by an "os" answer in the form; copied to the column so it can be listed and searched. */
export const osOf = (type: AssetType, attrs: AssetAttrs, given: string | null): string | null => {
  if (given) return given;
  const s = (k: string) => (typeof attrs[k] === 'string' && attrs[k] !== 'other' ? (attrs[k] as string) : '');
  const join = (...p: string[]) => blank(p.filter(Boolean).join(' '));
  switch (type) {
    case 'server': case 'laptop': return join(s('os'), s('os_version'));
    case 'cloud': return blank(s('os'));
    case 'fw': return join(s('vendor'), s('model'), s('firmware'));
    case 'web': return join(s('webserver'), s('webserver_version'));
    case 'db': return join(s('engine'), s('version'));
    case 'container': return blank(s('base_os'));
  }
};

export const toNewAsset = (i: AssetInput, source: string, createdBy: string | null): NewAsset => {
  const name = blank(i.name) ?? blank(i.addr) ?? '';
  if (!name) throw new InvalidValueException(Errors.assetIdentityRequired);
  const attrs = i.attrs ?? {};
  return {
    type: i.type, name, addr: blank(i.addr), os: osOf(i.type, attrs, blank(i.os)), env: i.env ?? 'prod',
    criticality: i.criticality ?? 'medium', exposed: i.exposed ?? false, source, owner: blank(i.owner),
    tags: i.tags ?? [], attrs, software: i.software ?? [], createdBy,
  };
};

@injectable()
export class ListAssetsUseCase {
  constructor(@inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository) {}
  execute(q: ListAssetsQuery) {
    return this.assets.list(q);
  }
}

@injectable()
export class GetAssetUseCase {
  constructor(@inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository) {}
  async execute(id: string) {
    const a = await this.assets.findById(id);
    if (!a) throw new NotFoundException(Entity.asset);
    return a;
  }
}

@injectable()
export class CreateAssetUseCase {
  constructor(
    @inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository,
    @inject(TYPES.MatchAssetsService) private readonly matcher: MatchAssetsService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, input: AssetInput) {
    const next = toNewAsset(input, 'manual', actor.id);
    if (await this.assets.findByIdentity(next.name, null)) throw new AlreadyExistsException(Entity.asset, 'name');
    const asset = await this.assets.create(next);
    await this.matcher.run(asset.id);
    await this.audit.record(auditActor(actor), AuditAction.assetCreated, { type: 'asset', id: asset.id }, { name: asset.name });
    return asset;
  }
}

@injectable()
export class UpdateAssetUseCase {
  constructor(
    @inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository,
    @inject(TYPES.MatchAssetsService) private readonly matcher: MatchAssetsService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string, patch: AssetPatch) {
    const current = await this.assets.findById(id);
    if (!current) throw new NotFoundException(Entity.asset);
    if (patch.name && patch.name.toLowerCase() !== current.name.toLowerCase() && (await this.assets.findByIdentity(patch.name, null))) {
      throw new AlreadyExistsException(Entity.asset, 'name');
    }
    // "os" is the one-line summary of the type-specific answers; keep it in step when they change.
    const next: AssetPatch = patch.attrs !== undefined && patch.os === undefined ? { ...patch, os: osOf(current.type, patch.attrs, null) } : patch;
    const asset = await this.assets.update(id, next);
    if (!asset) throw new NotFoundException(Entity.asset);
    await this.matcher.run(id);
    await this.audit.record(auditActor(actor), AuditAction.assetUpdated, { type: 'asset', id }, { fields: Object.keys(patch) });
    return asset;
  }
}

@injectable()
export class DeleteAssetUseCase {
  constructor(
    @inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string) {
    const current = await this.assets.findById(id);
    if (!current || !(await this.assets.delete(id))) throw new NotFoundException(Entity.asset);
    await this.audit.record(auditActor(actor), AuditAction.assetDeleted, { type: 'asset', id }, { name: current.name });
  }
}

export interface ImportRow {
  /** 1-based line in the uploaded file, echoed back in issues */
  row: number;
  type?: AssetType | undefined;
  name?: string | undefined;
  addr?: string | undefined;
  os?: string | undefined;
  env?: string | undefined;
  criticality?: Criticality | undefined;
  owner?: string | undefined;
  tags?: string[] | undefined;
  exposed?: boolean | undefined;
  software?: SoftwareItem[] | undefined;
}

export interface ImportIssue {
  row: number;
  level: 'error' | 'warning';
  value: string;
  message: 'invalidIp' | 'noIdentity' | 'matched' | 'osNormalized';
}

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;
const isIpv4 = (v: string) => IPV4.test(v) && v.split('.').every((p) => Number(p) <= 255);
const looksLikeIp = (v: string) => /^[\d.]+$/.test(v);

export interface ImportCommand {
  source: string;
  kind: string;
  dryRun: boolean;
  skipInvalid: boolean;
  rows: ImportRow[];
}

@injectable()
export class ImportAssetsUseCase {
  constructor(
    @inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository,
    @inject(TYPES.MatchAssetsService) private readonly matcher: MatchAssetsService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, cmd: ImportCommand) {
    const issues: ImportIssue[] = [];
    const accepted: { row: ImportRow; existingId: string | null }[] = [];
    const seen = new Set<string>();

    for (const row of cmd.rows) {
      const name = blank(row.name);
      const addr = blank(row.addr);
      if (!name && !addr) {
        issues.push({ row: row.row, level: 'error', value: '(empty)', message: 'noIdentity' });
        continue;
      }
      if (addr && looksLikeIp(addr) && !isIpv4(addr)) {
        issues.push({ row: row.row, level: 'error', value: addr, message: 'invalidIp' });
        continue;
      }
      const key = (name ?? addr ?? '').toLowerCase();
      if (seen.has(key)) {
        issues.push({ row: row.row, level: 'warning', value: name ?? addr ?? '', message: 'matched' });
        continue;
      }
      seen.add(key);
      const existing = await this.assets.findByIdentity(name ?? addr, addr);
      if (existing) issues.push({ row: row.row, level: 'warning', value: existing.name, message: 'matched' });
      accepted.push({ row, existingId: existing?.id ?? null });
    }

    const errors = issues.filter((i) => i.level === 'error').length;
    const software = accepted.reduce((n, a) => n + (a.row.software?.length ?? 0), 0);
    const totals = {
      rows: cmd.rows.length, valid: cmd.rows.length - errors, warnings: issues.length - errors, errors,
      created: accepted.filter((a) => !a.existingId).length, updated: accepted.filter((a) => a.existingId).length,
      skipped: cmd.rows.length - accepted.length, software,
    };
    if (cmd.dryRun) return { totals, issues, applied: false };
    if (errors > 0 && !cmd.skipInvalid) throw new InvalidValueException(Errors.validation);

    const touched: string[] = [];
    for (const { row, existingId } of accepted) {
      const input: AssetInput = {
        type: row.type ?? 'server', name: row.name ?? row.addr ?? '', addr: row.addr, os: row.os, env: row.env,
        criticality: row.criticality, exposed: row.exposed, owner: row.owner, tags: row.tags, software: row.software,
      };
      if (existingId) {
        // A re-import refreshes what the file knows and bumps "last seen"; untouched fields stay as they were.
        const update: AssetPatch = { archived: false, seen: true };
        if (row.addr) update.addr = blank(row.addr);
        if (row.os) update.os = blank(row.os);
        if (row.env) update.env = row.env;
        if (row.criticality) update.criticality = row.criticality;
        if (row.owner) update.owner = blank(row.owner);
        if (row.exposed !== undefined) update.exposed = row.exposed;
        if (row.software?.length) update.software = row.software;
        await this.assets.update(existingId, update);
        touched.push(existingId);
      } else {
        touched.push((await this.assets.create(toNewAsset(input, cmd.kind, actor.id))).id);
      }
    }
    for (const id of touched) await this.matcher.run(id);

    const status = totals.errors > 0 ? 'degraded' : 'healthy';
    await this.assets.recordImport({
      source: cmd.source, kind: cmd.kind, rows: totals.rows, created: totals.created, updated: totals.updated, skipped: totals.skipped,
      status, createdBy: actor.id,
    });
    await this.audit.record(auditActor(actor), AuditAction.assetsImported, undefined, { source: cmd.source, ...totals });
    return { totals, issues, applied: true };
  }
}

@injectable()
export class ListImportsUseCase {
  constructor(@inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository) {}
  execute() {
    return this.assets.imports(20);
  }
}

export interface SoftwareCheck {
  product: string;
  /** "matched": the CVE data knows this product; "unknown": nothing by that name, see the suggestions */
  status: 'matched' | 'unknown';
  pairs: string[];
  suggestions: ProductSuggestion[];
  versionMissing: boolean;
}

/** Tells, for each software entry of an asset, whether it will be matched against CVEs, before it is saved. */
@injectable()
export class CheckSoftwareUseCase {
  constructor(@inject(TYPES.ProductCatalogService) private readonly catalog: ProductCatalogService) {}

  async execute(items: { product: string; version?: string | null }[]): Promise<{ items: SoftwareCheck[] }> {
    const index = await this.catalog.get();
    return {
      items: items.map((i) => {
        const comp = toComponent(i.product, i.version?.trim() || null);
        const pairs = !comp ? [] : comp.vendor ? [`${comp.vendor}:${comp.product}`] : index.pairsOf(comp.product);
        const matched = pairs.length > 0;
        return {
          product: i.product, status: matched ? 'matched' : 'unknown', pairs, suggestions: matched ? [] : index.suggest(i.product),
          versionMissing: !i.version?.trim(),
        };
      }),
    };
  }
}

/** The list of software names behind the asset form: a searchable picker plus the team's own names. */
@injectable()
export class SoftwareCatalogUseCases {
  constructor(
    @inject(TYPES.ProductCatalogService) private readonly catalog: ProductCatalogService,
    @inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository,
    @inject(TYPES.MatchAssetsService) private readonly matcher: MatchAssetsService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  async search(q: string) {
    // Opened empty, the picker is a browsable list of the ~200 products the CVEs name most; typing narrows it.
    return { items: (await this.catalog.get()).search(q, q.trim() ? 20 : 200) };
  }

  aliases() {
    return this.vulns.aliases().then((items) => ({ items }));
  }

  async createAlias(actor: Actor, input: { name: string; pair: string }) {
    const index = await this.catalog.get();
    if (!index.hasPair(input.pair)) throw new InvalidValueException(Errors.unknownProduct(input.pair));
    const row = await this.vulns.createAlias({ ...input, createdBy: actor.id });
    if (!row) throw new AlreadyExistsException(Entity.softwareName, 'name');
    await this.changed(actor, { change: 'created', ...input });
    return row;
  }

  async deleteAlias(actor: Actor, id: string) {
    if (!(await this.vulns.deleteAlias(id))) throw new NotFoundException(Entity.softwareName);
    await this.changed(actor, { change: 'deleted', id });
  }

  /** New names change what existing assets match, so the inventory is matched again (in the background). */
  private async changed(actor: Actor, meta: Record<string, unknown>) {
    this.catalog.invalidate();
    await this.audit.record(auditActor(actor), AuditAction.softwareAliasChanged, undefined, meta);
    void this.matcher.run().catch((err) => this.logger.error({ err }, 'rematch after software name change failed'));
  }
}
