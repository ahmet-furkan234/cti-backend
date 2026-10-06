import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IVulnRepository, ListVulnsQuery, VulnRow } from '../../domain/vuln/vuln.repository.interface.js';
import { riskScore, slaHoursLeft, type VulnStatus } from '../../domain/vuln/risk.js';
import { NotFoundException } from '../../domain/common/exceptions.js';
import { AuditService } from '../audit/audit.service.js';
import { MatchAssetsService } from './match-assets.service.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { AuditAction, Entity } from '../../shared/strings.js';

export const withScores = <T extends VulnRow>(r: T) => ({
  ...r,
  risk: riskScore({ cvss: r.cvss, kev: r.kev, epss: r.epss, exposed: r.exposed, env: r.env }),
  slaHours: slaHoursLeft(r),
});

@injectable()
export class ListVulnsUseCase {
  constructor(@inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository) {}
  async execute(q: ListVulnsQuery) {
    return { items: (await this.vulns.list(q)).map(withScores) };
  }
}

@injectable()
export class ListCveAssetsUseCase {
  constructor(@inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository) {}

  async execute(cveId: string) {
    const items = (await this.vulns.forCve(cveId)).map(withScores).sort((a, b) => b.risk - a.risk);
    const count = (s: VulnStatus) => items.filter((i) => i.status === s).length;
    return {
      items,
      stats: {
        affected: items.length, exposed: items.filter((i) => i.exposed).length, open: count('open'),
        inProgress: count('in_progress'), mitigated: count('mitigated'),
      },
    };
  }
}

@injectable()
export class SetVulnStatusUseCase {
  constructor(
    @inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, ids: string[], status: VulnStatus) {
    const changed = await this.vulns.setStatus(ids, status, actor.id);
    if (changed === 0) throw new NotFoundException(Entity.vulnerability);
    await this.audit.record(auditActor(actor), AuditAction.vulnStatusChanged, undefined, { ids, status });
    return { changed };
  }
}

@injectable()
export class RematchVulnsUseCase {
  constructor(
    @inject(TYPES.MatchAssetsService) private readonly matcher: MatchAssetsService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor) {
    const result = await this.matcher.run();
    await this.audit.record(auditActor(actor), AuditAction.vulnRematched, undefined, result);
    return result;
  }
}
