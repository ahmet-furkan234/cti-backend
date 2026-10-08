export interface Actor {
  id: string;
  email: string;
  permissions: string[];
  ip: string | null;
  /** the company the request works in (a platform user may be working inside another company) */
  companyId: string;
}

export const auditActor = (a: Actor) => ({ id: a.id, email: a.email, ip: a.ip, companyId: a.companyId });
