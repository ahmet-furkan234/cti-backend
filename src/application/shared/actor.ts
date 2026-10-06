export interface Actor {
  id: string;
  email: string;
  permissions: string[];
  ip: string | null;
}

export const auditActor = (a: Actor) => ({ id: a.id, email: a.email, ip: a.ip });
