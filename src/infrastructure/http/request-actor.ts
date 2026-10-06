import type { Request } from 'express';
import type { Actor } from '../../application/shared/actor.js';

/** Builds the acting user for use cases from an authenticated request (used by every router). */
export function actorOf(req: Request): Actor {
  const a = req.auth!;
  return { id: a.userId, email: a.email, permissions: a.permissions, ip: req.ip ?? null };
}
