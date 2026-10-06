/**
 * Express request extensions shared by the whole HTTP layer (every router reads them).
 * Only cross-cutting augmentations belong here; anything used by a single module stays in that module.
 */
declare namespace Express {
  interface Request {
    /** Set by AuthMiddleware.authenticate */
    auth?: { userId: string; email: string; permissions: string[] };
    /** Set by validateRequest; read through the typed `valid()` helper */
    valid: { body?: unknown; query?: unknown; params?: unknown };
  }
}
