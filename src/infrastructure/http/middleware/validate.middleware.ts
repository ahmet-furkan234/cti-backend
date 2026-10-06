import type { Request, RequestHandler } from 'express';
import { z, type ZodType } from 'zod';
import { Errors, errorBody } from '../../../shared/strings.js';

interface Targets {
  body?: ZodType;
  query?: ZodType;
  params?: ZodType;
}

/** Validates request parts with Zod; parsed values are exposed through `req.valid` (typed via `valid()`). */
export function validateRequest(targets: Targets): RequestHandler {
  return (req, res, next) => {
    const out: Request['valid'] = {};
    const issues: { in: string; path: string; message: string }[] = [];
    for (const key of ['body', 'query', 'params'] as const) {
      const schema = targets[key];
      if (!schema) continue;
      const parsed = schema.safeParse(req[key]);
      if (parsed.success) out[key] = parsed.data;
      else parsed.error.issues.forEach((i) => issues.push({ in: key, path: i.path.join('.'), message: i.message }));
    }
    if (issues.length) {
      res.status(400).json({ ...errorBody(Errors.validation), issues });
      return;
    }
    req.valid = out;
    next();
  };
}

export function valid<B extends ZodType | undefined = undefined, Q extends ZodType | undefined = undefined, P extends ZodType | undefined = undefined>(
  req: Request,
  _schemas?: { body?: B; query?: Q; params?: P },
) {
  return req.valid as {
    body: B extends ZodType ? z.infer<B> : never;
    query: Q extends ZodType ? z.infer<Q> : never;
    params: P extends ZodType ? z.infer<P> : never;
  };
}
