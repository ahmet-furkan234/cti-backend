import { AsyncLocalStorage } from 'node:async_hooks';

/** The company a piece of work happens in. Repositories of company-owned data read it instead of taking a parameter. */
export interface TenantScope {
  companyId: string;
  /** the company is the platform owner (the main company) */
  platform: boolean;
}

const store = new AsyncLocalStorage<TenantScope>();

export const tenant = {
  run<T>(scope: TenantScope, fn: () => T): T {
    return store.run(scope, fn);
  },
  current(): TenantScope | undefined {
    return store.getStore();
  },
  /** Fails closed: company-owned data is never read or written without knowing whose it is. */
  require(): TenantScope {
    const scope = store.getStore();
    if (!scope) throw new Error('No company in scope for a company-owned operation');
    return scope;
  },
  /** shorthand for the id repositories filter on */
  id(): string {
    return tenant.require().companyId;
  },
};
