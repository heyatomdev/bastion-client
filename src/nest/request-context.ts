import { AsyncLocalStorage } from 'node:async_hooks';

const store = new AsyncLocalStorage<{ id?: unknown }>();

/** Express/Fastify middleware: keeps the request reachable for the rest of its async chain. */
export function requestContextMiddleware(req: { id?: unknown }, _res: unknown, next: () => void): void {
  store.run(req, next);
}

/**
 * The served request's own id, `req.id` as set by pino-http (`genReqId`, api.md §7):
 * the default `requestId` of `BastionModule`. Read lazily, so the logger
 * middleware may run before or after this one.
 */
export function currentRequestId(): string | undefined {
  const id = store.getStore()?.id;
  return typeof id === 'string' ? id : undefined;
}
