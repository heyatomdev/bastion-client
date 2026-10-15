import type { ModuleMetadata } from '@nestjs/common';

export const BASTION_OPTIONS = Symbol('BASTION_OPTIONS');

export interface BastionModuleOptions {
  /** `BASTION_URL` — base URL, e.g. `http://bastion:3001`. */
  baseUrl: string;
  /** `BASTION_APP_SLUG` — this service's App slug. Machine tokens must carry it as `serviceSlug`. */
  serviceSlug: string;
  /** `BASTION_CLIENT_API_KEY` — needed for outbound calls (audit writes). Optional for verify-only consumers. */
  apiKey?: string;
  /** Required by Bastion when the app is `isGlobal` or registered in more than one tenant. */
  tenantSlug?: string;
  /** Per-request timeout for outbound calls, default 8 000 ms. */
  timeoutMs?: number;
  /** `BASTION_JWKS_TTL_MS`, default 300 000. */
  jwksTtlMs?: number;
  /** Expected `iss`. Default `'bastion'`; `null` disables the check. */
  issuer?: string | null;
  /**
   * Id sent as `X-Request-Id` on calls to Bastion. Default: `req.id` of the request
   * being served (pino-http / nest-common `genReqId`), tracked by the module's middleware.
   * Express only: under Fastify the middleware sees the raw request, which has no `id`,
   * so pass a getter here (e.g. from nestjs-cls).
   */
  requestId?: () => string | undefined;
  /** `BastionUserGuard`: which apps' user tokens are accepted. Default `['meridian']`. */
  acceptedAppSlugs?: string[];
  /** `BastionUserGuard`: which roles are accepted. Default `['ADMIN', 'OWNER', 'SUPER_ADMIN']`. */
  acceptedRoles?: string[];
}

export interface BastionModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  useFactory: (...args: any[]) => BastionModuleOptions | Promise<BastionModuleOptions>;
  inject?: unknown[];
}
