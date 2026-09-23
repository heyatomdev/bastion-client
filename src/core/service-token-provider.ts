import { decodeJwt } from 'jose';
import type { BastionHttp, ClientAuthInput } from './bastion-http.js';
import { silentLogger, type BastionLogger } from './types.js';

const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const FALLBACK_TTL_MS = 60 * 60 * 1000;

interface Cached {
  token: string;
  expiresAt: number;
  tenantId: string | null;
}

/**
 * Holds machine tokens for outbound calls and renews each ahead of `exp`.
 * One credential (the common case) or several keyed by `serviceSlug`, for an
 * app that calls more than one service with its own client for each. Per
 * slug: single-flight (a burst of first calls shares one `POST /auth/client`)
 * and stale-cache fallback (a mint that fails while the old token is still
 * inside its `exp` keeps serving it).
 */
/** Credentials looked up per `serviceSlug` on demand — for an app whose targets are configured lazily. */
export interface CredentialResolver {
  resolve: (serviceSlug: string) => ClientAuthInput | null | undefined;
  defaultSlug: string;
}

export type ServiceTokenCredentials = ClientAuthInput | Record<string, ClientAuthInput> | CredentialResolver;

export class ServiceTokenProvider {
  private readonly resolveCredential: (serviceSlug: string) => ClientAuthInput | null | undefined;
  private readonly defaultSlug: string;
  private readonly cache = new Map<string, Cached>();
  private readonly inFlight = new Map<string, Promise<string>>();

  constructor(
    private readonly http: BastionHttp,
    credentials: ServiceTokenCredentials,
    private readonly logger: BastionLogger = silentLogger,
  ) {
    if ('resolve' in credentials && typeof credentials.resolve === 'function') {
      const resolver = credentials as CredentialResolver;
      this.resolveCredential = resolver.resolve;
      this.defaultSlug = resolver.defaultSlug;
    } else if ('apiKey' in credentials && typeof credentials.apiKey === 'string') {
      const single = credentials as ClientAuthInput;
      this.resolveCredential = (slug) => (slug === single.serviceSlug ? single : null);
      this.defaultSlug = single.serviceSlug;
    } else {
      const record = credentials as Record<string, ClientAuthInput>;
      const [first] = Object.keys(record);
      if (!first) throw new Error('ServiceTokenProvider: no credentials configured');
      this.resolveCredential = (slug) => record[slug];
      this.defaultSlug = first;
    }
  }

  /** Tenant of the default credential's token, once minted — the tenant `POST /events` rows land in. */
  get tenantId(): string | null {
    return this.cache.get(this.defaultSlug)?.tenantId ?? null;
  }

  getToken(serviceSlug: string = this.defaultSlug): Promise<string> {
    const cached = this.cache.get(serviceSlug);
    if (cached && Date.now() < cached.expiresAt - REFRESH_MARGIN_MS) return Promise.resolve(cached.token);

    const running = this.inFlight.get(serviceSlug);
    if (running) return running;

    const pending = this.refresh(serviceSlug)
      .catch((err: unknown) => {
        if (cached && Date.now() < cached.expiresAt) {
          this.logger.warn(`bastion: token mint for ${serviceSlug} failed, serving stale cache`);
          return cached.token;
        }
        throw err;
      })
      .finally(() => this.inFlight.delete(serviceSlug));
    this.inFlight.set(serviceSlug, pending);
    return pending;
  }

  private async refresh(serviceSlug: string): Promise<string> {
    const credential = this.resolveCredential(serviceSlug);
    if (!credential?.apiKey) throw new Error(`Bastion service client for "${serviceSlug}" not configured`);
    const { accessToken } = await this.http.clientAuth(credential);
    const { exp, tenantId } = decodeJwt(accessToken) as { exp?: number; tenantId?: string };
    this.cache.set(serviceSlug, {
      token: accessToken,
      expiresAt: exp ? exp * 1000 : Date.now() + FALLBACK_TTL_MS,
      tenantId: tenantId ?? null,
    });
    this.logger.log(`service client token refreshed for ${serviceSlug}`);
    return accessToken;
  }
}
