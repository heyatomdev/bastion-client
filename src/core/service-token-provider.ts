import { decodeJwt } from 'jose';
import type { BastionHttp, ClientAuthInput } from './bastion-http.js';
import { silentLogger, type BastionLogger } from './types.js';

const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const FALLBACK_TTL_MS = 60 * 60 * 1000;

/**
 * Holds the service-client token for outbound calls and renews it ahead of
 * `exp`. Single-flight: a burst of first calls shares one `POST /auth/client`
 * instead of issuing one per caller — the previous per-service copies had no
 * such guard.
 */
export class ServiceTokenProvider {
  private token: string | null = null;
  private expiresAt = 0;
  private inFlight: Promise<string> | null = null;
  /** Tenant the token was issued for — the tenant `POST /events` rows land in. */
  tenantId: string | null = null;

  constructor(
    private readonly http: BastionHttp,
    private readonly credentials: ClientAuthInput,
    private readonly logger: BastionLogger = silentLogger,
  ) {}

  getToken(): Promise<string> {
    if (this.token && Date.now() < this.expiresAt - REFRESH_MARGIN_MS) {
      return Promise.resolve(this.token);
    }
    this.inFlight ??= this.refresh().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async refresh(): Promise<string> {
    const { accessToken } = await this.http.clientAuth(this.credentials);
    const { exp, tenantId } = decodeJwt(accessToken) as {
      exp?: number;
      tenantId?: string;
    };
    this.token = accessToken;
    this.expiresAt = exp ? exp * 1000 : Date.now() + FALLBACK_TTL_MS;
    this.tenantId = tenantId ?? null;
    this.logger.log('service client token refreshed');
    return accessToken;
  }
}
