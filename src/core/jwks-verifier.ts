import {
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type KeyObject,
} from 'jose';
import { BastionTokenError } from './errors.js';
import { silentLogger, type BastionJwtPayload, type BastionLogger } from './types.js';

type Key = CryptoKey | KeyObject | Uint8Array;

export interface JwksVerifierOptions {
  /** Bastion base URL, e.g. `http://bastion:3001`. The JWKS lives at `/.well-known/jwks.json`. */
  baseUrl: string;
  /** How long a fetched key set is trusted before a refetch. Default 300 000 (5 min), matching Bastion's `Cache-Control`. */
  ttlMs?: number;
  /** Expected `iss` claim. Default `'bastion'`. Pass `null` to skip the check. */
  issuer?: string | null;
  logger?: BastionLogger;
  fetch?: typeof fetch;
}

/**
 * Refetch cooldown when a token names a `kid` we do not have. The kid comes
 * from an unverified header, so it is attacker-controlled: without a
 * cooldown a flood of random kids becomes a request amplifier against
 * Bastion's JWKS route.
 */
const UNKNOWN_KID_REFETCH_COOLDOWN_MS = 30_000;

/**
 * The canonical consumer of Bastion's JWKS (docs/BASTION_INTEGRATION.md):
 * keys cached and indexed by `kid`, refetch on an unknown kid with a
 * cooldown, stale cache served when a refetch fails. Second safety net only:
 * Bastion publishes a key before signing with it (publish-before-use), so a
 * correctly configured consumer should never meet an unknown kid.
 */
export class JwksVerifier {
  private keys = new Map<string, Key>();
  private fetchedAt = 0;
  private lastUnknownKidRefetchAt = 0;
  private inFlight: Promise<void> | null = null;

  private readonly jwksUrl: string;
  private readonly ttlMs: number;
  private readonly issuer: string | null;
  private readonly logger: BastionLogger;
  private readonly fetchImpl: typeof fetch;

  constructor(options: JwksVerifierOptions) {
    this.jwksUrl = `${options.baseUrl.replace(/\/$/, '')}/.well-known/jwks.json`;
    this.ttlMs = options.ttlMs ?? 300_000;
    this.issuer = options.issuer === undefined ? 'bastion' : options.issuer;
    this.logger = options.logger ?? silentLogger;
    // Late-bound on purpose: a consumer (or its tests) may replace global fetch after construction.
    this.fetchImpl = options.fetch ?? ((...args) => fetch(...args));
  }

  async verify(token: string): Promise<BastionJwtPayload> {
    let kid: string | undefined;
    try {
      ({ kid } = decodeProtectedHeader(token));
    } catch {
      throw new BastionTokenError('malformed', 'Malformed token');
    }
    if (!kid) throw new BastionTokenError('missing_kid', 'Missing kid in JWT header');

    await this.ensureFresh();
    let key = this.keys.get(kid);
    if (!key) {
      await this.refetchForUnknownKid();
      key = this.keys.get(kid);
    }
    if (!key) {
      this.logger.warn(`JWT verification failed: unknown kid=${kid}`);
      throw new BastionTokenError('unknown_kid', 'Unknown or expired kid');
    }

    try {
      const { payload } = await jwtVerify(token, key, {
        algorithms: ['RS256'],
        ...(this.issuer ? { issuer: this.issuer } : {}),
      });
      return payload as unknown as BastionJwtPayload;
    } catch {
      throw new BastionTokenError('invalid', 'Invalid token');
    }
  }

  /** Single-flight: concurrent verifies during a refetch share one HTTP call. */
  private fetchKeys(): Promise<void> {
    this.inFlight ??= (async () => {
      try {
        const res = await this.fetchImpl(this.jwksUrl);
        if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
        const { keys } = (await res.json()) as { keys: JWK[] };
        const next = new Map<string, Key>();
        for (const jwk of keys) {
          if (!jwk.kid) continue;
          next.set(jwk.kid, await importJWK(jwk, 'RS256'));
        }
        this.keys = next;
        this.fetchedAt = Date.now();
      } finally {
        this.inFlight = null;
      }
    })();
    return this.inFlight;
  }

  private async ensureFresh(): Promise<void> {
    const stale = Date.now() - this.fetchedAt >= this.ttlMs;
    if (!stale && this.keys.size) return;
    try {
      await this.fetchKeys();
    } catch (err) {
      if (!this.keys.size) throw err;
      this.logger.warn(`JWKS fetch failed, serving stale cache: ${(err as Error).message}`);
    }
  }

  private async refetchForUnknownKid(): Promise<void> {
    const now = Date.now();
    if (now - this.lastUnknownKidRefetchAt < UNKNOWN_KID_REFETCH_COOLDOWN_MS) return;
    this.lastUnknownKidRefetchAt = now;
    try {
      await this.fetchKeys();
    } catch (err) {
      this.logger.warn(`JWKS refetch for unknown kid failed: ${(err as Error).message}`);
    }
  }
}
