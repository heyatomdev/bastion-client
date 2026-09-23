import { createHash } from 'node:crypto';
import type { BastionHttp, BastionRequestInit } from './bastion-http.js';
import { silentLogger, type BastionLogger } from './types.js';
import type {
  BastionAgeVerificationResult,
  BastionAuthMethods,
  BastionClientContext,
  BastionEmailChangeRequest,
  BastionLinkTicket,
  BastionLoginResult,
  BastionMe,
  BastionProfile,
  BastionProfileUpdate,
  BastionRegisterInput,
  BastionSession,
  BastionSocialAccount,
  BastionTokenPair,
  BastionTwoFactorConfirmed,
  BastionTwoFactorSetup,
  BastionTwoFactorStatus,
  BastionUserAuditEventsPage,
} from './api-types.js';

const DEFAULT_REFRESH_MEMORY_MS = 60_000;
const AUTH_METHODS_CACHE_MS = 5 * 60_000;
const MAX_ROTATION_HOPS = 32;

export interface BastionApiClientOptions {
  http: BastionHttp;
  /** This app's slug — sent as `appSlug` on every user-facing call. */
  appSlug: string;
  /** Required by Bastion when the app is registered in more than one tenant, or is `isGlobal`. */
  tenantSlug?: string;
  /**
   * How long a refresh answer is remembered per refresh token, default 60 000 ms.
   * Within the window a second `refresh` with the same (now revoked) token
   * returns the remembered pair instead of tripping Bastion's reuse detection,
   * and `logout` still finds the successor. A BFF whose pages fire several
   * calls before the browser sees the new cookie may want a few minutes.
   */
  refreshMemoryMs?: number;
  logger?: BastionLogger;
}

/**
 * The user-facing half of Bastion's API, for an app backend that proxies its
 * users' auth: login, register, OAuth exchange, 2FA, refresh, logout,
 * sessions, `/me`, profile, social accounts, email/password flows, export,
 * self-deletion. Every call takes the user's `accessToken` where Bastion
 * needs one; nothing here holds state about who the user is.
 *
 * `refresh` is single-flight per refresh token and remembers each answer for
 * 60 s: Bastion rotates the token on every use and treats a replay as
 * theft (the whole family is revoked), so two concurrent refreshes with the
 * same token from a racing browser must collapse into one call. `logout`
 * follows the rotation chain so it revokes the token the browser is actually
 * holding, not the one it started with.
 */
export class BastionApiClient {
  private readonly http: BastionHttp;
  private readonly appSlug: string;
  private readonly tenantSlug?: string;
  private readonly refreshMemoryMs: number;
  private readonly logger: BastionLogger;

  private readonly inFlight = new Map<string, Promise<BastionTokenPair>>();
  private readonly recent = new Map<string, { value: BastionTokenPair; at: number }>();
  private readonly successors = new Map<string, { next: string; at: number }>();
  private authMethods?: { value: BastionAuthMethods; at: number };

  constructor(options: BastionApiClientOptions) {
    this.http = options.http;
    this.appSlug = options.appSlug;
    this.tenantSlug = options.tenantSlug || undefined;
    this.refreshMemoryMs = options.refreshMemoryMs ?? DEFAULT_REFRESH_MEMORY_MS;
    this.logger = options.logger ?? silentLogger;
  }

  private get appContext(): { appSlug: string; tenantSlug?: string } {
    return { appSlug: this.appSlug, ...(this.tenantSlug ? { tenantSlug: this.tenantSlug } : {}) };
  }

  private static clientHeaders(ctx?: BastionClientContext): Record<string, string> {
    const headers: Record<string, string> = {};
    if (ctx?.userAgent) headers['User-Agent'] = ctx.userAgent;
    if (ctx?.ip) headers['X-Real-IP'] = ctx.ip;
    return headers;
  }

  private call<T>(method: string, path: string, body?: unknown, init?: BastionRequestInit): Promise<T> {
    return this.http.call<T>(method, path, body, init);
  }

  private static hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  // ── session ──────────────────────────────────────────────────────────────

  login(email: string, password: string, ctx?: BastionClientContext): Promise<BastionLoginResult> {
    return this.call('POST', '/auth/login', { email, password, ...this.appContext }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  register(input: BastionRegisterInput, ctx?: BastionClientContext): Promise<{ message: string }> {
    return this.call('POST', '/auth/register', { ...input, ...this.appContext }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  /** Trades the one-time OAuth code for tokens. */
  exchange(code: string, ctx?: BastionClientContext): Promise<BastionLoginResult> {
    return this.call('POST', '/auth/exchange', { code, appSlug: this.appSlug }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  completeTwoFactor(twoFactorToken: string, code: string, ctx?: BastionClientContext): Promise<BastionTokenPair> {
    return this.call('POST', '/auth/2fa/authenticate', { twoFactorToken, code }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  async refresh(refreshToken: string, ctx?: BastionClientContext): Promise<BastionTokenPair> {
    const key = BastionApiClient.hash(refreshToken);
    this.prune(Date.now());
    const cached = this.recent.get(key);
    if (cached) return cached.value;
    const running = this.inFlight.get(key);
    if (running) return running;

    const pending = this.call<BastionTokenPair>('POST', '/auth/refresh', { refreshToken, ...this.appContext }, { headers: BastionApiClient.clientHeaders(ctx) })
      .then((value) => {
        const at = Date.now();
        this.recent.set(key, { value, at });
        this.successors.set(key, { next: value.refreshToken, at });
        return value;
      })
      .finally(() => this.inFlight.delete(key));
    this.inFlight.set(key, pending);
    return pending;
  }

  /** Revokes the token and any successor issued through `refresh` within the memory window. Never throws. */
  async logout(refreshToken: string | null | undefined): Promise<void> {
    if (!refreshToken) return;
    const tokens = new Set([refreshToken, this.latestRefreshToken(refreshToken)]);
    this.recent.delete(BastionApiClient.hash(refreshToken));
    await Promise.all(
      [...tokens].map((token) =>
        this.call<void>('POST', '/auth/logout', { refreshToken: token }).catch((err: Error) =>
          this.logger.warn(`bastion: logout failed: ${err.message}`),
        ),
      ),
    );
  }

  listSessions(accessToken: string): Promise<BastionSession[]> {
    return this.call('GET', '/auth/sessions', undefined, { token: accessToken });
  }

  revokeSession(accessToken: string, sessionId: string): Promise<void> {
    return this.call('DELETE', `/auth/sessions/${encodeURIComponent(sessionId)}`, undefined, { token: accessToken });
  }

  revokeOtherSessions(accessToken: string): Promise<{ count: number }> {
    return this.call('DELETE', '/auth/sessions', undefined, { token: accessToken });
  }

  // ── account ──────────────────────────────────────────────────────────────

  me(accessToken: string): Promise<BastionMe> {
    return this.call('GET', '/auth/me', undefined, { token: accessToken });
  }

  /** Answers the updated columns only (`BastionProfile`), not the full `BastionMe`. */
  updateProfile(accessToken: string, update: BastionProfileUpdate): Promise<BastionProfile> {
    return this.call('PATCH', '/auth/me', update, { token: accessToken });
  }

  completeAgeVerification(accessToken: string, birthDate: string): Promise<BastionAgeVerificationResult> {
    return this.call('POST', '/auth/age-verification', { birthDate }, { token: accessToken });
  }

  /** Cached 5 min; a failed refetch serves the cached answer. */
  async getAuthMethods(): Promise<BastionAuthMethods> {
    const cached = this.authMethods;
    if (cached && Date.now() - cached.at < AUTH_METHODS_CACHE_MS) return cached.value;
    const params = new URLSearchParams({ appSlug: this.appSlug });
    if (this.tenantSlug) params.set('tenantSlug', this.tenantSlug);
    try {
      const value = await this.call<BastionAuthMethods>('GET', `/auth/methods?${params}`);
      this.authMethods = { value, at: Date.now() };
      return value;
    } catch (err) {
      if (!cached) throw err;
      this.logger.warn(`bastion: /auth/methods failed (${(err as Error).message}), serving the cached answer`);
      return cached.value;
    }
  }

  // ── 2FA ──────────────────────────────────────────────────────────────────

  twoFactorStatus(accessToken: string): Promise<BastionTwoFactorStatus> {
    return this.call('GET', '/auth/2fa/status', undefined, { token: accessToken });
  }

  twoFactorSetup(accessToken: string, currentPassword?: string): Promise<BastionTwoFactorSetup> {
    return this.call('POST', '/auth/2fa/setup', currentPassword ? { currentPassword } : {}, { token: accessToken });
  }

  twoFactorConfirm(accessToken: string, code: string, currentPassword?: string): Promise<BastionTwoFactorConfirmed> {
    return this.call('POST', '/auth/2fa/confirm', { code, ...(currentPassword ? { currentPassword } : {}) }, { token: accessToken });
  }

  twoFactorDisable(accessToken: string, code: string, currentPassword?: string): Promise<{ message: string }> {
    return this.call('POST', '/auth/2fa/disable', { code, ...(currentPassword ? { currentPassword } : {}) }, { token: accessToken });
  }

  // ── social accounts ──────────────────────────────────────────────────────

  listSocialAccounts(accessToken: string): Promise<BastionSocialAccount[]> {
    return this.call('GET', '/auth/me/social-accounts', undefined, { token: accessToken });
  }

  createSocialAccountLinkTicket(accessToken: string, provider: string): Promise<BastionLinkTicket> {
    return this.call('POST', `/auth/me/social-accounts/${encodeURIComponent(provider)}/link-ticket`, undefined, { token: accessToken });
  }

  unlinkSocialAccount(accessToken: string, provider: string): Promise<void> {
    return this.call('DELETE', `/auth/me/social-accounts/${encodeURIComponent(provider)}`, undefined, { token: accessToken });
  }

  updateSocialAccountSyncAvatar(accessToken: string, provider: string, syncAvatar: boolean): Promise<BastionSocialAccount> {
    return this.call('PATCH', `/auth/me/social-accounts/${encodeURIComponent(provider)}`, { syncAvatar }, { token: accessToken });
  }

  // ── email & password ─────────────────────────────────────────────────────

  // Unauthenticated routes: Bastion rate-limits them by IP, so pass the
  // browser's context or every user behind this backend shares one bucket.

  resendVerification(email: string, ctx?: BastionClientContext): Promise<void> {
    return this.call('POST', '/auth/resend-verification', { email, ...this.appContext }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  verifyEmail(token: string, ctx?: BastionClientContext): Promise<void> {
    return this.call('GET', `/auth/verify-email?token=${encodeURIComponent(token)}`, undefined, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  forgotPassword(email: string, ctx?: BastionClientContext): Promise<void> {
    return this.call('POST', '/auth/forgot-password', { email, ...this.appContext }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  resetPassword(token: string, newPassword: string, ctx?: BastionClientContext): Promise<void> {
    return this.call('POST', '/auth/reset-password', { token, newPassword }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  changePassword(accessToken: string, currentPassword: string, newPassword: string): Promise<void> {
    return this.call('PATCH', '/auth/me/password', { currentPassword, newPassword }, { token: accessToken });
  }

  requestEmailChange(accessToken: string, input: BastionEmailChangeRequest): Promise<{ message: string }> {
    return this.call('PATCH', '/auth/me/email', input, { token: accessToken });
  }

  confirmEmailChange(token: string, ctx?: BastionClientContext): Promise<{ message: string }> {
    return this.call('POST', '/auth/me/confirm-email', { token }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  revokeEmailChange(token: string, ctx?: BastionClientContext): Promise<{ message: string }> {
    return this.call('POST', '/auth/me/revoke-email-change', { token }, { headers: BastionApiClient.clientHeaders(ctx) });
  }

  // ── GDPR ─────────────────────────────────────────────────────────────────

  /** The user's own audit trail (`GET /auth/me/events`), paginated. */
  listMyEvents(accessToken: string, page: { page?: number; limit?: number } = {}): Promise<BastionUserAuditEventsPage> {
    const params = new URLSearchParams();
    if (page.page !== undefined) params.set('page', String(page.page));
    if (page.limit !== undefined) params.set('limit', String(page.limit));
    const qs = params.toString();
    return this.call('GET', `/auth/me/events${qs ? `?${qs}` : ''}`, undefined, { token: accessToken });
  }

  exportData(accessToken: string): Promise<Record<string, unknown>> {
    return this.call('GET', '/auth/me/export', undefined, { token: accessToken });
  }

  /** Step-up: `currentPassword` when the account has one, `twoFactorCode` when 2FA is on. */
  deleteSelf(accessToken: string, stepUp: { currentPassword?: string; twoFactorCode?: string } = {}): Promise<void> {
    return this.call('DELETE', '/auth/me', stepUp, { token: accessToken });
  }

  // ── internals ────────────────────────────────────────────────────────────

  private latestRefreshToken(refreshToken: string): string {
    let current = refreshToken;
    for (let hop = 0; hop < MAX_ROTATION_HOPS; hop++) {
      const next = this.successors.get(BastionApiClient.hash(current))?.next;
      if (!next) break;
      current = next;
    }
    return current;
  }

  private prune(now: number): void {
    for (const [key, entry] of this.recent) if (now - entry.at >= this.refreshMemoryMs) this.recent.delete(key);
    for (const [key, entry] of this.successors) if (now - entry.at >= this.refreshMemoryMs) this.successors.delete(key);
  }
}
