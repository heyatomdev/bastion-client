import { BastionHttpError } from './errors.js';
import type { AuditEventInput, TokenResponse } from './types.js';

export interface BastionHttpOptions {
  baseUrl: string;
  fetch?: typeof fetch;
}

export interface ClientAuthInput {
  apiKey: string;
  serviceSlug: string;
  tenantSlug?: string;
}

/**
 * Outbound calls to Bastion. Nothing here verifies inbound tokens — that is
 * `JwksVerifier`. `call` is public so a service can reach any other route
 * (e.g. `POST /auth/login` from a BFF) with the same error handling; pass the
 * browser's IP as `X-Real-IP` on user-facing calls so Bastion's rate-limit
 * and audit rows see the real client, not your container.
 */
export class BastionHttp {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: BastionHttpOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.fetchImpl = options.fetch ?? fetch;
  }

  async call<T>(
    method: string,
    path: string,
    body?: unknown,
    init: { token?: string; headers?: Record<string, string> } = {},
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...init.headers,
    };
    if (init.token) headers['Authorization'] = `Bearer ${init.token}`;
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { message?: string };
      throw new BastionHttpError(res.status, err.message ?? 'Bastion error');
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  clientAuth(input: ClientAuthInput): Promise<TokenResponse> {
    return this.call<TokenResponse>('POST', '/auth/client', input);
  }

  /** `POST /events`. Bastion stores the event as `<serviceSlug>.<event>`; send the bare `resource.action`. */
  writeAuditEvent(
    token: string,
    data: AuditEventInput,
  ): Promise<{ id: string; createdAt: string }> {
    return this.call('POST', '/events', data, { token });
  }
}
