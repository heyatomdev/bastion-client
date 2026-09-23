import { BastionErrorCode, BastionHttpError } from './errors.js';
import type { AuditEventInput, TokenResponse } from './types.js';

export interface BastionHttpOptions {
  baseUrl: string;
  /** Per-request timeout, default 8 000 ms. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export interface BastionRequestInit {
  token?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export interface ClientAuthInput {
  apiKey: string;
  serviceSlug: string;
  tenantSlug?: string;
}

/**
 * Outbound calls to Bastion. Nothing here verifies inbound tokens — that is
 * `JwksVerifier`. `call` is public so a service can reach any route with the
 * same error handling: a non-2xx answer becomes `BastionHttpError` with the
 * status and a stable `code`; Bastion unreachable or timed out is a 503
 * `UNAVAILABLE`. Pass the browser's IP as `X-Real-IP` on user-facing calls.
 */
export class BastionHttp {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: BastionHttpOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 8_000;
    // Late-bound on purpose: a consumer (or its tests) may replace global fetch after construction.
    this.fetchImpl = options.fetch ?? ((...args) => fetch(...args));
  }

  async call<T>(method: string, path: string, body?: unknown, init: BastionRequestInit = {}): Promise<T> {
    const headers: Record<string, string> = { ...init.headers };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (init.token) headers['Authorization'] = `Bearer ${init.token}`;

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(init.timeoutMs ?? this.timeoutMs),
      });
    } catch (err) {
      throw new BastionHttpError(503, `Bastion unreachable: ${(err as Error).message}`, BastionErrorCode.UNAVAILABLE);
    }

    if (!res.ok) {
      const parsed = (await res.json().catch(() => ({}))) as { message?: string | string[] };
      const message = Array.isArray(parsed.message)
        ? parsed.message.join(', ')
        : (parsed.message ?? `Bastion error ${res.status}`);
      throw new BastionHttpError(res.status, message);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json().catch(() => undefined)) as T;
  }

  clientAuth(input: ClientAuthInput): Promise<TokenResponse> {
    return this.call<TokenResponse>('POST', '/auth/client', input);
  }

  /** `POST /events`. Bastion stores the event as `<serviceSlug>.<event>`; send the bare `resource.action`. */
  writeAuditEvent(token: string, data: AuditEventInput): Promise<{ id: string; createdAt: string }> {
    return this.call('POST', '/events', data, { token });
  }
}
