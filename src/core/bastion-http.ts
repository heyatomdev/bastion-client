import { BastionErrorCode, BastionHttpError, isBastionErrorCode } from './errors.js';
import type { AuditEventInput, TokenResponse } from './types.js';

export interface BastionHttpOptions {
  baseUrl: string;
  /** Per-request timeout, default 8 000 ms. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /**
   * The id of the request being served, sent as `X-Request-Id` on every call
   * (api.md §7) so Bastion logs it as `clientRequestId`. Read per call: back it
   * with the framework's request context. A value outside `[A-Za-z0-9._-]{1,64}` is not sent.
   */
  requestId?: () => string | undefined;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

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
  private readonly requestId?: () => string | undefined;

  constructor(options: BastionHttpOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 8_000;
    // Late-bound on purpose: a consumer (or its tests) may replace global fetch after construction.
    this.fetchImpl = options.fetch ?? ((...args) => fetch(...args));
    this.requestId = options.requestId;
  }

  async call<T>(method: string, path: string, body?: unknown, init: BastionRequestInit = {}): Promise<T> {
    const headers: Record<string, string> = { ...init.headers };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (init.token) headers['Authorization'] = `Bearer ${init.token}`;
    const requestId = this.requestId?.();
    if (requestId && REQUEST_ID_PATTERN.test(requestId)) headers['X-Request-Id'] ??= requestId;

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
      // Bastion's error body (api.md §3): `{ code, message, errors? }`; older builds put the field errors in `message`.
      const parsed = ((await res.json().catch(() => null)) ?? {}) as { message?: unknown; code?: unknown; errors?: unknown };
      const errors = Array.isArray(parsed.errors)
        ? parsed.errors.map(String)
        : Array.isArray(parsed.message)
          ? parsed.message.map(String)
          : undefined;
      const message = Array.isArray(parsed.message)
        ? parsed.message.join(', ')
        : typeof parsed.message === 'string'
          ? parsed.message
          : `Bastion error ${res.status}`;
      // A code Bastion still puts in `message` (UNDER_MINIMUM_AGE under `code: FORBIDDEN`) wins: classify reads it.
      const code = isBastionErrorCode(message)
        ? undefined
        : isBastionErrorCode(parsed.code)
          ? parsed.code
          : res.status === 400 && errors?.length
            ? BastionErrorCode.VALIDATION_FAILED
            : undefined;
      throw new BastionHttpError(res.status, message, code, errors);
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
