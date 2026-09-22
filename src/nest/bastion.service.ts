import { HttpException, Inject, Injectable } from '@nestjs/common';
import { BastionHttp } from '../core/bastion-http.js';
import { BastionHttpError } from '../core/errors.js';
import type { AuditEventInput, TokenResponse } from '../core/types.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';

/** Outbound HTTP to Bastion. A non-2xx answer surfaces as `HttpException` with Bastion's status. */
@Injectable()
export class BastionService {
  readonly http: BastionHttp;

  constructor(@Inject(BASTION_OPTIONS) private readonly options: BastionModuleOptions) {
    this.http = new BastionHttp({ baseUrl: options.baseUrl });
  }

  async call<T>(
    method: string,
    path: string,
    body?: unknown,
    init?: { token?: string; headers?: Record<string, string> },
  ): Promise<T> {
    try {
      return await this.http.call<T>(method, path, body, init);
    } catch (err) {
      if (err instanceof BastionHttpError) throw new HttpException(err.message, err.status);
      throw err;
    }
  }

  clientAuth(): Promise<TokenResponse> {
    if (!this.options.apiKey) {
      throw new Error('BastionModule: apiKey is required for clientAuth()');
    }
    return this.call<TokenResponse>('POST', '/auth/client', {
      apiKey: this.options.apiKey,
      serviceSlug: this.options.serviceSlug,
      ...(this.options.tenantSlug ? { tenantSlug: this.options.tenantSlug } : {}),
    });
  }

  writeAuditEvent(token: string, data: AuditEventInput): Promise<{ id: string; createdAt: string }> {
    return this.call('POST', '/events', data, { token });
  }
}
