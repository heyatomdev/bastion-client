import { Inject, Injectable } from '@nestjs/common';
import { type BastionRequestInit } from '../core/bastion-http.js';
import { NestBastionHttp } from './bastion-http-exception.js';
import type { AuditEventInput, TokenResponse } from '../core/types.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';

/** Outbound HTTP to Bastion. A failure surfaces as `BastionHttpException` (an `HttpException` with Bastion's status, a stable `code` and the upstream message). */
@Injectable()
export class BastionService {
  readonly http: NestBastionHttp;

  constructor(@Inject(BASTION_OPTIONS) private readonly options: BastionModuleOptions) {
    this.http = new NestBastionHttp({ baseUrl: options.baseUrl, timeoutMs: options.timeoutMs });
  }

  call<T>(method: string, path: string, body?: unknown, init?: BastionRequestInit): Promise<T> {
    return this.http.call<T>(method, path, body, init);
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
