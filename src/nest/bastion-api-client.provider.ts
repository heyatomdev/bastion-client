import { Inject, Injectable } from '@nestjs/common';
import { BastionApiClient } from '../core/api-client.js';
import { BastionService } from './bastion.service.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';
import { nestLogger } from './nest-logger.js';

/**
 * `BastionApiClient` bound to this app (`serviceSlug` as `appSlug`,
 * `tenantSlug`), sharing `BastionService.http`. Inject it in an app backend
 * that proxies its users' login/refresh/account flows; a pure service
 * (Herald, Beacon) never needs it. Failures are `BastionHttpException`s:
 * an `HttpException` with Bastion's status plus `code`/`upstreamMessage`.
 */
@Injectable()
export class BastionApiClientProvider extends BastionApiClient {
  constructor(bastion: BastionService, @Inject(BASTION_OPTIONS) options: BastionModuleOptions) {
    super({
      http: bastion.http,
      appSlug: options.serviceSlug,
      tenantSlug: options.tenantSlug,
      logger: nestLogger(BastionApiClient.name),
    });
  }
}
