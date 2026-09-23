import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { BASTION_OPTIONS, type BastionModuleAsyncOptions, type BastionModuleOptions } from './options.js';
import { BastionJwksService } from './bastion-jwks.service.js';
import { BastionService } from './bastion.service.js';
import { BastionAuditService } from './bastion-audit.service.js';
import { ServiceClientJwtGuard } from './guards/service-client-jwt.guard.js';
import { BastionUserGuard } from './guards/bastion-user.guard.js';
import { AuditInterceptor } from './interceptors/audit.interceptor.js';
import { BastionApiClientProvider } from './bastion-api-client.provider.js';

const PROVIDERS = [
  BastionJwksService,
  BastionService,
  BastionAuditService,
  ServiceClientJwtGuard,
  BastionUserGuard,
  AuditInterceptor,
  BastionApiClientProvider,
];

/**
 * ```ts
 * BastionModule.forRootAsync({
 *   inject: [ConfigService],
 *   useFactory: (config: ConfigService) => ({
 *     baseUrl: config.getOrThrow('BASTION_URL'),
 *     serviceSlug: config.getOrThrow('BASTION_APP_SLUG'),
 *     apiKey: config.get('BASTION_CLIENT_API_KEY'),
 *   }),
 * })
 * ```
 * Global: import once in `AppModule`, inject anywhere.
 */
@Global()
@Module({})
export class BastionModule {
  static forRoot(options: BastionModuleOptions): DynamicModule {
    return this.build({ provide: BASTION_OPTIONS, useValue: options });
  }

  static forRootAsync(options: BastionModuleAsyncOptions): DynamicModule {
    return this.build(
      { provide: BASTION_OPTIONS, useFactory: options.useFactory, inject: options.inject as never[] },
      options.imports,
    );
  }

  private static build(optionsProvider: Provider, imports: DynamicModule['imports'] = []): DynamicModule {
    return {
      module: BastionModule,
      imports,
      providers: [optionsProvider, ...PROVIDERS],
      exports: [BASTION_OPTIONS, ...PROVIDERS],
    };
  }
}
