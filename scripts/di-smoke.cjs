// Proves the tsc build keeps `design:paramtypes`: Nest must resolve every
// provider of BastionModule from dist/ without explicit @Inject on class
// deps. esbuild-based builds silently drop that metadata, and the failure
// only shows at consumer boot time.
require('reflect-metadata');
const { NestFactory } = require('@nestjs/core');
const { Module } = require('@nestjs/common');
const nest = require('../dist/cjs/nest/index.js');

class Root {}
Module({
  imports: [
    nest.BastionModule.forRootAsync({
      useFactory: async () => ({ baseUrl: 'http://bastion.invalid', serviceSlug: 'smoke' }),
    }),
  ],
})(Root);

NestFactory.createApplicationContext(Root, { logger: false })
  .then((app) => {
    for (const p of [nest.BastionJwksService, nest.BastionService, nest.BastionAuditService, nest.ServiceClientJwtGuard, nest.BastionUserGuard, nest.AuditInterceptor, nest.BastionApiClientProvider]) {
      if (!app.get(p)) throw new Error(`unresolved ${p.name}`);
    }
    console.log('DI smoke ok: 7 providers resolved from dist/cjs');
    return app.close();
  })
  .catch((err) => { console.error(err); process.exit(1); });
