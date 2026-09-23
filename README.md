# @heyatom/bastion-client

Consumer SDK for [Bastion](https://github.com/heyatomdev/bastion), the HeyAtom identity provider.
Replaces the `src/modules/bastion/` boilerplate every service used to copy by hand.

- `@heyatom/bastion-client` — framework-free core: `JwksVerifier` (kid-indexed cache, unknown-kid refetch with cooldown, stale-on-error), `BastionHttp` (`POST /auth/client`, `POST /events`, any other route), `ServiceTokenProvider` (single-flight refresh ahead of `exp`), payload types.
- `@heyatom/bastion-client` also carries Bastion's user-API contract: `BastionApiClient` (login, register, OAuth exchange, 2FA, single-flight refresh, logout, sessions, `/me`, profile, social accounts, email/password flows, export, delete), its types (`BastionMe`, `BastionTokenPair`, …) and `BastionErrorCode` (a stable code on every `BastionHttpError`).
- `@heyatom/bastion-client/webhooks` — `verifyWebhookSignature` (`X-Bastion-Signature-V2` with timestamp + delivery id, legacy fallback, secret rotation on both sides), header constants, payload type.
- `@heyatom/bastion-client/nest` — NestJS: `BastionModule`, `ServiceClientJwtGuard`, `BastionUserGuard`, `BastionAuditService`, `AuditInterceptor`, `@Public()`, `@RequireScope()`, `@Audit()`, `@CurrentClient()`, `@CurrentAdminUser()`.

Ships CJS and ESM. `jose` v6 is ESM-only, so the CJS build relies on Node's `require(esm)` — Node ≥ 20.19 / 22.12. Peer deps: `jose` (always), `@nestjs/common`, `@nestjs/core`, `rxjs`, `reflect-metadata` (for `/nest`).

## NestJS

```ts
// app.module.ts
import { APP_GUARD } from '@nestjs/core';
import { BastionModule, ServiceClientJwtGuard } from '@heyatom/bastion-client/nest';

@Module({
  imports: [
    BastionModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        baseUrl: config.getOrThrow('BASTION_URL'),
        serviceSlug: config.getOrThrow('BASTION_APP_SLUG'),
        apiKey: config.get('BASTION_CLIENT_API_KEY'),
        // tenantSlug, jwksTtlMs, issuer, acceptedAppSlugs, acceptedRoles — optional
      }),
    }),
  ],
  providers: [{ provide: APP_GUARD, useClass: ServiceClientJwtGuard }],
})
export class AppModule {}
```

```ts
@Controller('mail')
export class MailController {
  constructor(private readonly audit: BastionAuditService) {}

  @Post('send')
  @RequireScope('mail.send')
  send(@CurrentClient() client: ServiceClientJwtPayload, @Body() dto: SendDto) {
    // ...
    void this.audit.write('mail.sent', { metadata: { toDomain: 'example.com' } });
  }

  @Get('/health')
  @Public()
  health() { return { status: 'ok' }; }
}

// Admin surface: user tokens from the console
@Controller('admin/config')
@UseGuards(BastionUserGuard)
@UseInterceptors(AuditInterceptor)
export class AdminController {
  @Patch()
  @Audit('config.updated', { metadata: (_result, req) => ({ keys: Object.keys(req.body as object) }) })
  update(@CurrentAdminUser() admin: UserJwtPayload, @Body() dto: UpdateDto) { /* ... */ }
}
```

Bastion stores app events as `<serviceSlug>.<event>` — send the bare `resource.action`.

## App backends: verifying your users' tokens

```ts
// BastionJwksService.verifyUserToken(token): a user session token minted for this app
// (rejects machine tokens, checks aud + appSlug === serviceSlug, requires sub). Build your
// own guard on it — cookie extraction, suspension, age gate are the app's business.
// Core equivalent: assertUserTokenFor(await verifier.verify(token), 'dbd-builds').
```

## App backends (a BFF for your users)

```ts
import { BastionApiClientProvider, BastionHttpException } from '@heyatom/bastion-client/nest';

@Controller('auth')
export class AuthController {
  constructor(private readonly bastion: BastionApiClientProvider) {}

  @Post('login')
  async login(@Body() dto: LoginDto, @Req() req: Request) {
    try {
      return await this.bastion.login(dto.email, dto.password, { ip: clientIp(req), userAgent: req.headers['user-agent'] });
    } catch (err) {
      if (err instanceof BastionHttpException && err.code === 'EMAIL_NOT_VERIFIED') throw new ForbiddenException(err.code);
      throw err; // any other BastionHttpException already carries Bastion's status
    }
  }
}
```

```ts
// Webhook receiver — needs the raw body (NestFactory.create(AppModule, { rawBody: true }))
import { verifyWebhookSignature } from '@heyatom/bastion-client/webhooks';
const result = verifyWebhookSignature({ rawBody: req.rawBody, headers: req.headers, secrets: [secret, previousSecret] });
if (!result.ok) throw new UnauthorizedException(result.reason);
```

## Without NestJS

```ts
import { JwksVerifier, BastionHttp, ServiceTokenProvider } from '@heyatom/bastion-client';

const verifier = new JwksVerifier({ baseUrl: process.env.BASTION_URL! });
const payload = await verifier.verify(bearerToken); // throws BastionTokenError

const http = new BastionHttp({ baseUrl: process.env.BASTION_URL! });
const tokens = new ServiceTokenProvider(http, { apiKey, serviceSlug: 'my-service' });
await http.writeAuditEvent(await tokens.getToken(), { event: 'thing.done' });
```

## Release

Bump `version`, tag `vX.Y.Z`, push the tag. The workflow runs lint/test/build/DI smoke and publishes via npm trusted publishing (OIDC, no token; provenance implied).
