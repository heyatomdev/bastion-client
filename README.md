# @heyatom/bastion-client

Consumer SDK for [Bastion](https://github.com/heyatomdev/bastion), the HeyAtom identity provider.
Replaces the `src/modules/bastion/` boilerplate every service used to copy by hand.

- `@heyatom/bastion-client` — framework-free core: `JwksVerifier` (kid-indexed cache, unknown-kid refetch with cooldown, stale-on-error), `BastionHttp` (`POST /auth/client`, `POST /events`, any other route), `ServiceTokenProvider` (single-flight refresh ahead of `exp`), payload types.
- `@heyatom/bastion-client` also carries Bastion's user-API contract: `BastionApiClient` (login, register, OAuth exchange, 2FA, single-flight refresh, logout, sessions, `/me`, profile, social accounts, email/password flows, export, delete), its types (`BastionMe`, `BastionTokenPair`, …) and `BastionErrorCode` (a stable code on every `BastionHttpError`: credentials, app context, refresh token, OAuth code, age gate, OAuth flow, unavailable, upstream). `refreshMemoryMs` tunes how long a refresh answer is remembered per token (default 60 s). Since 0.7.2 `completeAgeVerification(token, birthDate, { currentPassword?, twoFactorCode? })` sends the step-up Bastion requires (as `deleteSelf`), and `UserJwtPayload.ageVerificationRequired?: true` is set only while the account owes the app's age screen: a consumer API can refuse it from the token alone.
- `@heyatom/bastion-client/webhooks` — `verifyWebhookSignature` (`X-Bastion-Signature-V2` with timestamp + delivery id, secret rotation on both sides; Bastion no longer sends the legacy body-only `X-Bastion-Signature`, so leave `allowLegacySignature` off — it only reopens replay), header constants, payload type.
- `@heyatom/bastion-client/nest` — NestJS: `BastionModule`, `ServiceClientJwtGuard`, `BastionUserGuard`, `BastionAuditService`, `AuditInterceptor` (attributes to `req.adminUser`, any `AuditActor` shape: `sub` plus optional `tenantId`/`tenantSlug`/`role`/`appSlug`), `@Public()`, `@RequireScope()`, `@Audit()`, `@CurrentClient()`, `@CurrentAdminUser()`, and for an app's own users `AppUserGuard` + `@CurrentUser()`.

Ships CJS and ESM, no ESM-only runtime dependency (RS256 verification is `node:crypto`), so Jest needs no `transformIgnorePatterns` for it. Node ≥ 20.19. Peer deps, for `/nest` only: `@nestjs/common`, `@nestjs/core`, `rxjs`, `reflect-metadata`.

### 0.8.0

- **Errors.** `BastionHttpError.errors` carries the field errors (and `upstreamCode` a code outside `BastionErrorCode`) of a 400 (`code: 'VALIDATION_FAILED'`); a `code` Bastion sends is kept when it is a `BastionErrorCode`. New codes: `VALIDATION_FAILED`, `RATE_LIMITED`. `BastionHttpException` answers a 4xx as Bastion did (`{ code, message, errors? }`) and keeps an unknown 4xx code (`PASSWORD_TOO_SHORT`, else the status default such as `NOT_FOUND`, never `UPSTREAM`) and hides a 5xx (api.md §3/§14): 502 `UPSTREAM` or 503 `UNAVAILABLE` with a generic message; Bastion's own status and message stay on `upstreamStatus`/`upstreamMessage` and in `message`, for the log. Show `errors` in the UI, not just `message`.
- **`X-Request-Id`** on every call to Bastion: `BastionHttpOptions.requestId` (a getter); in Nest the module tracks the served request and sends its `req.id` (nest-common / pino-http), overridable with `BastionModuleOptions.requestId` (required under Fastify, whose raw request has no `id`).
- **OAuth.** `oauthStart(provider)` → `{ url, state } | null`; `exchange(code, ctx, state)` now requires `state` (breaking: no CSRF-unprotected exchange).
- **`AppUserGuard`** (global guard for the app's users, honours `@Public()`, sets `req.user`) and **`@CurrentUser()`**.
- `jose` is no longer a peer dependency.

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
// providers: [{ provide: APP_GUARD, useClass: AppUserGuard }]
// A user session token minted for this app (BastionJwksService.verifyUserToken: rejects machine
// tokens, checks aud + appSlug === serviceSlug, requires sub). @Public() opts a route out.
@Get('me')
me(@CurrentUser() user: UserJwtPayload) { /* ... */ }
// Suspension, age gate, roles stay the app's business: a second guard after AppUserGuard.
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
      throw err; // 4xx: Bastion's status, code, errors; 5xx: 502 UPSTREAM / 503 UNAVAILABLE
    }
  }

  @Public()
  @Get('oauth/:provider')
  async oauthStart(@Param('provider') provider: string, @Res() res: Response) {
    const start = await this.bastion.oauthStart(provider);
    if (!start) throw new NotFoundException('Unknown OAuth provider');
    res.cookie('oauthState', start.state, { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth/callback', maxAge: 600_000 });
    res.redirect(start.url);
  }

  @Public()
  @Get('callback')
  async callback(@Query('code') code: string, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const state = req.cookies.oauthState; // from the cookie, never from the query
    res.clearCookie('oauthState', { path: '/auth/callback' });
    if (!code || !state) throw new UnauthorizedException();
    return this.bastion.exchange(code, { ip: req.ip, userAgent: req.headers['user-agent'] }, state);
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
// several targets: a record keyed by serviceSlug, or { defaultSlug, resolve: (slug) => credential | null }
await http.writeAuditEvent(await tokens.getToken(), { event: 'thing.done' });
```

## Release

Bump `version`, tag `vX.Y.Z`, push the tag. The workflow runs lint/test/build/DI smoke and publishes via npm trusted publishing (OIDC, no token; provenance implied).
