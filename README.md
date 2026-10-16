# @heyatom/bastion-client

Client SDK for [Bastion](https://github.com/heyatomdev/bastion), the HeyAtom identity provider.
It verifies Bastion tokens locally against the JWKS, calls Bastion's API (machine-to-machine and
on behalf of your users), verifies Bastion webhooks, and ships ready-made NestJS guards.

```bash
pnpm add @heyatom/bastion-client
```

- Node ≥ 20.19. CJS and ESM builds, no ESM-only runtime dependency (works in Jest as is).
- NestJS adapter: peer dependencies `@nestjs/common` and `@nestjs/core` 11, `rxjs`, `reflect-metadata`.

| Import | What |
|---|---|
| `@heyatom/bastion-client` | Framework-free core: `JwksVerifier`, `BastionHttp`, `ServiceTokenProvider`, `BastionApiClient`, types, error codes |
| `@heyatom/bastion-client/nest` | `BastionModule`, guards, decorators, audit (re-exports the core) |
| `@heyatom/bastion-client/webhooks` | `verifyWebhookSignature` |

## NestJS

```ts
import { APP_GUARD } from '@nestjs/core';
import { BastionModule, ServiceClientJwtGuard } from '@heyatom/bastion-client/nest';

@Module({
  imports: [
    BastionModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        baseUrl: config.getOrThrow('BASTION_URL'),
        serviceSlug: config.getOrThrow('BASTION_APP_SLUG'), // this service's slug in Bastion
        apiKey: config.get('BASTION_CLIENT_API_KEY'),       // needed for outbound calls and audit
      }),
    }),
  ],
  providers: [{ provide: APP_GUARD, useClass: ServiceClientJwtGuard }],
})
export class AppModule {}
```

`BastionModule` is global. Options:

| Option | Default | |
|---|---|---|
| `baseUrl` | — | Bastion base URL |
| `serviceSlug` | — | Your app/service slug |
| `apiKey` | — | Service client key, for outbound calls |
| `tenantSlug` | — | Required when the app lives in more than one tenant |
| `timeoutMs` | `8000` | Outbound call timeout |
| `jwksTtlMs` | `300000` | JWKS cache lifetime |
| `issuer` | `'bastion'` | Expected `iss`; `null` skips the check |
| `acceptedAppSlugs` / `acceptedRoles` | `['meridian']` / `['ADMIN', 'OWNER', 'SUPER_ADMIN']` | Who `BastionUserGuard` lets in |
| `requestId` | the served request's `req.id` | Sent as `X-Request-Id` to Bastion. Express only by default; on Fastify pass a getter |

### Guards

| Guard | Accepts | Payload on |
|---|---|---|
| `ServiceClientJwtGuard` | Machine tokens issued for this service; `@RequireScope('mail.send')` per route | `req.user`, `@CurrentClient()` |
| `AppUserGuard` | Your app's own users (rejects machine tokens and other apps' tokens) | `req.user`, `@CurrentUser()` |
| `BastionUserGuard` | Admin-console users with an accepted app and role | `req.adminUser`, `@CurrentAdminUser()` |

All of them skip routes marked `@Public()`. Use one as the global `APP_GUARD` and the others with
`@UseGuards()`. Suspension, age gate or custom roles are yours: add a guard after `AppUserGuard`.

```ts
@Controller('mail')
export class MailController {
  constructor(private readonly audit: BastionAuditService) {}

  @Post('send')
  @RequireScope('mail.send')
  send(@CurrentClient() client: ServiceClientJwtPayload, @Body() dto: SendDto) {
    void this.audit.write('mail.sent', { metadata: { toDomain: 'example.com' } }); // never throws
  }

  @Public()
  @Get('health')
  health() { return { status: 'ok' }; }
}

@Controller('admin/config')
@UseGuards(BastionUserGuard)
@UseInterceptors(AuditInterceptor)
export class AdminController {
  @Patch()
  @Audit('config.updated')
  update(@CurrentAdminUser() admin: UserJwtPayload, @Body() dto: UpdateDto) { /* ... */ }
}
```

Audit events are stored by Bastion as `<serviceSlug>.<event>`: send `resource.action`.

### Backend for your users (BFF)

`BastionApiClientProvider` is `BastionApiClient` bound to your `serviceSlug` and `tenantSlug`:
login, register, OAuth, 2FA, refresh, logout, sessions, profile, social accounts, email and
password flows, data export, account deletion.

```ts
@Controller('auth')
export class AuthController {
  constructor(private readonly bastion: BastionApiClientProvider) {}

  @Public()
  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request) {
    // Pass the browser's IP and user agent: Bastion rate-limits per IP.
    return this.bastion.login(dto.email, dto.password, { ip: req.ip, userAgent: req.headers['user-agent'] });
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
    const state = req.cookies.oauthState; // from your cookie, never from the query string
    res.clearCookie('oauthState', { path: '/auth/callback' });
    if (!code || !state) throw new UnauthorizedException();
    return this.bastion.exchange(code, { ip: req.ip, userAgent: req.headers['user-agent'] }, state);
  }
}
```

- `exchange` requires the `state` returned by `oauthStart`: it is what stops login CSRF.
- `refresh` is single-flight per token and remembers each answer for `refreshMemoryMs` (60 s):
  Bastion rotates refresh tokens and revokes the whole family on reuse, so concurrent refreshes
  from one browser must collapse into one call. Use one client instance per process.
- `logout` revokes the latest token in the rotation chain and never throws.

## Errors

Every failed call throws `BastionHttpError` (core) or `BastionHttpException` (Nest) with a stable
`code` (`BastionErrorCode`), so you never match Bastion's message text:

`INVALID_CREDENTIALS`, `EMAIL_NOT_VERIFIED`, `NO_APP_ACCESS`, `ACCOUNT_INACTIVE`,
`INVALID_APP_CONTEXT` (your configuration, not the user), `INVALID_REFRESH_TOKEN`,
`INVALID_OAUTH_CODE`, `VALIDATION_FAILED`, `STEP_UP_FAILED` (wrong current password or 2FA
code on a step-up route: the session is fine), `CONFLICT`, `RATE_LIMITED`, the age-gate codes
(`BIRTH_DATE_REQUIRED`, `BIRTH_DATE_INVALID`, `UNDER_MINIMUM_AGE`), the OAuth flow codes
(`OAUTH_*`), `UNAVAILABLE` (Bastion unreachable or timed out) and `UPSTREAM`.

- A 400 carries the field errors in `errors: string[]`. Show them: `message` is only
  "Validation failed".
- A code outside `BastionErrorCode` (e.g. a password-policy code) is on `upstreamCode`.

`BastionHttpException` is safe to let through to the client:

- a 4xx keeps Bastion's status and answers `{ code, message, errors? }`;
- a 5xx becomes 502 `UPSTREAM`, or 503 `UNAVAILABLE` when Bastion is down, with a generic message.
  Bastion's own status and message stay on `upstreamStatus` / `upstreamMessage` and in
  `message`, for your logs.

```ts
try {
  return await this.bastion.login(email, password, ctx);
} catch (err) {
  if (err instanceof BastionHttpException && err.code === 'EMAIL_NOT_VERIFIED') { /* ... */ }
  throw err;
}
```

## Without NestJS

```ts
import { JwksVerifier, BastionHttp, ServiceTokenProvider, BastionApiClient, assertUserTokenFor } from '@heyatom/bastion-client';

// Verify incoming tokens (throws BastionTokenError)
const verifier = new JwksVerifier({ baseUrl: process.env.BASTION_URL! });
const payload = await verifier.verify(bearerToken);
const user = assertUserTokenFor(payload, 'my-app'); // only your app's user tokens

// Call Bastion
const http = new BastionHttp({
  baseUrl: process.env.BASTION_URL!,
  requestId: () => currentRequestIdFromYourFramework(), // optional, sent as X-Request-Id
});
const tokens = new ServiceTokenProvider(http, { apiKey, serviceSlug: 'my-service' });
await http.writeAuditEvent(await tokens.getToken(), { event: 'thing.done' });

const api = new BastionApiClient({ http, appSlug: 'my-app' });
```

`ServiceTokenProvider` also takes several credentials, as a record keyed by `serviceSlug` or as
`{ defaultSlug, resolve: (slug) => credential | null }`.

## Webhooks

```ts
import { verifyWebhookSignature } from '@heyatom/bastion-client/webhooks';

// Needs the raw body: NestFactory.create(AppModule, { rawBody: true })
const result = verifyWebhookSignature({
  rawBody: req.rawBody,
  headers: req.headers,
  secrets: [secret, previousSecret], // both accepted during a rotation
});
if (!result.ok) throw new UnauthorizedException(result.reason);
// result.deliveryId: store it and ignore repeats
```

Checks [Standard Webhooks](https://www.standardwebhooks.com/) headers (`webhook-id`,
`webhook-timestamp`, `webhook-signature`) when present: HMAC-SHA256 over id + timestamp + body,
5 min tolerance, secret used as a UTF-8 string, `result.deliveryId` = `webhook-id`. Without them
it falls back to `X-Bastion-Signature-V2` (same guarantees), so it works against an older Bastion
too; Bastion will stop sending V2 in a later release. `result.version` says which one matched.
Leave `allowLegacySignature` off.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
