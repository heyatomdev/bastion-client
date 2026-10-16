# Architettura di `@heyatom/bastion-client`

**Aggiornato**: 2026-10-15 (0.8.0)

Documento interno: come è fatto il package e perché. L'uso dall'esterno sta nel
[README](../README.md) (pubblico, su npm) e nella guida di piattaforma
[`docs/integrations/bastion.md`](../../docs/integrations/bastion.md). Le regole HTTP comuni sono in
[`docs/standards/api.md`](../../docs/standards/api.md).

## Entry point

| Import | Sorgente | Dipendenze |
|---|---|---|
| `@heyatom/bastion-client` | `src/core/` | solo Node (≥ 20.19) |
| `@heyatom/bastion-client/nest` | `src/nest/` (riesporta il core) | peer `@nestjs/common`, `@nestjs/core`, `rxjs`, `reflect-metadata` |
| `@heyatom/bastion-client/webhooks` | `src/webhooks/` | solo Node |

Build doppia con `tsc` (`tsconfig.cjs.json`, `tsconfig.esm.json`), `dist/esm/package.json` con
`"type": "module"`. Niente bundler: esbuild/swc perdono `design:paramtypes` e la DI di Nest si
rompe solo al boot del consumer. `scripts/di-smoke.cjs` (`pnpm test:di`) avvia
`BastionModule` da `dist/cjs` e risolve ogni provider: è il controllo che lo garantisce.

Nessuna dipendenza runtime ESM-only. Fino alla 0.7.x c'era `jose` v6, solo ESM: la build CJS
faceva `require('jose')` e Jest (che non supporta `require(esm)`) chiedeva
`transformIgnorePatterns` in ogni consumer. Dalla 0.8.0 la verifica è su `node:crypto`; `jose`
resta solo devDependency per firmare i token nei test.

## Core

### `JwksVerifier` + `jwt.ts`

- JWKS da `<baseUrl>/.well-known/jwks.json`, chiavi indicizzate per `kid`, TTL 5 min (come il
  `Cache-Control` di Bastion). Fetch single-flight.
- `kid` sconosciuto → un refetch, poi cooldown di 30 s: il `kid` viene da un header non verificato,
  senza cooldown sarebbe un amplificatore di richieste verso Bastion.
- Refetch fallito con cache piena → si serve la cache scaduta (warn). Una chiave del JWKS che non
  si importa si salta, le altre restano usabili.
- `jwt.ts` replica i controlli che faceva `jose.jwtVerify`:
  - segmenti in alfabeto base64url stretto (il decoder di `Buffer` ignora padding e caratteri
    estranei: senza il controllo lo stesso token avrebbe infinite grafie valide);
  - `alg === 'RS256'` obbligatorio, `crit` rifiutato;
  - chiave solo da JWK `kty: 'RSA'`, `alg` assente o `RS256`, `use` assente o `sig`, modulo ≥ 2048
    bit. Una chiave RSA non può verificare HS256/none/PSS: niente alg confusion;
  - firma su `header.payload` così come arrivano (nessuna ricanonicalizzazione);
  - `exp` obbligatorio (Bastion lo mette sempre), `nbf` e tipo di `iat` se presenti, `iss`
    (default `bastion`, `null` lo salta).
- Errori: `BastionTokenError` con `code` (`malformed`, `missing_kid`, `unknown_kid`, `invalid`,
  `not_user_token`, `wrong_app`). Il messaggio si può restituire al chiamante.
- Una sola chiave firma tutta la flotta: la firma da sola non dice per quale app è il token.
  `assertUserTokenFor` controlla `type` assente, `aud === appSlug === <slug>`, `sub`.

### `BastionHttp`

- `call(method, path, body?, init?)`: timeout (default 8 s), `Authorization` da `init.token`.
- `X-Request-Id`: preso dal getter `requestId` a ogni chiamata, inviato solo se rispetta
  `/^[A-Za-z0-9._-]{1,64}$/` (api.md §7) e se il chiamante non l'ha già messo (confronto
  case-insensitive).
- Errori → `BastionHttpError { status, code, message, errors?, upstreamCode? }`:
  - Bastion irraggiungibile o in timeout: 503 `UNAVAILABLE`;
  - body nel formato api.md §3 `{ code, message, errors? }`; le build vecchie di Bastion mettono
    gli errori di validazione in `message: string[]`, gestito uguale (messaggio = join);
  - `code` del body tenuto se è un `BastionErrorCode`, altrimenti finisce in `upstreamCode` e il
    codice si deriva con `classifyBastionError(status, message)`;
  - un codice ancora trasportato in `message` (`{ code: 'FORBIDDEN', message: 'UNDER_MINIMUM_AGE' }`)
    vince sul `code` generico del body;
  - 400 con `errors` → `VALIDATION_FAILED`.
- `classifyBastionError` esiste perché Bastion non ha ancora un `code` di dominio su ogni errore:
  le regex su `message` vanno tolte quando ce l'avrà. Il fallback è `UPSTREAM`.

### `BastionApiClient`

Lato utente dell'API di Bastion, per un backend che fa da BFF. Stato in memoria per processo:

- `refresh` single-flight per refresh token (chiave = sha256 del token) e memoria della risposta
  per `refreshMemoryMs` (60 s). Bastion ruota il token a ogni uso e un replay revoca l'intera
  famiglia: due refresh concorrenti dello stesso browser devono diventare una chiamata.
- `logout` segue la catena di rotazione (`successors`, max 32 salti) e revoca il token che il
  browser ha davvero. Non lancia mai.
- `getAuthMethods` in cache 5 min, stale-on-error.
- `oauthStart(provider)`: `state` da 32 byte casuali (base64url, 43 caratteri) sull'URL di
  initiate. `exchange` richiede `state` (vuoto → reject prima della chiamata): Bastion rifiuta un
  codice emesso sotto un altro `state`, ed è questo che blocca il login CSRF.

### `ServiceTokenProvider`

Token machine-to-machine (`POST /auth/client`): cache per `serviceSlug`, rinnovo 5 min prima di
`exp` (letto senza verifica: il token l'abbiamo appena ricevuto da Bastion), single-flight,
stale-on-error finché il vecchio è dentro `exp`.

## Adapter Nest

- `BastionModule` è `@Global()`, `forRoot`/`forRootAsync`. Implementa `NestModule.configure`:
  registra `requestContextMiddleware` su `{ path: '{*splat}', method: RequestMethod.ALL }`.
- `request-context.ts`: `AsyncLocalStorage` il cui store è l'oggetto request stesso;
  `currentRequestId()` legge `req.id` **al momento della chiamata**, quindi l'ordine rispetto al
  middleware di pino-http (nest-common `genReqId`) non conta. Solo Express: con Fastify il
  middleware riceve la request raw senza `id`, serve l'opzione `requestId`.
- `BastionService.http` è `NestBastionHttp`: converte `BastionHttpError` in `BastionHttpException`.
- `BastionHttpException` (api.md §3/§14):
  - 4xx: status di Bastion, body `{ code, message, errors? }`. Se il codice è `UPSTREAM` (non
    classificato) si usa `upstreamCode` o il default dello status (`NOT_FOUND`, `UNPROCESSABLE`, …);
  - 503 o `UNAVAILABLE` → 503 `UNAVAILABLE`, ogni altro 5xx → 502 `UPSTREAM`, messaggio generico.
    Status e messaggio di Bastion restano su `upstreamStatus`/`upstreamMessage` e in `message`:
    il filtro di nest-common logga `message` e risponde con `getResponse()`, quindi il dettaglio
    finisce solo nel log.
- Guard:
  - `ServiceClientJwtGuard`: machine token con `serviceSlug` del servizio, `@RequireScope()`, `req.user`;
  - `BastionUserGuard`: superficie `/admin/*`, user token di `acceptedAppSlugs` (default
    `meridian`) con un ruolo di `acceptedRoles`, `req.adminUser`. I rifiuti vanno in audit
    (`admin.access_denied`) con cooldown di 5 min per (app, motivo), max 50 chiavi;
  - `AppUserGuard`: utenti dell'app stessa (`verifyUserToken`), `req.user`. Sospensione, age gate
    e ruoli restano all'app, in un guard successivo.
  - Tutti rispettano `@Public()`.
- `BastionAuditService`: `POST /events` fire-and-forget, non lancia. `AuditInterceptor` +
  `@Audit()` attribuiscono a `req.adminUser`. Bastion salva gli eventi come
  `<serviceSlug>.<event>`: si manda il solo `resource.action`.

## Webhook

`verifyWebhookSignature`: Standard Webhooks (`webhook-id`/`-timestamp`/`-signature`, base64
HMAC su `id.timestamp.body`, secret UTF-8 come `signStandardWebhook` di nest-common) se anche
uno solo degli header è presente, altrimenti `X-Bastion-Signature-V2` su timestamp + delivery id
+ body (fallback per Bastion più vecchi, da togliere quando Bastion smette di mandarlo). Rotazione
del secret (lista di secret accettati, qualsiasi `v1`). Bastion non manda più la firma legacy solo-body;
`allowLegacySignature` riapre il replay e va lasciato spento.

## Test e release

- `pnpm lint` (tsc), `pnpm test` (vitest, chiavi RSA vere), `pnpm build`, `pnpm test:di`.
  `prepublishOnly` li esegue tutti.
- Release: aggiornare `version` e [`CHANGELOG.md`](../CHANGELOG.md), commit, tag `vX.Y.Z`, push
  del tag. Il workflow `publish.yml` ripete i controlli, verifica che il tag corrisponda a
  `version` e pubblica con npm trusted publishing (OIDC, provenance inclusa).
- Il pacchetto pubblicato contiene `dist`, `README.md` e `CHANGELOG.md`: niente in quei file deve
  dipendere da path o servizi interni.
