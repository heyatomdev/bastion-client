# Changelog

## Unreleased

### Added

- `BastionWebhookEvent`: discriminated union of every webhook event Bastion sends, with its extra fields (`newEmail`, `oldRole`/`newRole`, `initiator`, …). `switch (payload.event)` narrows them. `BastionWebhookEventName` is the union of event names. `BastionWebhookPayload` stays as the loose shape.

## 2.0.0

### Breaking

- `verifyWebhookSignature` verifies only [Standard Webhooks](https://www.standardwebhooks.com/) headers. `X-Bastion-Signature-V2` and the legacy `X-Bastion-Signature` are no longer read: a delivery without `webhook-id` / `webhook-timestamp` / `webhook-signature` is `{ ok: false, reason: 'missing' }`. Requires Bastion >= 1.8.0 (the first to send Standard Webhooks headers); Bastion's next release drops the V2 header.
- Removed `allowLegacySignature`, `BASTION_SIGNATURE_HEADER`, `BASTION_SIGNATURE_V2_HEADER`; `VerifyWebhookResult` is now `{ ok: true; version: 'standard'; … }` or a failure.
- Classification change, like 1.0.0: `TWO_FACTOR_CODE_INVALID` and `TWO_FACTOR_CHALLENGE_EXPIRED` are sent only by a Bastion release that includes them (not yet released). Until then a wrong 2FA code (`'Invalid code'`) is classified `INVALID_CREDENTIALS`; once Bastion ships them, `err.code` becomes the new codes.
- Same for `CLIENT_INACTIVE` and `USER_NOT_FOUND`: against a Bastion that sends these codes, a 401 `'Client is inactive'` moves from `ACCOUNT_INACTIVE` to `CLIENT_INACTIVE`, and a 401 `'User not found'` moves from `INVALID_CREDENTIALS` to `USER_NOT_FOUND`. An older Bastion keeps the old text-derived classification.

### Added

- `BastionHttpError.factor` and `BastionHttpException.factor` (`BastionStepUpFactor`: `'password' | 'second_factor'`): which credential a `STEP_UP_FAILED` refers to, parsed from Bastion's error body. `BastionHttpException` also puts it in the response body.
- `BastionErrorCode.TWO_FACTOR_CODE_INVALID`, `TWO_FACTOR_CHALLENGE_EXPIRED` (`POST /auth/2fa/authenticate`), `CLIENT_INACTIVE` and `USER_NOT_FOUND`. Bastion's `code` wins over message classification.

## 1.0.0

Reads both the current Bastion answers and the `{ data }` envelope Bastion 2.0 will send, so you can upgrade before Bastion does.

### Breaking

- `BastionHttp.call` (and so every `BastionApiClient`, `BastionService.call`, `ServiceTokenProvider` and `BastionHttpException` call) unwraps a success body whose only key is `data` and returns `data`. A page (`{ data, meta }`), an array, any other object and an empty body are returned unchanged. Three Bastion routes answer `{ data }` alone today (`GET /auth/me/tenants`, `GET /admin/apps/:slug/permissions`, `PUT /admin/apps/:slug/roles/:roleId/permissions`): through `call` they now give you the inner array. Read them as `Array.isArray(res) ? res : res.data`, which also works with any later Bastion.
- `listMyEvents` returns `{ data, meta: { total, page, limit, totalPages } }` (new type `BastionPageMeta`). An older Bastion's `{ data, total, page, limit }` is converted to this shape.
- `err.code` is the domain code for `PROVIDER_TAKEN`, `ALREADY_LINKED`, `OAUTH_EMAIL_TAKEN`, `AGE_ALREADY_VERIFIED` (previously `CONFLICT`), `AGE_GATE_NOT_CONFIGURED`, `CURRENT_PASSWORD_REQUIRED`, `TWO_FACTOR_CODE_REQUIRED`, `OAUTH_USER_INACTIVE`, `OAUTH_UNDER_MINIMUM_AGE` (previously `UPSTREAM`). `BastionHttpException` forwards that code to your client instead of `CONFLICT` / `BAD_REQUEST` / `FORBIDDEN`. When Bastion sends these codes in `code`, `upstreamCode` is no longer set for them.

### Added

- The error codes above in `BastionErrorCode`.
- Bastion's `code` is used whenever it is a `BastionErrorCode` and `message` is not itself one, so the code survives a reworded `message`. Message-based classification stays as the fallback for a Bastion that sends no domain `code`.

## 0.9.0

### Added

- `verifyWebhookSignature` verifies [Standard Webhooks](https://www.standardwebhooks.com/) headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`: space-separated `v1,<base64 HMAC-SHA256("<id>.<timestamp>.<body>")>`, secret used as UTF-8). When any of them is present they are the ones checked: same tolerance, any secret against any `v1` entry, `deliveryId` = `webhook-id`, result `version: 'standard'`.
- Header name constants `WEBHOOK_ID_HEADER`, `WEBHOOK_TIMESTAMP_HEADER`, `WEBHOOK_SIGNATURE_HEADER`.

### Changed

- Without Standard Webhooks headers, `X-Bastion-Signature-V2` is verified exactly as before, so receivers keep working against an older Bastion. Bastion sends both for one release and will then drop V2. `allowLegacySignature` is unchanged.
- Whitespace-only entries in `secrets` (e.g. `' '` from an unset env var) are ignored instead of keying the HMAC; if none is left the result is `{ ok: false, reason: 'missing' }`. Other secrets are still used byte-exact (not trimmed).

### Breaking (types)

- `VerifyWebhookResult` gains the `version: 'standard'` variant: an exhaustive `switch` on `version` needs the new case.

## 0.8.1

### Added

- Error code `STEP_UP_FAILED`: the 401 Bastion answers when the current password or 2FA code of a step-up protected route is wrong (or the step-up counter is locked). Tells a wrong factor apart from a dead session, also a 401 (`INVALID_CREDENTIALS`). Needs a Bastion that sends `code: 'STEP_UP_FAILED'`; an older one still classifies as `INVALID_CREDENTIALS`.

## 0.8.0

### Breaking

- `BastionApiClient.exchange(code, ctx, state)` requires `state`; an empty one rejects before calling Bastion. Get it from the new `oauthStart`.
- `jose` is no longer a peer dependency: token verification runs on `node:crypto`. The CJS build no longer loads an ESM-only module, so Jest needs no `transformIgnorePatterns`.
- `BastionHttpException` no longer forwards Bastion's 5xx: it answers 502 `UPSTREAM` (503 `UNAVAILABLE` when Bastion is down) with a generic message. Bastion's status and message stay on `upstreamStatus`, `upstreamMessage` and `message`.
- Tokens whose segments are not strict base64url (padding, stray characters) are rejected as `malformed`.

### Added

- `BastionApiClient.oauthStart(provider)` → `{ url, state } | null`.
- `AppUserGuard` and `@CurrentUser()` for an app's own users.
- `X-Request-Id` on every call to Bastion: `BastionHttpOptions.requestId`; in NestJS the served request's `req.id` by default (`BastionModuleOptions.requestId` to override).
- `BastionHttpError.errors` (field errors of a 400) and `upstreamCode` (a code outside `BastionErrorCode`).
- Error codes `VALIDATION_FAILED` and `RATE_LIMITED`.

### Fixed

- Validation errors from Bastion were reduced to "Validation failed": the field errors and Bastion's `code` are now kept.
- A 4xx with a code the package does not know answered `UPSTREAM`: it now keeps Bastion's code or the status default (`NOT_FOUND`, `UNPROCESSABLE`, …).

## 0.7.2

- `completeAgeVerification(token, birthDate, { currentPassword?, twoFactorCode? })` sends the required step-up.
- `UserJwtPayload.ageVerificationRequired` while the account owes the app's age screen.

## 0.7.1

- `exchange` sends the OAuth flow `state`.

## 0.7.0

- Step-up on `completeSocialAccountLink`.
- **Breaking**: webhooks with only the legacy `X-Bastion-Signature` are rejected unless `allowLegacySignature` is set.

## 0.6.0

- `BastionSocialAccount.providerId`.
