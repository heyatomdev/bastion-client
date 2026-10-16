# Changelog

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
