export type TokenErrorCode =
  | 'malformed'
  | 'missing_kid'
  | 'unknown_kid'
  | 'invalid'
  | 'not_user_token'
  | 'wrong_app';

/** Verification failure. `code` is safe to log; the message is safe to return to the caller. */
export class BastionTokenError extends Error {
  constructor(
    readonly code: TokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BastionTokenError';
  }
}

/**
 * Stable classification of a Bastion error answer, so an app can branch on a
 * code instead of on Bastion's message text. Bastion's own `code` is used when
 * it is one of these; for an older Bastion that sends none, the code is derived
 * from status + message (`classifyBastionError`).
 */
export const BastionErrorCode = {
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  NO_APP_ACCESS: 'NO_APP_ACCESS',
  ACCOUNT_INACTIVE: 'ACCOUNT_INACTIVE',
  /** The app/tenant pair in the request does not resolve: unknown app or tenant, inactive tenant, missing or wrong `tenantSlug`. A configuration error, never the user's. */
  INVALID_APP_CONTEXT: 'INVALID_APP_CONTEXT',
  /** `POST /auth/refresh` refused the token: expired, unknown, or replayed (the whole family is revoked). Re-authenticate. */
  INVALID_REFRESH_TOKEN: 'INVALID_REFRESH_TOKEN',
  /** `POST /auth/exchange` refused the one-time OAuth code: expired, already used, or minted for another app. */
  INVALID_OAUTH_CODE: 'INVALID_OAUTH_CODE',
  /** A 400 carrying field errors (`BastionHttpError.errors`): Bastion's `ValidationPipe`. */
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  /** A 401 from a step-up protected route (password change, email change, 2FA setup/confirm/disable, account delete): the current password or 2FA code is wrong, or the step-up counter is locked. The session is fine — do not log the user out. Bastion sends it as `code`; an older Bastion sends a plain 401, classified `INVALID_CREDENTIALS`. */
  STEP_UP_FAILED: 'STEP_UP_FAILED',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  BIRTH_DATE_REQUIRED: 'BIRTH_DATE_REQUIRED',
  BIRTH_DATE_INVALID: 'BIRTH_DATE_INVALID',
  UNDER_MINIMUM_AGE: 'UNDER_MINIMUM_AGE',
  OAUTH_FLOW_INVALID: 'OAUTH_FLOW_INVALID',
  OAUTH_EMAIL_UNVERIFIED: 'OAUTH_EMAIL_UNVERIFIED',
  OAUTH_EMAIL_REQUIRED: 'OAUTH_EMAIL_REQUIRED',
  OAUTH_NO_ACCOUNT: 'OAUTH_NO_ACCOUNT',
  /** `completeSocialAccountLink` called with a token that is not the link ticket's owner. The code is spent; start the link again. */
  OAUTH_LINK_USER_MISMATCH: 'OAUTH_LINK_USER_MISMATCH',
  /** OAuth signup with an email that a verified account of the tenant already owns. */
  OAUTH_EMAIL_TAKEN: 'OAUTH_EMAIL_TAKEN',
  OAUTH_USER_INACTIVE: 'OAUTH_USER_INACTIVE',
  OAUTH_UNDER_MINIMUM_AGE: 'OAUTH_UNDER_MINIMUM_AGE',
  /** Linking a provider account that belongs to another user. */
  PROVIDER_TAKEN: 'PROVIDER_TAKEN',
  /** The user already has an account of this provider linked. */
  ALREADY_LINKED: 'ALREADY_LINKED',
  AGE_ALREADY_VERIFIED: 'AGE_ALREADY_VERIFIED',
  AGE_GATE_NOT_CONFIGURED: 'AGE_GATE_NOT_CONFIGURED',
  /** A step-up route was called without `currentPassword`. Ask for it; the session is fine. */
  CURRENT_PASSWORD_REQUIRED: 'CURRENT_PASSWORD_REQUIRED',
  /** A step-up route was called without `twoFactorCode`. Ask for it; the session is fine. */
  TWO_FACTOR_CODE_REQUIRED: 'TWO_FACTOR_CODE_REQUIRED',
  /** `POST /auth/2fa/authenticate`: the TOTP/recovery code is wrong. Ask again; the challenge is still valid. */
  TWO_FACTOR_CODE_INVALID: 'TWO_FACTOR_CODE_INVALID',
  /** `POST /auth/2fa/authenticate`: the challenge token expired. Start the login again. */
  TWO_FACTOR_CHALLENGE_EXPIRED: 'TWO_FACTOR_CHALLENGE_EXPIRED',
  /** The service client (API key) is inactive. A configuration error, never the user's. */
  CLIENT_INACTIVE: 'CLIENT_INACTIVE',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  UNAVAILABLE: 'UNAVAILABLE',
  UPSTREAM: 'UPSTREAM',
} as const;
export type BastionErrorCode = (typeof BastionErrorCode)[keyof typeof BastionErrorCode];

/** Which step-up credential a `STEP_UP_FAILED` refers to. */
export type BastionStepUpFactor = 'password' | 'second_factor';

/** Messages Bastion already emits as a bare code: passed through unchanged. */
const CODE_MESSAGES: ReadonlySet<string> = new Set([
  BastionErrorCode.BIRTH_DATE_REQUIRED,
  BastionErrorCode.BIRTH_DATE_INVALID,
  BastionErrorCode.UNDER_MINIMUM_AGE,
  BastionErrorCode.OAUTH_FLOW_INVALID,
  BastionErrorCode.OAUTH_EMAIL_UNVERIFIED,
  BastionErrorCode.OAUTH_EMAIL_REQUIRED,
  BastionErrorCode.OAUTH_NO_ACCOUNT,
  BastionErrorCode.OAUTH_LINK_USER_MISMATCH,
  BastionErrorCode.OAUTH_EMAIL_TAKEN,
  BastionErrorCode.OAUTH_USER_INACTIVE,
  BastionErrorCode.OAUTH_UNDER_MINIMUM_AGE,
  BastionErrorCode.PROVIDER_TAKEN,
  BastionErrorCode.ALREADY_LINKED,
  BastionErrorCode.AGE_ALREADY_VERIFIED,
  BastionErrorCode.AGE_GATE_NOT_CONFIGURED,
  BastionErrorCode.CURRENT_PASSWORD_REQUIRED,
  BastionErrorCode.TWO_FACTOR_CODE_REQUIRED,
]);

const APP_CONTEXT_RE = /app not found|tenant not found|tenant is inactive|no tenants configured|tenantslug is required/i;
const OAUTH_CODE_RE = /already used code|code expired|code\/app mismatch/i;

export function classifyBastionError(status: number, message: string): BastionErrorCode {
  if (CODE_MESSAGES.has(message)) return message as BastionErrorCode;
  if (APP_CONTEXT_RE.test(message) && (status === 401 || status === 400)) return BastionErrorCode.INVALID_APP_CONTEXT;
  if (status === 403 && /email not verified/i.test(message)) return BastionErrorCode.EMAIL_NOT_VERIFIED;
  if (status === 401) {
    if (/refresh token/i.test(message)) return BastionErrorCode.INVALID_REFRESH_TOKEN;
    if (OAUTH_CODE_RE.test(message)) return BastionErrorCode.INVALID_OAUTH_CODE;
    if (/no access to this app/i.test(message)) return BastionErrorCode.NO_APP_ACCESS;
    if (/inactive|locked/i.test(message)) return BastionErrorCode.ACCOUNT_INACTIVE;
    return BastionErrorCode.INVALID_CREDENTIALS;
  }
  if (status === 403 && /no access to this app/i.test(message)) return BastionErrorCode.NO_APP_ACCESS;
  if (status === 409) return BastionErrorCode.CONFLICT;
  if (status === 429) return BastionErrorCode.RATE_LIMITED;
  if (status === 503) return BastionErrorCode.UNAVAILABLE;
  return BastionErrorCode.UPSTREAM;
}

export function isBastionErrorCode(value: unknown): value is BastionErrorCode {
  return typeof value === 'string' && Object.hasOwn(BastionErrorCode, value);
}

/**
 * A non-2xx answer from Bastion's HTTP API, or Bastion unreachable (`status` 503, code `UNAVAILABLE`).
 * `message` and `errors` are Bastion's own: fine to show for a 4xx, never for a 5xx (api.md §14).
 */
export class BastionHttpError extends Error {
  readonly code: BastionErrorCode;

  constructor(
    readonly status: number,
    message: string,
    code?: BastionErrorCode,
    /** Field errors of a 400 (`VALIDATION_FAILED`), one line each. */
    readonly errors?: string[],
    /** Bastion's own `code` when it is not a `BastionErrorCode` (`NOT_FOUND`, `PASSWORD_TOO_SHORT`, …). */
    readonly upstreamCode?: string,
    /** On `STEP_UP_FAILED`: which credential was wrong. Absent from an older Bastion. */
    readonly factor?: BastionStepUpFactor,
  ) {
    super(message);
    this.name = 'BastionHttpError';
    this.code = code ?? classifyBastionError(status, message);
  }
}
