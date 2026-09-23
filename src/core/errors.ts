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
 * code instead of on Bastion's message text. The age-gate codes are Bastion's
 * own (it returns them verbatim); the rest are derived from status + message
 * until Bastion carries a `code` field on every error.
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
  CONFLICT: 'CONFLICT',
  BIRTH_DATE_REQUIRED: 'BIRTH_DATE_REQUIRED',
  BIRTH_DATE_INVALID: 'BIRTH_DATE_INVALID',
  UNDER_MINIMUM_AGE: 'UNDER_MINIMUM_AGE',
  OAUTH_FLOW_INVALID: 'OAUTH_FLOW_INVALID',
  OAUTH_EMAIL_UNVERIFIED: 'OAUTH_EMAIL_UNVERIFIED',
  OAUTH_EMAIL_REQUIRED: 'OAUTH_EMAIL_REQUIRED',
  OAUTH_NO_ACCOUNT: 'OAUTH_NO_ACCOUNT',
  UNAVAILABLE: 'UNAVAILABLE',
  UPSTREAM: 'UPSTREAM',
} as const;
export type BastionErrorCode = (typeof BastionErrorCode)[keyof typeof BastionErrorCode];

/** Messages Bastion already emits as a bare code: passed through unchanged. */
const CODE_MESSAGES: ReadonlySet<string> = new Set([
  BastionErrorCode.BIRTH_DATE_REQUIRED,
  BastionErrorCode.BIRTH_DATE_INVALID,
  BastionErrorCode.UNDER_MINIMUM_AGE,
  BastionErrorCode.OAUTH_FLOW_INVALID,
  BastionErrorCode.OAUTH_EMAIL_UNVERIFIED,
  BastionErrorCode.OAUTH_EMAIL_REQUIRED,
  BastionErrorCode.OAUTH_NO_ACCOUNT,
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
  if (status === 503) return BastionErrorCode.UNAVAILABLE;
  return BastionErrorCode.UPSTREAM;
}

/** A non-2xx answer from Bastion's HTTP API, or Bastion unreachable (`status` 503, code `UNAVAILABLE`). */
export class BastionHttpError extends Error {
  readonly code: BastionErrorCode;

  constructor(
    readonly status: number,
    message: string,
    code?: BastionErrorCode,
  ) {
    super(message);
    this.name = 'BastionHttpError';
    this.code = code ?? classifyBastionError(status, message);
  }
}
