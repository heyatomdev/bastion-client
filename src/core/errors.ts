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
  CONFLICT: 'CONFLICT',
  BIRTH_DATE_REQUIRED: 'BIRTH_DATE_REQUIRED',
  BIRTH_DATE_INVALID: 'BIRTH_DATE_INVALID',
  UNDER_MINIMUM_AGE: 'UNDER_MINIMUM_AGE',
  UNAVAILABLE: 'UNAVAILABLE',
  UPSTREAM: 'UPSTREAM',
} as const;
export type BastionErrorCode = (typeof BastionErrorCode)[keyof typeof BastionErrorCode];

export function classifyBastionError(status: number, message: string): BastionErrorCode {
  if (
    message === BastionErrorCode.BIRTH_DATE_REQUIRED ||
    message === BastionErrorCode.BIRTH_DATE_INVALID ||
    message === BastionErrorCode.UNDER_MINIMUM_AGE
  ) {
    return message;
  }
  if (status === 403 && /email not verified/i.test(message)) return BastionErrorCode.EMAIL_NOT_VERIFIED;
  if (status === 401) {
    if (/no access to this app/i.test(message)) return BastionErrorCode.NO_APP_ACCESS;
    if (/inactive|locked/i.test(message)) return BastionErrorCode.ACCOUNT_INACTIVE;
    return BastionErrorCode.INVALID_CREDENTIALS;
  }
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
