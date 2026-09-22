export type TokenErrorCode =
  | 'malformed'
  | 'missing_kid'
  | 'unknown_kid'
  | 'invalid';

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

/** A non-2xx answer from Bastion's HTTP API. */
export class BastionHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'BastionHttpError';
  }
}
