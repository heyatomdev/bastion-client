import { HttpException } from '@nestjs/common';
import { BastionHttp, type BastionRequestInit } from '../core/bastion-http.js';
import { BastionErrorCode, BastionHttpError } from '../core/errors.js';

/**
 * The Nest face of a Bastion error, so the global filter answers the browser
 * per api.md §3/§14:
 * - 4xx: Bastion's status, `code`, message and `errors` (field errors of a 400);
 * - Bastion down, timed out or answering 503: 503 `UNAVAILABLE`, generic message;
 * - any other 5xx: 502 `UPSTREAM`, generic message.
 *
 * `getResponse()` is `{ code, message, errors? }`. `upstreamStatus` and
 * `upstreamMessage` keep Bastion's own for logs and branching; `message`
 * carries them too, so the filter's 5xx log line says what Bastion answered.
 */
export class BastionHttpException extends HttpException {
  readonly upstreamStatus: number;

  constructor(
    readonly code: BastionErrorCode,
    status: number,
    readonly upstreamMessage: string,
    readonly errors?: string[],
  ) {
    const unavailable = code === BastionErrorCode.UNAVAILABLE || status === 503;
    const publicStatus = status < 500 ? status : unavailable ? 503 : 502;
    const body =
      status < 500
        ? { code, message: upstreamMessage, ...(errors?.length ? { errors } : {}) }
        : unavailable
          ? { code: BastionErrorCode.UNAVAILABLE, message: 'Upstream service unavailable' }
          : { code: BastionErrorCode.UPSTREAM, message: 'Upstream service error' };
    super(body, publicStatus);
    this.upstreamStatus = status;
    if (status >= 500) this.message = `Bastion ${status}: ${upstreamMessage}`;
  }

  static from(err: BastionHttpError): BastionHttpException {
    return new BastionHttpException(err.code, err.status, err.message, err.errors);
  }
}

/** `BastionHttp` whose failures are `BastionHttpException`s — what `BastionService.http` is. */
export class NestBastionHttp extends BastionHttp {
  override async call<T>(method: string, path: string, body?: unknown, init?: BastionRequestInit): Promise<T> {
    try {
      return await super.call<T>(method, path, body, init);
    } catch (err) {
      if (err instanceof BastionHttpError) throw BastionHttpException.from(err);
      throw err;
    }
  }
}
