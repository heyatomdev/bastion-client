import { HttpException } from '@nestjs/common';
import { BastionHttp, type BastionRequestInit } from '../core/bastion-http.js';
import { BastionHttpError, type BastionErrorCode } from '../core/errors.js';

/**
 * The Nest face of a Bastion error: an `HttpException` carrying Bastion's
 * status, so the global filter answers with it unchanged, plus the stable
 * `code` and the upstream message for the handlers that branch on them.
 * `getResponse()` is `{ code, message }`.
 */
export class BastionHttpException extends HttpException {
  constructor(
    readonly code: BastionErrorCode,
    status: number,
    readonly upstreamMessage: string,
  ) {
    super({ code, message: upstreamMessage }, status);
  }

  static from(err: BastionHttpError): BastionHttpException {
    return new BastionHttpException(err.code, err.status, err.message);
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
