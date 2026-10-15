import { HttpException, HttpStatus } from '@nestjs/common';
import { BastionHttp, type BastionRequestInit } from '../core/bastion-http.js';
import { BastionErrorCode, BastionHttpError } from '../core/errors.js';

/**
 * The Nest face of a Bastion error, so the global filter answers the browser
 * per api.md §3/§14:
 * - 4xx: Bastion's status, `code`, message and `errors` (field errors of a 400). A 4xx the
 *   package can't classify keeps Bastion's own code (`PASSWORD_TOO_SHORT`) or the status
 *   default (`NOT_FOUND`), never `UPSTREAM`;
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
    readonly upstreamCode?: string,
  ) {
    const publicCode = code === BastionErrorCode.UPSTREAM ? (upstreamCode ?? statusCode(status)) : code;
    const unavailable = code === BastionErrorCode.UNAVAILABLE || status === 503;
    const publicStatus = status < 500 ? status : unavailable ? 503 : 502;
    const body =
      status < 500
        ? { code: publicCode, message: upstreamMessage, ...(errors?.length ? { errors } : {}) }
        : unavailable
          ? { code: BastionErrorCode.UNAVAILABLE, message: 'Upstream service unavailable' }
          : { code: BastionErrorCode.UPSTREAM, message: 'Upstream service error' };
    super(body, publicStatus);
    this.upstreamStatus = status;
    if (status >= 500) this.message = `Bastion ${status}: ${upstreamMessage}`;
  }

  static from(err: BastionHttpError): BastionHttpException {
    return new BastionHttpException(err.code, err.status, err.message, err.errors, err.upstreamCode);
  }
}

/** api.md §3 default code of a 4xx: `NOT_FOUND`, `UNPROCESSABLE`, `RATE_LIMITED`, … */
function statusCode(status: number): string {
  if (status === 422) return 'UNPROCESSABLE';
  if (status === 429) return 'RATE_LIMITED';
  return (HttpStatus[status] as string | undefined) ?? 'BAD_REQUEST';
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
