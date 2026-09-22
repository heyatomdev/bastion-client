import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwksVerifier } from '../core/jwks-verifier.js';
import { BastionTokenError } from '../core/errors.js';
import { assertUserTokenFor, type BastionJwtPayload, type UserJwtPayload } from '../core/types.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';
import { nestLogger } from './nest-logger.js';

/** Verifies inbound Bastion tokens against the cached JWKS. Throws `UnauthorizedException` on any failure. */
@Injectable()
export class BastionJwksService {
  private readonly verifier: JwksVerifier;

  private readonly appSlug: string;

  constructor(@Inject(BASTION_OPTIONS) options: BastionModuleOptions) {
    this.appSlug = options.serviceSlug;
    this.verifier = new JwksVerifier({
      baseUrl: options.baseUrl,
      ttlMs: options.jwksTtlMs,
      issuer: options.issuer,
      logger: nestLogger(BastionJwksService.name),
    });
  }

  async verify(token: string): Promise<BastionJwtPayload> {
    try {
      return await this.verifier.verify(token);
    } catch (err) {
      if (err instanceof BastionTokenError) throw new UnauthorizedException(err.message);
      throw err;
    }
  }

  /**
   * A *user* session token issued for this app (`options.serviceSlug` is the
   * app's own slug). What an app backend puts behind its own auth guard —
   * cookie extraction, suspension, age gate stay the app's business.
   */
  async verifyUserToken(token: string): Promise<UserJwtPayload> {
    const payload = await this.verify(token);
    try {
      return assertUserTokenFor(payload, this.appSlug);
    } catch (err) {
      if (err instanceof BastionTokenError) throw new UnauthorizedException(err.message);
      throw err;
    }
  }
}
