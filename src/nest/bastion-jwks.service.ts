import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwksVerifier } from '../core/jwks-verifier.js';
import { BastionTokenError } from '../core/errors.js';
import type { BastionJwtPayload } from '../core/types.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';
import { nestLogger } from './nest-logger.js';

/** Verifies inbound Bastion tokens against the cached JWKS. Throws `UnauthorizedException` on any failure. */
@Injectable()
export class BastionJwksService {
  private readonly verifier: JwksVerifier;

  constructor(@Inject(BASTION_OPTIONS) options: BastionModuleOptions) {
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
}
