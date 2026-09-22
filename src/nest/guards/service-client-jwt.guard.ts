import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { isServiceClientToken } from '../../core/types.js';
import { BastionJwksService } from '../bastion-jwks.service.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from '../options.js';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator.js';
import { REQUIRED_SCOPES_KEY } from '../decorators/require-scope.decorator.js';

/**
 * Machine-to-machine guard, meant as the global `APP_GUARD`: every route needs
 * a `service_client` token issued for this service (`serviceSlug` from the
 * module options, never hard-coded) unless it carries `@Public()`.
 * `@RequireScope()` adds a per-route scope check. The payload lands on `req.user`.
 */
@Injectable()
export class ServiceClientJwtGuard implements CanActivate {
  constructor(
    private readonly jwks: BastionJwksService,
    private readonly reflector: Reflector,
    @Inject(BASTION_OPTIONS) private readonly options: BastionModuleOptions,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) return true;

    const req = ctx.switchToHttp().getRequest<{ headers: Record<string, string | undefined>; user?: unknown }>();
    const auth = req.headers['authorization'];
    if (!auth?.startsWith('Bearer ')) throw new UnauthorizedException('Missing token');

    const payload = await this.jwks.verify(auth.slice(7));
    if (!isServiceClientToken(payload)) throw new UnauthorizedException('Not a service client token');
    if (payload.serviceSlug !== this.options.serviceSlug) {
      throw new ForbiddenException('Token not issued for this service');
    }

    const required = this.reflector.getAllAndOverride<string[] | undefined>(REQUIRED_SCOPES_KEY, targets) ?? [];
    const missing = required.filter((s) => !payload.scopes?.includes(s));
    if (missing.length) throw new ForbiddenException(`Missing scope: ${missing.join(', ')}`);

    req.user = payload;
    return true;
  }
}
