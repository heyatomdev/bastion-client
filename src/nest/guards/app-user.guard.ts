import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { UserJwtPayload } from '../../core/types.js';
import { BastionJwksService } from '../bastion-jwks.service.js';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator.js';

/**
 * Guard for an app backend's own users, meant as the global `APP_GUARD`: every
 * route needs a Bastion *user* token minted for this app (`serviceSlug` is the
 * app's slug) unless it carries `@Public()`. Machine tokens and other apps'
 * tokens are refused. The payload lands on `req.user`, read with `@CurrentUser()`.
 * Suspension, age gate and roles stay the app's business: stack its own guard after this one.
 */
@Injectable()
export class AppUserGuard implements CanActivate {
  constructor(
    private readonly jwks: BastionJwksService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [ctx.getHandler(), ctx.getClass()])) return true;

    const req = ctx.switchToHttp().getRequest<{ headers: Record<string, string | undefined>; user?: UserJwtPayload }>();
    const auth = req.headers['authorization'];
    if (!auth?.startsWith('Bearer ')) throw new UnauthorizedException('Missing token');

    req.user = await this.jwks.verifyUserToken(auth.slice(7));
    return true;
  }
}
