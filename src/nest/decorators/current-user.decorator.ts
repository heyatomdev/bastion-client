import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { ServiceClientJwtPayload, UserJwtPayload } from '../../core/types.js';

/** The machine token payload set by `ServiceClientJwtGuard`. */
export const CurrentClient = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): ServiceClientJwtPayload | undefined =>
    ctx.switchToHttp().getRequest<{ user?: ServiceClientJwtPayload }>().user,
);

/** The user payload set by `BastionUserGuard`. */
export const CurrentAdminUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): UserJwtPayload | undefined =>
    ctx.switchToHttp().getRequest<{ adminUser?: UserJwtPayload }>().adminUser,
);
