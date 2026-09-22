import { ForbiddenException } from '@nestjs/common';
import type { UserJwtPayload } from '../core/types.js';

export const CROSS_TENANT_ROLE = 'SUPER_ADMIN';

/** The tenant a console user may read: their own, or the requested one if they are SUPER_ADMIN. */
export function resolveTenantScope(user: UserJwtPayload, requested?: string): string | undefined {
  if (user.role === CROSS_TENANT_ROLE) return requested;
  if (!user.tenantId) throw new ForbiddenException('Token without tenant scope');
  return user.tenantId;
}
