import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
/** Exempts a route (or a whole controller) from `ServiceClientJwtGuard`. */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
