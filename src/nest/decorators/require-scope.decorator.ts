import { SetMetadata } from '@nestjs/common';

export const REQUIRED_SCOPES_KEY = 'bastion:requiredScopes';
/** Scopes the machine token must carry to reach this route (all of them). Checked by `ServiceClientJwtGuard`. */
export const RequireScope = (...scopes: string[]) => SetMetadata(REQUIRED_SCOPES_KEY, scopes);
