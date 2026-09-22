import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { isServiceClientToken, type UserJwtPayload } from '../../core/types.js';
import { BastionJwksService } from '../bastion-jwks.service.js';
import { BastionAuditService } from '../bastion-audit.service.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from '../options.js';

const ACCESS_DENIED_COOLDOWN_MS = 5 * 60 * 1000;
const ACCESS_DENIED_MAX_KEYS = 50;
const DEFAULT_ACCEPTED_APP_SLUGS = ['meridian'];
const DEFAULT_ACCEPTED_ROLES = ['ADMIN', 'OWNER', 'SUPER_ADMIN'];

/**
 * Admin-surface guard: accepts a *user* token from one of `acceptedAppSlugs`
 * (the console, typically) with one of `acceptedRoles`. Sets `req.adminUser`.
 * A denial is audited as `admin.access_denied`, rate-limited per (app, reason)
 * so a misconfigured console cannot flood the log.
 */
@Injectable()
export class BastionUserGuard implements CanActivate {
  private readonly acceptedAppSlugs: string[];
  private readonly acceptedRoles: string[];
  private readonly reportedAt = new Map<string, number>();

  constructor(
    private readonly jwks: BastionJwksService,
    private readonly audit: BastionAuditService,
    @Inject(BASTION_OPTIONS) options: BastionModuleOptions,
  ) {
    this.acceptedAppSlugs = options.acceptedAppSlugs ?? DEFAULT_ACCEPTED_APP_SLUGS;
    this.acceptedRoles = options.acceptedRoles ?? DEFAULT_ACCEPTED_ROLES;
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<{
      headers: Record<string, string | undefined>;
      adminUser?: UserJwtPayload;
      originalUrl?: string;
      url?: string;
    }>();
    const auth = req.headers['authorization'];
    if (!auth?.startsWith('Bearer ')) throw new UnauthorizedException('Missing token');

    const payload = await this.jwks.verify(auth.slice(7));
    if (isServiceClientToken(payload)) throw new UnauthorizedException('Service client token not allowed');

    if (!this.acceptedAppSlugs.includes(payload.appSlug)) {
      this.reportAccessDenied('app_not_allowed', payload, req);
      throw new ForbiddenException('App not allowed');
    }
    if (!this.acceptedRoles.includes(payload.role ?? '')) {
      this.reportAccessDenied('role_insufficient', payload, req);
      throw new ForbiddenException('Insufficient role');
    }

    req.adminUser = payload;
    return true;
  }

  private reportAccessDenied(
    reason: 'app_not_allowed' | 'role_insufficient',
    user: UserJwtPayload,
    req: { originalUrl?: string; url?: string },
  ): void {
    const key = `${user.appSlug}:${reason}`;
    const now = Date.now();
    const last = this.reportedAt.get(key);
    if (last !== undefined && now - last < ACCESS_DENIED_COOLDOWN_MS) return;
    if (this.reportedAt.size >= ACCESS_DENIED_MAX_KEYS) this.reportedAt.clear();
    this.reportedAt.set(key, now);
    void this.audit.write('admin.access_denied', {
      metadata: {
        reason,
        appSlug: user.appSlug,
        role: user.role ?? 'none',
        path: req.originalUrl ?? req.url ?? 'unknown',
      },
    });
  }
}
