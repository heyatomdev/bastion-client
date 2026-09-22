import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, tap } from 'rxjs';
import type { UserJwtPayload } from '../../core/types.js';
import { BastionAuditService } from '../bastion-audit.service.js';
import { AUDIT_EVENT_KEY, type AuditDescriptor, type AuditRequest } from '../decorators/audit.decorator.js';

/** Pairs with `@Audit()`: after a handler succeeds, writes the event attributed to `req.adminUser`. */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuditInterceptor.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly audit: BastionAuditService,
  ) {}

  intercept(ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const descriptor = this.reflector.get<AuditDescriptor | undefined>(AUDIT_EVENT_KEY, ctx.getHandler());
    if (!descriptor) return next.handle();

    const req = ctx.switchToHttp().getRequest<AuditRequest & { adminUser?: UserJwtPayload }>();
    return next.handle().pipe(
      tap((result) => {
        let metadata: Record<string, unknown>;
        try {
          metadata = descriptor.options.metadata?.(result, req) ?? {};
        } catch (err) {
          this.logger.warn(`audit metadata builder failed event=${descriptor.event}: ${(err as Error).message}`);
          return;
        }
        void this.audit.writeAsAdmin(descriptor.event, req.adminUser, metadata);
      }),
    );
  }
}
