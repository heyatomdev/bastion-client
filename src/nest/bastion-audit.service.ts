import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ServiceTokenProvider } from '../core/service-token-provider.js';
import type { UserJwtPayload } from '../core/types.js';
import { BastionService } from './bastion.service.js';
import { BASTION_OPTIONS, type BastionModuleOptions } from './options.js';
import { nestLogger } from './nest-logger.js';

/**
 * Fire-and-forget audit writes to `POST /events` under this service's own
 * machine token. Never throws: a failed write is logged, the request that
 * produced it is not affected.
 */
@Injectable()
export class BastionAuditService implements OnModuleInit {
  private readonly logger = new Logger(BastionAuditService.name);
  private readonly tokens: ServiceTokenProvider | null;
  private tenantMismatchWarned = false;

  constructor(
    private readonly bastion: BastionService,
    @Inject(BASTION_OPTIONS) options: BastionModuleOptions,
  ) {
    this.tokens = options.apiKey
      ? new ServiceTokenProvider(
          bastion.http,
          {
            apiKey: options.apiKey,
            serviceSlug: options.serviceSlug,
            ...(options.tenantSlug ? { tenantSlug: options.tenantSlug } : {}),
          },
          nestLogger(BastionAuditService.name),
        )
      : null;
  }

  async onModuleInit(): Promise<void> {
    if (!this.tokens) return;
    await this.tokens.getToken().catch((err: Error) =>
      this.logger.error(`Bastion unreachable at startup, will retry on first write: ${err.message}`),
    );
  }

  /** Tenant of this service's machine token, once known. */
  get tenantId(): string | null {
    return this.tokens?.tenantId ?? null;
  }

  async write(
    event: string,
    opts: { userId?: string; metadata?: Record<string, unknown> } = {},
  ): Promise<void> {
    if (!this.tokens) {
      this.logger.warn(`audit write skipped, no apiKey configured event=${event}`);
      return;
    }
    let token: string;
    try {
      token = await this.tokens.getToken();
    } catch (err) {
      this.logger.error(`audit write skipped, no service client token event=${event}: ${(err as Error).message}`);
      return;
    }
    await this.bastion
      .writeAuditEvent(token, { event, ...opts })
      .catch((err: Error) => this.logger.error(`audit write failed event=${event}: ${err.message}`));
  }

  /**
   * Attribute an event to an admin user. `userId` is only set when the actor
   * belongs to the same tenant as this service's token — Bastion rejects a
   * foreign userId silently — otherwise the actor goes into `metadata`.
   */
  async writeAsAdmin(
    event: string,
    actor: UserJwtPayload | undefined,
    metadata: Record<string, unknown> = {},
  ): Promise<void> {
    await this.tokens?.getToken().catch(() => undefined);
    const sameTenant = Boolean(actor?.sub) && Boolean(this.tenantId) && actor?.tenantId === this.tenantId;
    if (sameTenant && actor) return this.write(event, { userId: actor.sub, metadata });

    if (actor && !this.tenantMismatchWarned) {
      this.tenantMismatchWarned = true;
      this.logger.warn(
        `admin tenant (${actor.tenantSlug ?? actor.tenantId}) differs from this service's tenant (${this.tenantId ?? 'unknown'}) — audit events fall back to actor metadata instead of userId`,
      );
    }
    return this.write(event, {
      metadata: {
        ...metadata,
        actorId: actor?.sub ?? 'unknown',
        actorRole: actor?.role ?? 'unknown',
        actorAppSlug: actor?.appSlug ?? 'unknown',
      },
    });
  }
}
