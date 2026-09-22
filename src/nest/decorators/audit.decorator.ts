import { SetMetadata } from '@nestjs/common';

export const AUDIT_EVENT_KEY = 'bastion:auditEvent';

export interface AuditRequest {
  params: Record<string, string>;
  body: unknown;
}

export interface AuditOptions {
  /** Builds the metadata from the handler's result and the request. Errors here are logged, never propagated. */
  metadata?: (result: unknown, req: AuditRequest) => Record<string, unknown>;
}

export interface AuditDescriptor {
  event: string;
  options: AuditOptions;
}

/** Writes `event` (attributed to the admin user on the request) after the handler succeeds. Needs `AuditInterceptor`. */
export const Audit = (event: string, options: AuditOptions = {}) =>
  SetMetadata(AUDIT_EVENT_KEY, { event, options } satisfies AuditDescriptor);
