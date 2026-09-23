import { createHmac, timingSafeEqual } from 'node:crypto';

/** Headers Bastion sends with every delivery. Lower-case, as Node exposes them. */
export const BASTION_SIGNATURE_HEADER = 'x-bastion-signature';
export const BASTION_SIGNATURE_V2_HEADER = 'x-bastion-signature-v2';
export const BASTION_EVENT_HEADER = 'x-bastion-event';
export const BASTION_DELIVERY_ID_HEADER = 'x-bastion-delivery-id';

/** Sent to every app with a webhook URL, whether or not the user has a role in it. */
export const BASTION_LIFECYCLE_EVENTS = ['user.deleted', 'user.expired_unverified', 'user.deactivated'] as const;

export interface BastionWebhookPayload {
  event: string;
  tenantSlug?: string;
  userId?: string;
  timestamp?: string;
  /** `auth.email_changed` */
  newEmail?: string;
  /** `auth.email_verified` */
  email?: string;
  /** `user.deleted` from the age gate carries `under_minimum_age`; absent otherwise. */
  reason?: string;
  [key: string]: unknown;
}

export interface VerifyWebhookOptions {
  /** The request body exactly as received — never a re-serialized object. */
  rawBody: Buffer | string;
  /** Request headers (any case). */
  headers: Record<string, string | string[] | undefined>;
  /** Your webhook secret, plus the previous one during a rotation. */
  secrets: string | string[];
  /** Max age of `t` on a v2 signature, default 300 s. */
  toleranceSeconds?: number;
  /** For tests. */
  now?: () => number;
}

export type VerifyWebhookResult =
  | { ok: true; version: 'v2'; timestamp: number; deliveryId: string }
  | { ok: true; version: 'legacy' }
  | { ok: false; reason: 'missing' | 'malformed' | 'stale' | 'mismatch' };

function header(headers: VerifyWebhookOptions['headers'], name: string): string | undefined {
  const direct = headers[name] ?? headers[name.toLowerCase()];
  if (direct !== undefined) return Array.isArray(direct) ? direct[0] : direct;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  const v = key ? headers[key] : undefined;
  return Array.isArray(v) ? v[0] : v;
}

function macEquals(hexA: string, hexB: string): boolean {
  const a = Buffer.from(hexA, 'hex');
  const b = Buffer.from(hexB, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

/**
 * Verifies a Bastion delivery. Prefers `X-Bastion-Signature-V2`
 * (`t=<unix>,id=<deliveryId>,v1=<hex>[,v1=<hex>]`, MAC over `"<t>.<id>.<body>"`),
 * which binds the timestamp and the delivery id so a stale or replayed
 * delivery is rejected without trusting any unsigned header; falls back to
 * the legacy `X-Bastion-Signature: sha256=<hex>` over the body alone only when
 * v2 is absent. Any of the caller's `secrets` matching any `v1=` accepts:
 * that is how a secret rotation stays zero-downtime on both sides.
 */
export function verifyWebhookSignature(options: VerifyWebhookOptions): VerifyWebhookResult {
  const body = typeof options.rawBody === 'string' ? Buffer.from(options.rawBody, 'utf8') : options.rawBody;
  const secrets = (Array.isArray(options.secrets) ? options.secrets : [options.secrets]).filter(Boolean);
  if (secrets.length === 0) return { ok: false, reason: 'missing' };

  const v2 = header(options.headers, BASTION_SIGNATURE_V2_HEADER);
  if (v2) {
    const parts = v2.split(',').map((p) => p.trim());
    const t = parts.find((p) => p.startsWith('t='))?.slice(2);
    const id = parts.find((p) => p.startsWith('id='))?.slice(3);
    const macs = parts.filter((p) => p.startsWith('v1=')).map((p) => p.slice(3));
    const timestamp = Number(t);
    if (!t || !id || macs.length === 0 || !Number.isFinite(timestamp)) return { ok: false, reason: 'malformed' };

    const now = Math.floor((options.now ?? Date.now)() / 1000);
    if (Math.abs(now - timestamp) > (options.toleranceSeconds ?? 300)) return { ok: false, reason: 'stale' };

    const signed = Buffer.concat([Buffer.from(`${timestamp}.${id}.`, 'utf8'), body]);
    for (const secret of secrets) {
      const expected = createHmac('sha256', secret).update(signed).digest('hex');
      if (macs.some((mac) => macEquals(mac, expected))) return { ok: true, version: 'v2', timestamp, deliveryId: id };
    }
    return { ok: false, reason: 'mismatch' };
  }

  const legacy = header(options.headers, BASTION_SIGNATURE_HEADER);
  if (!legacy) return { ok: false, reason: 'missing' };
  if (!legacy.startsWith('sha256=')) return { ok: false, reason: 'malformed' };
  const provided = legacy.slice('sha256='.length).trim();
  for (const secret of secrets) {
    const expected = createHmac('sha256', secret).update(body).digest('hex');
    if (macEquals(provided, expected)) return { ok: true, version: 'legacy' };
  }
  return { ok: false, reason: 'mismatch' };
}
