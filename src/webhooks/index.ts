import { createHmac, timingSafeEqual } from 'node:crypto';

/** Headers Bastion sends with every delivery. Lower-case, as Node exposes them. */
export const BASTION_SIGNATURE_HEADER = 'x-bastion-signature';
export const BASTION_SIGNATURE_V2_HEADER = 'x-bastion-signature-v2';
export const BASTION_EVENT_HEADER = 'x-bastion-event';
export const BASTION_DELIVERY_ID_HEADER = 'x-bastion-delivery-id';
/** Standard Webhooks (standardwebhooks.com) headers, sent alongside v2 during the migration. */
export const WEBHOOK_ID_HEADER = 'webhook-id';
export const WEBHOOK_TIMESTAMP_HEADER = 'webhook-timestamp';
export const WEBHOOK_SIGNATURE_HEADER = 'webhook-signature';

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
  /**
   * Accept the legacy body-only `X-Bastion-Signature` when v2 is absent.
   * Default `false`: legacy carries no timestamp or delivery id, so accepting
   * it lets anyone holding an old delivery replay it by stripping the v2
   * header. Bastion no longer sends the legacy header, so there is nothing
   * left to migrate: leave it off.
   */
  allowLegacySignature?: boolean;
  /** Max distance of the signed timestamp from now (Standard Webhooks and v2), default 300 s. */
  toleranceSeconds?: number;
  /** For tests. */
  now?: () => number;
}

export type VerifyWebhookResult =
  | { ok: true; version: 'standard'; timestamp: number; deliveryId: string }
  | { ok: true; version: 'v2'; timestamp: number; deliveryId: string }
  | { ok: true; version: 'legacy' }
  | { ok: false; reason: 'missing' | 'malformed' | 'stale' | 'mismatch' };

function header(headers: VerifyWebhookOptions['headers'], name: string): string | undefined {
  let v = headers[name];
  if (v === undefined) {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
    v = key === undefined ? undefined : headers[key];
  }
  return Array.isArray(v) ? v[0] : v;
}

function macEquals(hexA: string, hexB: string): boolean {
  const a = Buffer.from(hexA, 'hex');
  const b = Buffer.from(hexB, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

function isFresh(timestamp: number, options: VerifyWebhookOptions): boolean {
  const now = Math.floor((options.now ?? Date.now)() / 1000);
  return Math.abs(now - timestamp) <= (options.toleranceSeconds ?? 300);
}

/**
 * Verifies a Bastion delivery. Prefers Standard Webhooks when any of `webhook-id`,
 * `webhook-timestamp`, `webhook-signature` is present: `webhook-signature` is a
 * space-separated list of `v1,<base64 HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>`,
 * keyed with the secret as UTF-8 (not a `whsec_` base64 key); `deliveryId` is `webhook-id`.
 * Otherwise falls back to `X-Bastion-Signature-V2`
 * (`t=<unix>,id=<deliveryId>,v1=<hex>[,v1=<hex>]`, MAC over `"<t>.<id>.<body>"`),
 * which binds the timestamp and the delivery id so a stale or replayed
 * delivery is rejected without trusting any unsigned header. The legacy
 * `X-Bastion-Signature: sha256=<hex>` over the body alone is accepted only
 * when both of the above are absent **and** `allowLegacySignature` is set. Any of the caller's
 * `secrets` matching any `v1` entry accepts:
 * that is how a secret rotation stays zero-downtime on both sides.
 */
export function verifyWebhookSignature(options: VerifyWebhookOptions): VerifyWebhookResult {
  const body = typeof options.rawBody === 'string' ? Buffer.from(options.rawBody, 'utf8') : options.rawBody;
  const secrets = (Array.isArray(options.secrets) ? options.secrets : [options.secrets]).filter(
    // A whitespace-only secret is a misconfiguration, never a key; the rest are used byte-exact.
    (s) => typeof s === 'string' && s.trim() !== '',
  );
  if (secrets.length === 0) return { ok: false, reason: 'missing' };

  const stdId = header(options.headers, WEBHOOK_ID_HEADER);
  const stdTs = header(options.headers, WEBHOOK_TIMESTAMP_HEADER);
  const stdSig = header(options.headers, WEBHOOK_SIGNATURE_HEADER);
  if (stdId || stdTs || stdSig) {
    const macs = (stdSig ?? '')
      .split(' ')
      .map((entry) => entry.split(','))
      .filter(([version, value]) => version === 'v1' && value)
      .map(([, value]) => Buffer.from(value, 'base64'));
    if (!stdId || !stdTs || !/^\d+$/.test(stdTs) || macs.length === 0) return { ok: false, reason: 'malformed' };
    const timestamp = Number(stdTs);
    if (!isFresh(timestamp, options)) return { ok: false, reason: 'stale' };

    const signed = Buffer.concat([Buffer.from(`${stdId}.${stdTs}.`, 'utf8'), body]);
    for (const secret of secrets) {
      const expected = createHmac('sha256', secret).update(signed).digest();
      if (macs.some((mac) => mac.length === expected.length && timingSafeEqual(mac, expected))) {
        return { ok: true, version: 'standard', timestamp, deliveryId: stdId };
      }
    }
    return { ok: false, reason: 'mismatch' };
  }

  const v2 = header(options.headers, BASTION_SIGNATURE_V2_HEADER);
  if (v2) {
    const parts = v2.split(',').map((p) => p.trim());
    const t = parts.find((p) => p.startsWith('t='))?.slice(2);
    const id = parts.find((p) => p.startsWith('id='))?.slice(3);
    const macs = parts.filter((p) => p.startsWith('v1=')).map((p) => p.slice(3));
    const timestamp = Number(t);
    if (!t || !id || macs.length === 0 || !Number.isFinite(timestamp)) return { ok: false, reason: 'malformed' };

    if (!isFresh(timestamp, options)) return { ok: false, reason: 'stale' };

    const signed = Buffer.concat([Buffer.from(`${timestamp}.${id}.`, 'utf8'), body]);
    for (const secret of secrets) {
      const expected = createHmac('sha256', secret).update(signed).digest('hex');
      if (macs.some((mac) => macEquals(mac, expected))) return { ok: true, version: 'v2', timestamp, deliveryId: id };
    }
    return { ok: false, reason: 'mismatch' };
  }

  if (!options.allowLegacySignature) return { ok: false, reason: 'missing' };
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
