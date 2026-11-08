import { createHmac, timingSafeEqual } from 'node:crypto';

/** Headers Bastion sends with every delivery. Lower-case, as Node exposes them. */
export const BASTION_EVENT_HEADER = 'x-bastion-event';
export const BASTION_DELIVERY_ID_HEADER = 'x-bastion-delivery-id';
/** Standard Webhooks (standardwebhooks.com) headers. */
export const WEBHOOK_ID_HEADER = 'webhook-id';
export const WEBHOOK_TIMESTAMP_HEADER = 'webhook-timestamp';
export const WEBHOOK_SIGNATURE_HEADER = 'webhook-signature';

/** Fields every delivery body carries. `id` is the delivery id, equal to the `webhook-id` header. */
interface BastionWebhookBase<E extends string> {
  id: string;
  event: E;
  tenantSlug: string;
  userId: string;
  /** ISO 8601. */
  timestamp: string;
}

/**
 * Every event Bastion sends, discriminated on `event`: `switch (payload.event)` narrows the
 * extra fields. Parse the verified body as this type and keep a `default` branch, since a newer
 * Bastion may send events this version does not list.
 */
export type BastionWebhookEvent =
  | (BastionWebhookBase<'user.deleted'> & {
      /** Only on a deletion by the age gate; absent on an ordinary erasure. */
      reason?: 'under_minimum_age';
    })
  | BastionWebhookBase<'user.deactivated'>
  | BastionWebhookBase<'user.expired_unverified'>
  | (BastionWebhookBase<'user.role_changed'> & { appSlug: string; oldRole: string; newRole: string })
  | (BastionWebhookBase<'auth.email_verified'> & { email: string })
  | (BastionWebhookBase<'auth.email_changed'> & { newEmail: string })
  | (BastionWebhookBase<'auth.oauth_linked'> & {
      /** Lowercase: `discord`, `google`, `twitch`, … */
      provider: string;
      avatarUrl: string | null;
    })
  | (BastionWebhookBase<'auth.oauth_unlinked'> & { provider: string })
  | BastionWebhookBase<'auth.2fa_enabled'>
  | (BastionWebhookBase<'auth.2fa_disabled'> & { initiator: 'self' | 'admin' });

export type BastionWebhookEventName = BastionWebhookEvent['event'];

/** Sent to every app with a webhook URL, whether or not the user has a role in it. */
export const BASTION_LIFECYCLE_EVENTS = [
  'user.deleted',
  'user.expired_unverified',
  'user.deactivated',
] as const satisfies readonly BastionWebhookEventName[];

/** Loose shape of a delivery body. Prefer `BastionWebhookEvent`, which narrows on `event`. */
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
  /** Max distance of the signed timestamp from now, default 300 s. */
  toleranceSeconds?: number;
  /** For tests. */
  now?: () => number;
}

export type VerifyWebhookResult =
  | { ok: true; version: 'standard'; timestamp: number; deliveryId: string }
  | { ok: false; reason: 'missing' | 'malformed' | 'stale' | 'mismatch' };

function header(headers: VerifyWebhookOptions['headers'], name: string): string | undefined {
  let v = headers[name];
  if (v === undefined) {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
    v = key === undefined ? undefined : headers[key];
  }
  return Array.isArray(v) ? v[0] : v;
}

function isFresh(timestamp: number, options: VerifyWebhookOptions): boolean {
  const now = Math.floor((options.now ?? Date.now)() / 1000);
  return Math.abs(now - timestamp) <= (options.toleranceSeconds ?? 300);
}

/**
 * Verifies a Bastion delivery against its [Standard Webhooks](https://www.standardwebhooks.com/)
 * headers: `webhook-signature` is a space-separated list of
 * `v1,<base64 HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>`, keyed with the secret as UTF-8
 * (not a `whsec_` base64 key); `deliveryId` is `webhook-id`. A stale timestamp is rejected.
 * Any of the caller's `secrets` matching any `v1` entry accepts: that is how a secret rotation
 * stays zero-downtime on both sides. A delivery without these headers (the retired
 * `X-Bastion-Signature` / `-V2`) is `missing`.
 */
export function verifyWebhookSignature(options: VerifyWebhookOptions): VerifyWebhookResult {
  const body = typeof options.rawBody === 'string' ? Buffer.from(options.rawBody, 'utf8') : options.rawBody;
  const secrets = (Array.isArray(options.secrets) ? options.secrets : [options.secrets]).filter(
    // A whitespace-only secret is a misconfiguration, never a key; the rest are used byte-exact.
    (s) => typeof s === 'string' && s.trim() !== '',
  );
  if (secrets.length === 0) return { ok: false, reason: 'missing' };

  const id = header(options.headers, WEBHOOK_ID_HEADER);
  const ts = header(options.headers, WEBHOOK_TIMESTAMP_HEADER);
  const sig = header(options.headers, WEBHOOK_SIGNATURE_HEADER);
  if (!id && !ts && !sig) return { ok: false, reason: 'missing' };

  const macs = (sig ?? '')
    .split(' ')
    .map((entry) => entry.split(','))
    .filter(([version, value]) => version === 'v1' && value)
    .map(([, value]) => Buffer.from(value, 'base64'));
  if (!id || !ts || !/^\d+$/.test(ts) || macs.length === 0) return { ok: false, reason: 'malformed' };
  const timestamp = Number(ts);
  if (!isFresh(timestamp, options)) return { ok: false, reason: 'stale' };

  const signed = Buffer.concat([Buffer.from(`${id}.${ts}.`, 'utf8'), body]);
  for (const secret of secrets) {
    const expected = createHmac('sha256', secret).update(signed).digest();
    if (macs.some((mac) => mac.length === expected.length && timingSafeEqual(mac, expected))) {
      return { ok: true, version: 'standard', timestamp, deliveryId: id };
    }
  }
  return { ok: false, reason: 'mismatch' };
}
