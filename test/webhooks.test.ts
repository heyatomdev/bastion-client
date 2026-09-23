import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyWebhookSignature } from '../src/webhooks/index.js';

const body = JSON.stringify({ event: 'user.deleted', userId: 'u1' });
const secret = 'whsec_one';
const previous = 'whsec_zero';
const now = 1_700_000_000_000;
const v2 = (secrets: string[], t = 1_700_000_000, id = 'd-1') =>
  [`t=${t}`, `id=${id}`, ...secrets.map((s) => 'v1=' + createHmac('sha256', s).update(`${t}.${id}.${body}`).digest('hex'))].join(',');
const legacy = (s: string) => 'sha256=' + createHmac('sha256', s).update(body).digest('hex');

describe('verifyWebhookSignature', () => {
  it('accepts a v2 signature and returns timestamp and delivery id', () => {
    expect(verifyWebhookSignature({ rawBody: body, headers: { 'X-Bastion-Signature-V2': v2([secret]) }, secrets: secret, now: () => now }))
      .toEqual({ ok: true, version: 'v2', timestamp: 1_700_000_000, deliveryId: 'd-1' });
  });

  it('accepts either secret during a rotation, on both sides', () => {
    const rotatedByBastion = { 'x-bastion-signature-v2': v2([secret, previous]) };
    expect(verifyWebhookSignature({ rawBody: body, headers: rotatedByBastion, secrets: previous, now: () => now }).ok).toBe(true);
    const rotatedByConsumer = { 'x-bastion-signature-v2': v2([previous]) };
    expect(verifyWebhookSignature({ rawBody: body, headers: rotatedByConsumer, secrets: [secret, previous], now: () => now }).ok).toBe(true);
  });

  it('rejects stale, tampered and wrong-secret v2 deliveries, and a body that changed', () => {
    const h = { 'x-bastion-signature-v2': v2([secret]) };
    expect(verifyWebhookSignature({ rawBody: body, headers: h, secrets: secret, now: () => now + 600_000 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyWebhookSignature({ rawBody: body, headers: h, secrets: 'other', now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
    expect(verifyWebhookSignature({ rawBody: body + ' ', headers: h, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
    expect(verifyWebhookSignature({ rawBody: body, headers: { 'x-bastion-signature-v2': 't=1,v1=zz' }, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('falls back to the legacy body-only signature only when v2 is absent', () => {
    expect(verifyWebhookSignature({ rawBody: Buffer.from(body), headers: { 'x-bastion-signature': legacy(secret) }, secrets: secret })).toEqual({ ok: true, version: 'legacy' });
    expect(verifyWebhookSignature({ rawBody: body, headers: { 'x-bastion-signature': legacy(secret), 'x-bastion-signature-v2': v2(['bad']) }, secrets: secret, now: () => now }).ok).toBe(false);
    expect(verifyWebhookSignature({ rawBody: body, headers: {}, secrets: secret })).toEqual({ ok: false, reason: 'missing' });
  });
});
