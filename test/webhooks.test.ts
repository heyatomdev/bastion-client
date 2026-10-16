import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyWebhookSignature } from '../src/webhooks/index.js';

const body = JSON.stringify({ event: 'user.deleted', userId: 'u1' });
const secret = 'secret-one';
const previous = 'secret-zero';
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

  it('rejects a legacy-only delivery by default (v2 header stripped = replay downgrade)', () => {
    expect(verifyWebhookSignature({ rawBody: body, headers: { 'x-bastion-signature': legacy(secret) }, secrets: secret })).toEqual({ ok: false, reason: 'missing' });
  });

  it('falls back to the legacy body-only signature only when opted in and v2 is absent', () => {
    expect(verifyWebhookSignature({ rawBody: Buffer.from(body), headers: { 'x-bastion-signature': legacy(secret) }, secrets: secret, allowLegacySignature: true })).toEqual({ ok: true, version: 'legacy' });
    expect(verifyWebhookSignature({ rawBody: body, headers: { 'x-bastion-signature': legacy(secret), 'x-bastion-signature-v2': v2(['bad']) }, secrets: secret, allowLegacySignature: true, now: () => now }).ok).toBe(false);
    expect(verifyWebhookSignature({ rawBody: body, headers: {}, secrets: secret })).toEqual({ ok: false, reason: 'missing' });
  });

  it('ignores whitespace-only secrets', () => {
    const headers = { 'x-bastion-signature-v2': v2([secret]) };
    expect(verifyWebhookSignature({ rawBody: body, headers, secrets: [' '], now: () => now })).toEqual({ ok: false, reason: 'missing' });
    expect(verifyWebhookSignature({ rawBody: body, headers, secrets: [' ', secret], now: () => now }).ok).toBe(true);
  });

  // Fixed vector: signStandardWebhook({ id: 'd-1', timestamp: 1_700_000_000, body, secrets: [secret, previous] })
  // from nest-common/src/webhooks, run once with `node --experimental-strip-types`.
  const stdSig1 = 'v1,/FGewLTPxVeBIi/OjqleG6KhFtrmVwa1YfgSNVWjTHs=';
  const stdSig0 = 'v1,hNNunNZVyaMOuQAu2blZSTaa5ZU5S9M93ABBeW3xLhc=';
  const std = (sig = stdSig1) => ({ 'webhook-id': 'd-1', 'webhook-timestamp': '1700000000', 'webhook-signature': sig });
  const ok = { ok: true, version: 'standard', timestamp: 1_700_000_000, deliveryId: 'd-1' };

  describe('Standard Webhooks', () => {
    it('hardcoded vectors match an inline recompute', () => {
      const mac = (s: string) => 'v1,' + createHmac('sha256', s).update(`d-1.1700000000.${body}`).digest('base64');
      expect([mac(secret), mac(previous)]).toEqual([stdSig1, stdSig0]);
    });

    it('accepts the nest-common signed vector', () => {
      expect(verifyWebhookSignature({ rawBody: body, headers: std(), secrets: secret, now: () => now })).toEqual(ok);
      expect(verifyWebhookSignature({ rawBody: Buffer.from(body), headers: { 'Webhook-Id': 'd-1', 'Webhook-Timestamp': '1700000000', 'Webhook-Signature': stdSig1 }, secrets: secret, now: () => now })).toEqual(ok);
    });

    it('accepts any secret against any v1 entry during a rotation', () => {
      const both = std(`${stdSig1} ${stdSig0}`);
      expect(verifyWebhookSignature({ rawBody: body, headers: both, secrets: secret, now: () => now })).toEqual(ok);
      expect(verifyWebhookSignature({ rawBody: body, headers: both, secrets: previous, now: () => now })).toEqual(ok);
      expect(verifyWebhookSignature({ rawBody: body, headers: std(stdSig0), secrets: [secret, previous], now: () => now })).toEqual(ok);
    });

    it('rejects tampered body, wrong secret, stale and malformed', () => {
      expect(verifyWebhookSignature({ rawBody: body + ' ', headers: std(), secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
      expect(verifyWebhookSignature({ rawBody: body, headers: std(), secrets: 'other', now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
      expect(verifyWebhookSignature({ rawBody: body, headers: { ...std(), 'webhook-id': 'd-2' }, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
      expect(verifyWebhookSignature({ rawBody: body, headers: std(), secrets: secret, now: () => now + 600_000 })).toEqual({ ok: false, reason: 'stale' });
      for (const headers of [
        { ...std(), 'webhook-timestamp': '17e8' },
        { ...std(), 'webhook-signature': 'v2,abc' },
        { 'webhook-id': 'd-1', 'webhook-signature': stdSig1 },
        { 'webhook-signature': stdSig1, 'x-bastion-signature-v2': v2([secret]) },
      ]) {
        expect(verifyWebhookSignature({ rawBody: body, headers, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'malformed' });
      }
    });

    it('falls back to v2 when absent, and wins over v2 when both are present', () => {
      expect(verifyWebhookSignature({ rawBody: body, headers: { 'x-bastion-signature-v2': v2([secret], 1_700_000_000, 'v2-id') }, secrets: secret, now: () => now }))
        .toEqual({ ok: true, version: 'v2', timestamp: 1_700_000_000, deliveryId: 'v2-id' });
      expect(verifyWebhookSignature({ rawBody: body, headers: { ...std(), 'x-bastion-signature-v2': v2([secret], 1_700_000_000, 'v2-id') }, secrets: secret, now: () => now })).toEqual(ok);
      expect(verifyWebhookSignature({ rawBody: body, headers: { ...std(), 'x-bastion-signature-v2': v2(['bad']) }, secrets: secret, now: () => now })).toEqual(ok);
      expect(verifyWebhookSignature({ rawBody: body, headers: { ...std(stdSig0), 'x-bastion-signature-v2': v2([secret]) }, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'mismatch' });
    });
  });
});
