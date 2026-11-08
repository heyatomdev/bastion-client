import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyWebhookSignature } from '../src/webhooks/index.js';

const body = JSON.stringify({ event: 'user.deleted', userId: 'u1' });
const secret = 'secret-one';
const previous = 'secret-zero';
const now = 1_700_000_000_000;

describe('verifyWebhookSignature', () => {
  it('rejects the retired V2 and legacy signatures: no Standard Webhooks headers = missing', () => {
    const t = 1_700_000_000;
    const v2 = `t=${t},id=d-1,v1=` + createHmac('sha256', secret).update(`${t}.d-1.${body}`).digest('hex');
    const legacy = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
    for (const headers of [{ 'x-bastion-signature-v2': v2 }, { 'x-bastion-signature': legacy }, {}]) {
      expect(verifyWebhookSignature({ rawBody: body, headers, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'missing' });
    }
  });

  it('ignores a V2 header next to Standard Webhooks ones', () => {
    expect(verifyWebhookSignature({ rawBody: body, headers: { ...std(), 'x-bastion-signature-v2': 't=1,id=x,v1=00' }, secrets: secret, now: () => now })).toEqual(ok);
  });

  it('ignores whitespace-only secrets', () => {
    expect(verifyWebhookSignature({ rawBody: body, headers: std(), secrets: [' '], now: () => now })).toEqual({ ok: false, reason: 'missing' });
    expect(verifyWebhookSignature({ rawBody: body, headers: std(), secrets: [' ', secret], now: () => now }).ok).toBe(true);
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
        { 'webhook-signature': stdSig1 },
      ]) {
        expect(verifyWebhookSignature({ rawBody: body, headers, secrets: secret, now: () => now })).toEqual({ ok: false, reason: 'malformed' });
      }
    });
  });
});
