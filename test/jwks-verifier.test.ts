import { describe, expect, it } from 'vitest';
import { BastionTokenError, JwksVerifier } from '../src/core/index.js';
import { fakeJwksFetch, makeIssuer, serviceClaims } from './helpers.js';

describe('JwksVerifier', () => {
  it('verifies a token and caches the key set across calls', async () => {
    const issuer = await makeIssuer();
    const { fetchImpl, calls } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion/', fetch: fetchImpl });

    const token = await issuer.sign(serviceClaims);
    const payload = await verifier.verify(token);
    await verifier.verify(token);

    expect(payload.sub).toBe('client-1');
    expect(payload.type).toBe('service_client');
    expect(calls.count).toBe(1);
  });

  it('refetches once on an unknown kid, then honours the cooldown', async () => {
    const old = await makeIssuer('kid-old');
    const fresh = await makeIssuer('kid-new');
    let published = [old.jwk];
    const { fetchImpl, calls } = fakeJwksFetch(() => ({ keys: published }));
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fetchImpl });

    await verifier.verify(await old.sign(serviceClaims));
    published = [old.jwk, fresh.jwk];
    await verifier.verify(await fresh.sign(serviceClaims)); // unknown kid → refetch
    expect(calls.count).toBe(2);

    const unknown = await (await makeIssuer('kid-ghost')).sign(serviceClaims);
    await expect(verifier.verify(unknown)).rejects.toMatchObject({ code: 'unknown_kid' });
    expect(calls.count).toBe(2); // cooldown: no third fetch
  });

  it('serves the stale cache when a refetch fails', async () => {
    const issuer = await makeIssuer();
    let status = 200;
    const calls = { count: 0 };
    const fetchImpl = (async () => {
      calls.count += 1;
      return { ok: status < 400, status, json: async () => ({ keys: [issuer.jwk] }) } as Response;
    }) as unknown as typeof fetch;
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fetchImpl, ttlMs: 0 });

    const token = await issuer.sign(serviceClaims);
    await verifier.verify(token);
    status = 503;
    await expect(verifier.verify(token)).resolves.toMatchObject({ sub: 'client-1' });
  });

  it('rejects a wrong issuer, a bad signature, an expired token and a kid-less header', async () => {
    const issuer = await makeIssuer();
    const other = await makeIssuer('kid-1'); // same kid, different key
    const { fetchImpl } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fetchImpl });

    await expect(verifier.verify(await issuer.sign(serviceClaims, { iss: 'evil' }))).rejects.toMatchObject({ code: 'invalid' });
    await expect(verifier.verify(await other.sign(serviceClaims))).rejects.toMatchObject({ code: 'invalid' });
    await expect(verifier.verify(await issuer.sign(serviceClaims, { exp: '-1m' }))).rejects.toMatchObject({ code: 'invalid' });
    await expect(verifier.verify('not.a.jwt')).rejects.toBeInstanceOf(BastionTokenError);
  });

  it('skips the issuer check only when issuer is null', async () => {
    const issuer = await makeIssuer();
    const { fetchImpl } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const token = await issuer.sign(serviceClaims, { iss: null });

    await expect(new JwksVerifier({ baseUrl: 'http://b', fetch: fetchImpl }).verify(token)).rejects.toMatchObject({ code: 'invalid' });
    await expect(new JwksVerifier({ baseUrl: 'http://b', fetch: fetchImpl, issuer: null }).verify(token)).resolves.toBeDefined();
  });
});
