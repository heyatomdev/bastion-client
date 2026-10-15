import { createHmac, generateKeyPairSync } from 'node:crypto';
import { importRs256Jwk, verifyRs256 } from '../src/core/jwt.js';
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

  it('rejects alg none / HS256 tokens, a tampered payload, a future nbf and a short RSA key', async () => {
    const issuer = await makeIssuer();
    const { fetchImpl } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fetchImpl });
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const claims = { ...serviceClaims, iss: 'bastion', exp: Math.floor(Date.now() / 1000) + 600 };

    await expect(verifier.verify(`${b64({ alg: 'none', kid: 'kid-1' })}.${b64(claims)}.`)).rejects.toMatchObject({ code: 'invalid' });
    const hsInput = `${b64({ alg: 'HS256', kid: 'kid-1' })}.${b64(claims)}`;
    const hsSig = createHmac('sha256', JSON.stringify(issuer.jwk)).update(hsInput).digest('base64url');
    await expect(verifier.verify(`${hsInput}.${hsSig}`)).rejects.toMatchObject({ code: 'invalid' });

    const [h, , sig] = (await issuer.sign(serviceClaims)).split('.');
    await expect(verifier.verify(`${h}.${b64({ ...claims, scopes: ['*'] })}.${sig}`)).rejects.toMatchObject({ code: 'invalid' });
    await expect(verifier.verify(await issuer.sign({ ...serviceClaims, nbf: Math.floor(Date.now() / 1000) + 600 }))).rejects.toMatchObject({ code: 'invalid' });

    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weak = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fakeJwksFetch(() => ({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'kid-1' }] })).fetchImpl });
    await expect(weak.verify(await issuer.sign(serviceClaims))).rejects.toMatchObject({ code: 'unknown_kid' });
  });

  it('skips the issuer check only when issuer is null', async () => {
    const issuer = await makeIssuer();
    const { fetchImpl } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const token = await issuer.sign(serviceClaims, { iss: null });

    await expect(new JwksVerifier({ baseUrl: 'http://b', fetch: fetchImpl }).verify(token)).rejects.toMatchObject({ code: 'invalid' });
    await expect(new JwksVerifier({ baseUrl: 'http://b', fetch: fetchImpl, issuer: null }).verify(token)).resolves.toBeDefined();
  });
});

describe('jwt helpers', () => {
  it('rejects a crit header, padded or junk-laden segments, and skips non-RSA or enc keys', async () => {
    const issuer = await makeIssuer();
    const { fetchImpl } = fakeJwksFetch(() => ({ keys: [issuer.jwk] }));
    const verifier = new JwksVerifier({ baseUrl: 'http://bastion', fetch: fetchImpl });
    const token = await issuer.sign(serviceClaims);
    await expect(verifier.verify(token)).resolves.toBeTruthy();
    await expect(verifier.verify(`${token}==`)).rejects.toMatchObject({ code: 'malformed' });
    await expect(verifier.verify(`${token}!`)).rejects.toMatchObject({ code: 'malformed' });

    const key = importRs256Jwk(issuer.jwk as JsonWebKey);
    const [, p, s] = token.split('.');
    const critHeader = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'kid-1', crit: ['b64'] })).toString('base64url');
    expect(() => verifyRs256(`${critHeader}.${p}.${s}`, key, 'bastion')).toThrow('crit');

    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    expect(() => importRs256Jwk(ec)).toThrow('not an RS256 signing key');
    expect(() => importRs256Jwk({ ...issuer.jwk, use: 'enc' } as JsonWebKey)).toThrow('not an RS256 signing key');
  });
});
