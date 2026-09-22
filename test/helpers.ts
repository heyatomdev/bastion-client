import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose';

export async function makeIssuer(kid = 'kid-1') {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const sign = (claims: Record<string, unknown>, opts: { kid?: string; iss?: string | null; exp?: string } = {}) => {
    let jwt = new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: opts.kid ?? kid })
      .setIssuedAt()
      .setExpirationTime(opts.exp ?? '15m');
    if (opts.iss !== null) jwt = jwt.setIssuer(opts.iss ?? 'bastion');
    return jwt.sign(privateKey as CryptoKey);
  };
  return { jwk, sign };
}

/** A `fetch` stub serving a JWKS; call count exposed for cache assertions. */
export function fakeJwksFetch(jwks: () => unknown, status = 200) {
  const calls = { count: 0 };
  const fetchImpl = (async () => {
    calls.count += 1;
    return { ok: status < 400, status, json: async () => jwks() } as Response;
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

export const serviceClaims = {
  sub: 'client-1',
  type: 'service_client',
  tenantId: 't-1',
  tenantSlug: 'dbd',
  clientName: 'herald-prod',
  serviceSlug: 'herald',
  scopes: ['mail.send'],
};

export const userClaims = {
  sub: 'user-1',
  tenantId: 't-1',
  tenantSlug: 'dbd',
  email: 'a@b.c',
  username: 'a',
  image: null,
  preferredLocale: 'it',
  appSlug: 'meridian',
  role: 'ADMIN',
  permissions: [],
};
