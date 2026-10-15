import { createPublicKey, verify, type KeyObject } from 'node:crypto';

/** Header and payload of a compact JWS, unverified. Throws on anything that isn't one. */
export function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.');
  // Strict alphabet: Buffer's base64url decoder skips padding and junk, which would let one token have many spellings.
  if (parts.length !== 3 || !parts.every((part) => /^[A-Za-z0-9_-]*$/.test(part))) throw new Error('not a compact JWS');
  const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8')) as unknown;
  const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as unknown;
  if (!isObject(header) || !isObject(payload)) throw new Error('header or payload not an object');
  return { header, payload };
}

/** An RS256 verification key from a JWKS entry; RSA ≥ 2048 bits only. */
export function importRs256Jwk(jwk: JsonWebKey): KeyObject {
  if (jwk.kty !== 'RSA' || (jwk.alg !== undefined && jwk.alg !== 'RS256') || (jwk.use !== undefined && jwk.use !== 'sig')) {
    throw new Error('not an RS256 signing key');
  }
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('RSA key shorter than 2048 bits');
  return key;
}

/**
 * RS256 signature, `exp`/`nbf`, optional `iss`. What `jose.jwtVerify` checked for us,
 * in node:crypto so the CJS build has no ESM-only dependency. Throws on any failure.
 */
export function verifyRs256(token: string, key: KeyObject, issuer: string | null, now = Date.now()): Record<string, unknown> {
  const { header, payload } = decodeJwt(token);
  if (header.alg !== 'RS256') throw new Error('alg not RS256');
  if (header.crit !== undefined) throw new Error('unsupported crit header');
  const [h, p, s] = token.split('.') as [string, string, string];
  if (!verify('RSA-SHA256', Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'))) throw new Error('bad signature');

  const seconds = Math.floor(now / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= seconds) throw new Error('expired');
  if (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || payload.nbf > seconds)) throw new Error('not yet valid');
  if (payload.iat !== undefined && typeof payload.iat !== 'number') throw new Error('bad iat');
  if (issuer && payload.iss !== issuer) throw new Error('wrong issuer');
  return payload;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
