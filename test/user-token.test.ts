import { describe, expect, it } from 'vitest';
import { assertUserTokenFor, type BastionJwtPayload } from '../src/core/index.js';
import { serviceClaims, userClaims } from './helpers.js';

const user = { ...userClaims, appSlug: 'dbd-builds', aud: 'dbd-builds', iat: 0, exp: 0 } as BastionJwtPayload;

describe('assertUserTokenFor', () => {
  it('returns the payload for a user token minted for this app', () => {
    expect(assertUserTokenFor(user, 'dbd-builds').sub).toBe('user-1');
  });

  it('rejects a machine token regardless of scopes', () => {
    const machine = { ...serviceClaims, iat: 0, exp: 0 } as BastionJwtPayload;
    expect(() => assertUserTokenFor(machine, 'dbd-builds')).toThrow(expect.objectContaining({ code: 'not_user_token' }));
  });

  it('rejects a user token for another app, on aud or on appSlug', () => {
    expect(() => assertUserTokenFor({ ...user, aud: 'meridian' } as BastionJwtPayload, 'dbd-builds')).toThrow(expect.objectContaining({ code: 'wrong_app' }));
    expect(() => assertUserTokenFor({ ...user, appSlug: 'meridian' } as BastionJwtPayload, 'dbd-builds')).toThrow(expect.objectContaining({ code: 'wrong_app' }));
    expect(() => assertUserTokenFor({ ...user, sub: '' } as BastionJwtPayload, 'dbd-builds')).toThrow(expect.objectContaining({ code: 'wrong_app' }));
  });
});
