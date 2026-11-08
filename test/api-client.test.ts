import { describe, expect, it } from 'vitest';
import { BastionApiClient, BastionHttp, BastionHttpError, ServiceTokenProvider } from '../src/core/index.js';
import { makeIssuer, serviceClaims } from './helpers.js';

function fakeHttp(answers: (path: string, init: RequestInit) => { status: number; body?: unknown }) {
  const calls: { path: string; init: RequestInit }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const path = url.replace('http://bastion', '');
    calls.push({ path, init });
    const a = answers(path, init);
    return { ok: a.status < 400, status: a.status, json: async () => a.body } as Response;
  }) as unknown as typeof fetch;
  return { http: new BastionHttp({ baseUrl: 'http://bastion', fetch: fetchImpl }), calls };
}

describe('BastionApiClient', () => {
  it('pages the user audit trail and reads the profile back as the updated columns', async () => {
    const { http, calls } = fakeHttp((path) =>
      path.startsWith('/auth/me/events') ? { status: 200, body: { data: [], total: 0, page: 2, limit: 5 } } : { status: 200, body: { id: 'u', email: 'a@b.c', username: 'a', image: null, preferredLocale: 'it', emailVerified: true } },
    );
    const api = new BastionApiClient({ http, appSlug: 'x' });
    await expect(api.listMyEvents('t', { page: 2, limit: 5 })).resolves.toMatchObject({ meta: { page: 2 } });
    expect(calls[0].path).toBe('/auth/me/events?page=2&limit=5');
    await expect(api.updateProfile('t', { username: 'a' })).resolves.toMatchObject({ emailVerified: true });
  });

  it('sends appSlug/tenantSlug and forwards the browser context on login', async () => {
    const { http, calls } = fakeHttp(() => ({ status: 200, body: { accessToken: 'a', refreshToken: 'r' } }));
    const api = new BastionApiClient({ http, appSlug: 'dbd-builds', tenantSlug: 'dbd' });

    await api.login('a@b.c', 'pw', { ip: '1.2.3.4', userAgent: 'UA' });

    const { path, init } = calls[0];
    expect(path).toBe('/auth/login');
    expect(JSON.parse(init.body as string)).toEqual({ email: 'a@b.c', password: 'pw', appSlug: 'dbd-builds', tenantSlug: 'dbd' });
    expect(init.headers).toMatchObject({ 'X-Real-IP': '1.2.3.4', 'User-Agent': 'UA' });
  });

  it('sends the flow state on exchange and refuses to exchange without one', async () => {
    const { http, calls } = fakeHttp(() => ({ status: 200, body: { accessToken: 'a', refreshToken: 'r' } }));
    const api = new BastionApiClient({ http, appSlug: 'meridian' });

    await api.exchange('c', undefined, 's');
    await expect(api.exchange('c', undefined, '')).rejects.toThrow('state is required');

    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ code: 'c', appSlug: 'meridian', state: 's' });
  });

  it('oauthStart puts a fresh state on the provider URL, null for an unknown provider', async () => {
    const { http } = fakeHttp(() => ({ status: 200, body: { oauth: [{ provider: 'twitch', authorizeUrl: 'http://bastion/auth/oauth/twitch?appSlug=x' }] } }));
    const api = new BastionApiClient({ http, appSlug: 'x' });

    const a = await api.oauthStart('twitch');
    const b = await api.oauthStart('twitch');
    expect(a!.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a!.state).not.toBe(b!.state);
    expect(new URL(a!.url).searchParams.get('state')).toBe(a!.state);
    expect(new URL(a!.url).searchParams.get('appSlug')).toBe('x');
    await expect(api.oauthStart('google')).resolves.toBeNull();
  });

  it('single-flights concurrent refreshes and logs out the rotated successor', async () => {
    let n = 0;
    const { http, calls } = fakeHttp((path) =>
      path === '/auth/refresh' ? { status: 200, body: { accessToken: `a${++n}`, refreshToken: `r${n}` } } : { status: 204 },
    );
    const api = new BastionApiClient({ http, appSlug: 'x' });

    const [p1, p2] = await Promise.all([api.refresh('r0'), api.refresh('r0')]);
    expect(p1).toBe(p2);
    expect(calls.filter((c) => c.path === '/auth/refresh')).toHaveLength(1);
    await expect(api.refresh('r0')).resolves.toBe(p1); // 60 s memory

    await api.logout('r0');
    const revoked = calls.filter((c) => c.path === '/auth/logout').map((c) => JSON.parse(c.init.body as string).refreshToken).sort();
    expect(revoked).toEqual(['r0', 'r1']);
  });

  it('surfaces a classified BastionHttpError and maps unreachable to UNAVAILABLE', async () => {
    const { http } = fakeHttp(() => ({ status: 401, body: { message: 'No access to this app' } }));
    const api = new BastionApiClient({ http, appSlug: 'x' });
    await expect(api.login('a', 'b')).rejects.toMatchObject({ status: 401, code: 'NO_APP_ACCESS' });

    const down = new BastionHttp({ baseUrl: 'http://bastion', fetch: (async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch });
    await expect(new BastionApiClient({ http: down, appSlug: 'x' }).me('t')).rejects.toMatchObject({ status: 503, code: 'UNAVAILABLE' });
    expect(new BastionHttpError(403, 'Email not verified').code).toBe('EMAIL_NOT_VERIFIED');
    expect(new BastionHttpError(403, 'UNDER_MINIMUM_AGE').code).toBe('UNDER_MINIMUM_AGE');
  });
});

describe('BastionApiClient — 0.4.0 additions', () => {
  it('classifies app/tenant context, refresh token and OAuth code failures, and passes OAUTH_* codes through', () => {
    expect(new BastionHttpError(401, 'Tenant not found for this app').code).toBe('INVALID_APP_CONTEXT');
    expect(new BastionHttpError(400, 'tenantSlug is required for this app').code).toBe('INVALID_APP_CONTEXT');
    expect(new BastionHttpError(401, 'Invalid refresh token').code).toBe('INVALID_REFRESH_TOKEN');
    expect(new BastionHttpError(401, 'Invalid or already used code').code).toBe('INVALID_OAUTH_CODE');
    expect(new BastionHttpError(403, 'OAUTH_EMAIL_UNVERIFIED').code).toBe('OAUTH_EMAIL_UNVERIFIED');
    expect(new BastionHttpError(401, 'Invalid credentials').code).toBe('INVALID_CREDENTIALS');
  });

  it('forwards the browser context on forgotPassword and honours refreshMemoryMs', async () => {
    let n = 0;
    const { http, calls } = fakeHttp((path) =>
      path === '/auth/refresh' ? { status: 200, body: { accessToken: `a${++n}`, refreshToken: `r${n}` } } : { status: 204 },
    );
    const api = new BastionApiClient({ http, appSlug: 'x', refreshMemoryMs: 0 });

    await api.forgotPassword('a@b.c', { ip: '9.9.9.9', userAgent: 'UA' });
    expect(calls[0].init.headers).toMatchObject({ 'X-Real-IP': '9.9.9.9', 'User-Agent': 'UA' });

    await api.refresh('r0');
    await api.refresh('r0'); // memory disabled → second call reaches Bastion
    expect(calls.filter((c) => c.path === '/auth/refresh')).toHaveLength(2);
  });
});

describe('BastionApiClient — 0.5.0 additions', () => {
  it("completes a link with the user's token and surfaces a user mismatch as its OAUTH_ code", async () => {
    const { http, calls } = fakeHttp(() => ({ status: 200, body: { provider: 'discord' } }));
    const api = new BastionApiClient({ http, appSlug: 'x' });

    await expect(api.completeSocialAccountLink('user-token', 'link-code')).resolves.toEqual({ provider: 'discord' });
    expect(calls[0].path).toBe('/auth/me/social-accounts/link/complete');
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ code: 'link-code' });
    expect(calls[0].init.headers).toMatchObject({ Authorization: 'Bearer user-token' });

    await api.completeSocialAccountLink('user-token', 'link-code', { currentPassword: 'pw', twoFactorCode: '123456' });
    expect(JSON.parse(calls[1].init.body as string)).toEqual({ code: 'link-code', currentPassword: 'pw', twoFactorCode: '123456' });

    const refused = fakeHttp(() => ({ status: 403, body: { message: 'OAUTH_LINK_USER_MISMATCH' } }));
    await expect(
      new BastionApiClient({ http: refused.http, appSlug: 'x' }).completeSocialAccountLink('t', 'c'),
    ).rejects.toMatchObject({ status: 403, code: 'OAUTH_LINK_USER_MISMATCH' });
  });
});

describe('BastionApiClient — 0.7.2 additions', () => {
  it('sends the step-up fields with the age screen', async () => {
    const { http, calls } = fakeHttp(() => ({ status: 200, body: { ageVerified: true, isMinor: false } }));
    const api = new BastionApiClient({ http, appSlug: 'x' });

    await api.completeAgeVerification('user-token', '2000-01-31');
    expect(calls[0].path).toBe('/auth/age-verification');
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ birthDate: '2000-01-31' });

    await api.completeAgeVerification('user-token', '2000-01-31', { currentPassword: 'pw', twoFactorCode: '123456' });
    expect(JSON.parse(calls[1].init.body as string)).toEqual({ birthDate: '2000-01-31', currentPassword: 'pw', twoFactorCode: '123456' });
    expect(calls[1].init.headers).toMatchObject({ Authorization: 'Bearer user-token' });
  });
});

describe('BastionHttp — 0.8.0', () => {
  it('keeps the field errors and the code of a 400, in both body shapes', async () => {
    const current = fakeHttp(() => ({ status: 400, body: { statusCode: 400, code: 'VALIDATION_FAILED', message: 'Validation failed', errors: ['email must be an email'] } }));
    await expect(current.http.call('POST', '/x')).rejects.toMatchObject({ status: 400, code: 'VALIDATION_FAILED', message: 'Validation failed', errors: ['email must be an email'] });

    const legacy = fakeHttp(() => ({ status: 400, body: { message: ['a is bad', 'b is bad'], error: 'Bad Request' } }));
    await expect(legacy.http.call('POST', '/x')).rejects.toMatchObject({ code: 'VALIDATION_FAILED', message: 'a is bad, b is bad', errors: ['a is bad', 'b is bad'] });

    const stepUp = fakeHttp(() => ({ status: 401, body: { statusCode: 401, code: 'STEP_UP_FAILED', factor: 'password', message: 'Current password is required' } }));
    await expect(stepUp.http.call('PATCH', '/auth/me/password')).rejects.toMatchObject({ status: 401, code: 'STEP_UP_FAILED', upstreamCode: undefined, factor: 'password' });

    const second = fakeHttp(() => ({ status: 401, body: { code: 'STEP_UP_FAILED', factor: 'second_factor', message: 'Invalid code' } }));
    await expect(second.http.call('PATCH', '/auth/me/password')).rejects.toMatchObject({ factor: 'second_factor' });
    const bogus = fakeHttp(() => ({ status: 401, body: { code: 'STEP_UP_FAILED', factor: 'nope', message: 'x' } }));
    await expect(bogus.http.call('PATCH', '/x')).rejects.toMatchObject({ factor: undefined });

    const twoFa = fakeHttp(() => ({ status: 401, body: { code: 'TWO_FACTOR_CODE_INVALID', message: 'Invalid code' } }));
    await expect(twoFa.http.call('POST', '/auth/2fa/authenticate')).rejects.toMatchObject({ code: 'TWO_FACTOR_CODE_INVALID', upstreamCode: undefined });
    const expired = fakeHttp(() => ({ status: 401, body: { code: 'TWO_FACTOR_CHALLENGE_EXPIRED', message: 'Challenge expired' } }));
    await expect(expired.http.call('POST', '/auth/2fa/authenticate')).rejects.toMatchObject({ code: 'TWO_FACTOR_CHALLENGE_EXPIRED' });

    const coded = fakeHttp(() => ({ status: 409, body: { code: 'CONFLICT', message: 'Email taken' } }));
    await expect(coded.http.call('POST', '/x')).rejects.toMatchObject({ code: 'CONFLICT', errors: undefined });

    const inMessage = fakeHttp(() => ({ status: 403, body: { code: 'FORBIDDEN', message: 'UNDER_MINIMUM_AGE' } }));
    await expect(inMessage.http.call('POST', '/x')).rejects.toMatchObject({ code: 'UNDER_MINIMUM_AGE' });

    const unknownCode = fakeHttp(() => ({ status: 401, body: { code: 'UNAUTHORIZED', message: 'Refresh token expired' } }));
    await expect(unknownCode.http.call('POST', '/x')).rejects.toMatchObject({ code: 'INVALID_REFRESH_TOKEN', upstreamCode: 'UNAUTHORIZED' });
  });

  it('sends the served request id as X-Request-Id, unless malformed or set by the caller', async () => {
    let id: string | undefined = 'req-1';
    const calls: RequestInit[] = [];
    const http = new BastionHttp({
      baseUrl: 'http://bastion',
      requestId: () => id,
      fetch: (async (_: string, init: RequestInit) => (calls.push(init), { ok: true, status: 204 })) as unknown as typeof fetch,
    });
    await http.call('GET', '/a');
    await http.call('GET', '/a', undefined, { headers: { 'x-request-id': 'mine' } });
    id = 'bad\r\nid';
    await http.call('GET', '/a');
    expect(calls.map((c) => (c.headers as Record<string, string>)['X-Request-Id'])).toEqual(['req-1', undefined, undefined]);
    expect((calls[1].headers as Record<string, string>)['x-request-id']).toBe('mine');
  });
});

describe('BastionHttp — 1.0.0, both response shapes', () => {
  const profile = { id: 'u', email: 'a@b.c', username: 'a', image: null, preferredLocale: 'it', emailVerified: true };

  it('unwraps a body whose only key is data, and passes every other shape through', async () => {
    const answer = async (body: unknown) => fakeHttp(() => ({ status: 200, body })).http.call('GET', '/x');
    await expect(answer(profile)).resolves.toEqual(profile);
    await expect(answer({ data: profile })).resolves.toEqual(profile);
    await expect(answer([1, 2])).resolves.toEqual([1, 2]);
    await expect(answer({ data: [1, 2] })).resolves.toEqual([1, 2]);
    const page = { data: [1], meta: { total: 1, page: 1, limit: 20, totalPages: 1 } };
    await expect(answer(page)).resolves.toEqual(page);
    // Bastion before 2.0 pages without `meta`: two keys, not an envelope.
    await expect(answer({ data: [1], total: 1 })).resolves.toEqual({ data: [1], total: 1 });
    await expect(answer({ data: null })).resolves.toBeNull();
    await expect(answer(undefined)).resolves.toBeUndefined();
    // A route that already answers `{ data }` alone and gets enveloped again: one level comes off.
    await expect(answer({ data: { data: [1] } })).resolves.toEqual({ data: [1] });
    await expect(fakeHttp(() => ({ status: 204 })).http.call('DELETE', '/x')).resolves.toBeUndefined();
  });

  it('gives the API client the same result from a bare and an enveloped answer', async () => {
    const pair = { accessToken: 'a', refreshToken: 'r' };
    for (const wrap of [(b: unknown) => b, (b: unknown) => ({ data: b })]) {
      const { http } = fakeHttp((path) => ({ status: 200, body: wrap(path === '/auth/login' ? pair : profile) }));
      const api = new BastionApiClient({ http, appSlug: 'x' });
      await expect(api.login('a@b.c', 'pw')).resolves.toMatchObject(pair);
      await expect(api.updateProfile('t', { username: 'a' })).resolves.toEqual(profile);
    }
  });

  it('reads the service token from an enveloped /auth/client answer', async () => {
    const issuer = await makeIssuer();
    const token = await issuer.sign(serviceClaims, { exp: '1h' });
    const { http } = fakeHttp(() => ({ status: 201, body: { data: { accessToken: token, expiresIn: 3600 } } }));
    const provider = new ServiceTokenProvider(http, { apiKey: 'k', serviceSlug: 'herald' });
    await expect(provider.getToken()).resolves.toBe(token);
  });

  it('pages the audit trail as { data, meta } from both Bastion shapes', async () => {
    const event = { id: 'e', tenantId: 't', userId: 'u', appSlug: 'x', event: 'auth.login', source: 'BASTION', metadata: {}, createdAt: 'now' };
    const legacy = fakeHttp(() => ({ status: 200, body: { data: [event], total: 41, page: 2, limit: 20 } }));
    const current = fakeHttp(() => ({ status: 200, body: { data: [event], meta: { total: 41, page: 2, limit: 20, totalPages: 3 } } }));
    const expected = { data: [event], meta: { total: 41, page: 2, limit: 20, totalPages: 3 } };
    await expect(new BastionApiClient({ http: legacy.http, appSlug: 'x' }).listMyEvents('t')).resolves.toEqual(expected);
    await expect(new BastionApiClient({ http: current.http, appSlug: 'x' }).listMyEvents('t')).resolves.toEqual(expected);
    const empty = fakeHttp(() => ({ status: 200, body: { data: [], total: 0, page: 1, limit: 0 } }));
    await expect(new BastionApiClient({ http: empty.http, appSlug: 'x' }).listMyEvents('t')).resolves.toMatchObject({ meta: { totalPages: 0 } });
    const none = fakeHttp(() => ({ status: 200 }));
    await expect(new BastionApiClient({ http: none.http, appSlug: 'x' }).listMyEvents('t')).resolves.toBeUndefined();
  });

  it("takes Bastion's code over the message, falling back to the message for an older Bastion", async () => {
    const fail = (status: number, body: unknown) => fakeHttp(() => ({ status, body })).http.call('POST', '/x');
    // Bastion >= 1.11: the code is in `code`, the message unchanged.
    await expect(fail(401, { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials' })).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS', upstreamCode: undefined });
    await expect(fail(409, { code: 'PROVIDER_TAKEN', message: 'PROVIDER_TAKEN' })).rejects.toMatchObject({ code: 'PROVIDER_TAKEN', upstreamCode: undefined });
    await expect(fail(400, { code: 'CURRENT_PASSWORD_REQUIRED', message: 'CURRENT_PASSWORD_REQUIRED' })).rejects.toMatchObject({ code: 'CURRENT_PASSWORD_REQUIRED' });
    // A cleaned-up message (Bastion 2.1) still classifies through its code.
    await expect(fail(403, { code: 'OAUTH_EMAIL_UNVERIFIED', message: 'Verify your email first' })).rejects.toMatchObject({ code: 'OAUTH_EMAIL_UNVERIFIED', message: 'Verify your email first' });
    // Older Bastion: the code only in the message, the generic status code in `code`.
    await expect(fail(409, { code: 'CONFLICT', message: 'ALREADY_LINKED' })).rejects.toMatchObject({ code: 'ALREADY_LINKED' });
    await expect(fail(400, { code: 'BAD_REQUEST', message: 'TWO_FACTOR_CODE_REQUIRED' })).rejects.toMatchObject({ code: 'TWO_FACTOR_CODE_REQUIRED' });
    // Two different codes (not sent by Bastion): the message wins, as the rule says.
    await expect(fail(401, { code: 'STEP_UP_FAILED', message: 'INVALID_CREDENTIALS' })).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    // A domain code outside the enum stays on upstreamCode.
    await expect(fail(409, { code: 'HAS_SOCIAL_ACCOUNTS', message: 'User has social accounts' })).rejects.toMatchObject({ code: 'CONFLICT', upstreamCode: 'HAS_SOCIAL_ACCOUNTS' });
  });
});
