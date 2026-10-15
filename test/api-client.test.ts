import { describe, expect, it } from 'vitest';
import { BastionApiClient, BastionHttp, BastionHttpError } from '../src/core/index.js';

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
    await expect(api.listMyEvents('t', { page: 2, limit: 5 })).resolves.toMatchObject({ page: 2 });
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

    const coded = fakeHttp(() => ({ status: 409, body: { code: 'CONFLICT', message: 'Email taken' } }));
    await expect(coded.http.call('POST', '/x')).rejects.toMatchObject({ code: 'CONFLICT', errors: undefined });

    const inMessage = fakeHttp(() => ({ status: 403, body: { code: 'FORBIDDEN', message: 'UNDER_MINIMUM_AGE' } }));
    await expect(inMessage.http.call('POST', '/x')).rejects.toMatchObject({ code: 'UNDER_MINIMUM_AGE' });

    const unknownCode = fakeHttp(() => ({ status: 401, body: { code: 'UNAUTHORIZED', message: 'Refresh token expired' } }));
    await expect(unknownCode.http.call('POST', '/x')).rejects.toMatchObject({ code: 'INVALID_REFRESH_TOKEN' });
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
    await http.call('GET', '/a', undefined, { headers: { 'X-Request-Id': 'mine' } });
    id = 'bad\r\nid';
    await http.call('GET', '/a');
    expect(calls.map((c) => (c.headers as Record<string, string>)['X-Request-Id'])).toEqual(['req-1', 'mine', undefined]);
  });
});
