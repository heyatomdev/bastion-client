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
