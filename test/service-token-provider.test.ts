import { describe, expect, it } from 'vitest';
import { BastionHttp, ServiceTokenProvider } from '../src/core/index.js';
import { makeIssuer, serviceClaims } from './helpers.js';

function httpStub(mint: () => Promise<string>) {
  const calls = { count: 0 };
  const http = {
    clientAuth: async () => {
      calls.count += 1;
      return { accessToken: await mint() };
    },
  } as unknown as BastionHttp;
  return { http, calls };
}

describe('ServiceTokenProvider', () => {
  it('single-flights concurrent first calls into one clientAuth', async () => {
    const issuer = await makeIssuer();
    const { http, calls } = httpStub(() => issuer.sign(serviceClaims, { exp: '1h' }));
    const provider = new ServiceTokenProvider(http, { apiKey: 'k', serviceSlug: 'herald' });

    const tokens = await Promise.all([provider.getToken(), provider.getToken(), provider.getToken()]);

    expect(calls.count).toBe(1);
    expect(new Set(tokens).size).toBe(1);
    expect(provider.tenantId).toBe('t-1');
  });

  it('renews inside the 5-minute margin before exp', async () => {
    const issuer = await makeIssuer();
    const { http, calls } = httpStub(() => issuer.sign(serviceClaims, { exp: '4m' }));
    const provider = new ServiceTokenProvider(http, { apiKey: 'k', serviceSlug: 'herald' });

    await provider.getToken();
    await provider.getToken();

    expect(calls.count).toBe(2);
  });
});

describe('ServiceTokenProvider — several credentials', () => {
  it('mints per serviceSlug and serves the stale token when a re-mint fails', async () => {
    const issuer = await makeIssuer();
    let fail = false;
    const calls: string[] = [];
    const http = {
      clientAuth: async (input: { serviceSlug: string }) => {
        calls.push(input.serviceSlug);
        if (fail) throw new Error('down');
        return { accessToken: await issuer.sign({ ...serviceClaims, serviceSlug: input.serviceSlug }, { exp: '4m' }) };
      },
    } as unknown as BastionHttp;
    const provider = new ServiceTokenProvider(http, {
      'dbd-builds': { apiKey: 'k1', serviceSlug: 'dbd-builds' },
      articuno: { apiKey: 'k2', serviceSlug: 'articuno' },
    });

    const own = await provider.getToken();
    const art = await provider.getToken('articuno');
    expect(own).not.toBe(art);
    expect(calls).toEqual(['dbd-builds', 'articuno']);
    expect(provider.tenantId).toBe('t-1');

    fail = true; // inside the 5-minute margin → re-mint attempted → fails → stale served
    await expect(provider.getToken('articuno')).resolves.toBe(art);
    await expect(provider.getToken('beacon')).rejects.toThrow('not configured');
  });
});

describe('ServiceTokenProvider — lazy resolver', () => {
  it('asks the resolver per slug and uses defaultSlug when none is given', async () => {
    const issuer = await makeIssuer();
    const seen: string[] = [];
    const http = {
      clientAuth: async (input: { serviceSlug: string }) => ({ accessToken: await issuer.sign({ ...serviceClaims, serviceSlug: input.serviceSlug }, { exp: '1h' }) }),
    } as unknown as BastionHttp;
    const provider = new ServiceTokenProvider(http, {
      defaultSlug: 'dbd-builds',
      resolve: (slug) => {
        seen.push(slug);
        return slug === 'beacon' ? null : { apiKey: `k-${slug}`, serviceSlug: slug };
      },
    });

    await provider.getToken();
    await provider.getToken('articuno');
    await expect(provider.getToken('beacon')).rejects.toThrow('not configured');
    expect(seen).toEqual(['dbd-builds', 'articuno', 'beacon']);
  });
});
