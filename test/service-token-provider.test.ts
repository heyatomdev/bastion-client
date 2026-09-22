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
