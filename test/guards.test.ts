import 'reflect-metadata';
import { ForbiddenException, RequestMethod, UnauthorizedException, type ExecutionContext, type MiddlewareConsumer } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import { ServiceClientJwtGuard } from '../src/nest/guards/service-client-jwt.guard.js';
import { BastionUserGuard } from '../src/nest/guards/bastion-user.guard.js';
import { AppUserGuard } from '../src/nest/guards/app-user.guard.js';
import { BastionModule } from '../src/nest/bastion.module.js';
import { BastionService } from '../src/nest/bastion.service.js';
import { BastionHttpException } from '../src/nest/bastion-http-exception.js';
import { BastionHttpError } from '../src/core/errors.js';
import { currentRequestId, requestContextMiddleware } from '../src/nest/request-context.js';
import { IS_PUBLIC_KEY, REQUIRED_SCOPES_KEY } from '../src/nest/index.js';
import type { BastionJwksService } from '../src/nest/bastion-jwks.service.js';
import type { BastionAuditService } from '../src/nest/bastion-audit.service.js';
import { serviceClaims, userClaims } from './helpers.js';

function ctx(token: string | undefined, meta: Record<string, unknown> = {}) {
  const handler = () => undefined;
  for (const [k, v] of Object.entries(meta)) Reflect.defineMetadata(k, v, handler);
  const req: Record<string, unknown> = { headers: token ? { authorization: `Bearer ${token}` } : {}, url: '/x' };
  return {
    req,
    ctx: {
      getHandler: () => handler,
      getClass: () => class {},
      switchToHttp: () => ({ getRequest: () => req }),
    } as unknown as ExecutionContext,
  };
}

const jwksReturning = (payload: unknown) =>
  ({ verify: vi.fn(async () => payload) }) as unknown as BastionJwksService;

describe('ServiceClientJwtGuard', () => {
  const options = { baseUrl: 'http://b', serviceSlug: 'herald' };

  it('lets @Public routes through without a token', async () => {
    const guard = new ServiceClientJwtGuard(jwksReturning(null), new Reflector(), options);
    await expect(guard.canActivate(ctx(undefined, { [IS_PUBLIC_KEY]: true }).ctx)).resolves.toBe(true);
  });

  it('accepts a machine token for this service and sets req.user', async () => {
    const guard = new ServiceClientJwtGuard(jwksReturning(serviceClaims), new Reflector(), options);
    const { ctx: c, req } = ctx('t');
    await expect(guard.canActivate(c)).resolves.toBe(true);
    expect(req.user).toMatchObject({ serviceSlug: 'herald' });
  });

  it('rejects a user token, a token for another service, and a missing scope', async () => {
    await expect(new ServiceClientJwtGuard(jwksReturning(userClaims), new Reflector(), options).canActivate(ctx('t').ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(new ServiceClientJwtGuard(jwksReturning(serviceClaims), new Reflector(), { ...options, serviceSlug: 'beacon' }).canActivate(ctx('t').ctx)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(new ServiceClientJwtGuard(jwksReturning(serviceClaims), new Reflector(), options).canActivate(ctx('t', { [REQUIRED_SCOPES_KEY]: ['mail.admin'] }).ctx)).rejects.toThrow('Missing scope: mail.admin');
  });
});

describe('BastionUserGuard', () => {
  const audit = { write: vi.fn(async () => undefined) } as unknown as BastionAuditService;
  const options = { baseUrl: 'http://b', serviceSlug: 'herald' };

  it('accepts a console ADMIN and sets req.adminUser', async () => {
    const guard = new BastionUserGuard(jwksReturning(userClaims), audit, options);
    const { ctx: c, req } = ctx('t');
    await expect(guard.canActivate(c)).resolves.toBe(true);
    expect(req.adminUser).toMatchObject({ sub: 'user-1' });
  });

  it('rejects a machine token, a foreign app, an insufficient role — and audits the denial once per cooldown', async () => {
    const write = vi.fn(async () => undefined);
    const auditSpy = { write } as unknown as BastionAuditService;
    await expect(new BastionUserGuard(jwksReturning(serviceClaims), auditSpy, options).canActivate(ctx('t').ctx)).rejects.toBeInstanceOf(UnauthorizedException);

    const foreign = new BastionUserGuard(jwksReturning({ ...userClaims, appSlug: 'dbd-builds' }), auditSpy, options);
    await expect(foreign.canActivate(ctx('t').ctx)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(foreign.canActivate(ctx('t').ctx)).rejects.toBeInstanceOf(ForbiddenException);
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith('admin.access_denied', expect.objectContaining({ metadata: expect.objectContaining({ reason: 'app_not_allowed' }) }));

    await expect(new BastionUserGuard(jwksReturning({ ...userClaims, role: 'VIEWER' }), auditSpy, { ...options, acceptedRoles: ['ADMIN'] }).canActivate(ctx('t').ctx)).rejects.toThrow('Insufficient role');
  });
});

describe('AppUserGuard', () => {
  const jwksUser = (payload: unknown) =>
    ({ verifyUserToken: vi.fn(async () => payload) }) as unknown as BastionJwksService;

  it('lets @Public through, requires a Bearer token, sets req.user', async () => {
    const guard = new AppUserGuard(jwksUser(userClaims), new Reflector());
    await expect(guard.canActivate(ctx(undefined, { [IS_PUBLIC_KEY]: true }).ctx)).resolves.toBe(true);
    await expect(guard.canActivate(ctx(undefined).ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    const { ctx: c, req } = ctx('t');
    await expect(guard.canActivate(c)).resolves.toBe(true);
    expect(req.user).toMatchObject({ sub: 'user-1' });
  });

  it('propagates the verifier refusal (machine token, other app)', async () => {
    const jwks = { verifyUserToken: vi.fn(async () => { throw new UnauthorizedException('Invalid app context'); }) } as unknown as BastionJwksService;
    await expect(new AppUserGuard(jwks, new Reflector()).canActivate(ctx('t').ctx)).rejects.toThrow('Invalid app context');
  });
});

describe('BastionHttpException', () => {
  it('passes a 4xx through with its field errors', () => {
    const e = BastionHttpException.from(new BastionHttpError(400, 'Validation failed', 'VALIDATION_FAILED', ['x is bad']));
    expect(e.getStatus()).toBe(400);
    expect(e.getResponse()).toEqual({ code: 'VALIDATION_FAILED', message: 'Validation failed', errors: ['x is bad'] });
  });

  it('hides a 5xx behind 502 UPSTREAM / 503 UNAVAILABLE, keeping the detail for the log', () => {
    const e500 = BastionHttpException.from(new BastionHttpError(500, 'relation "users" does not exist'));
    expect(e500.getStatus()).toBe(502);
    expect(e500.getResponse()).toEqual({ code: 'UPSTREAM', message: 'Upstream service error' });
    expect(e500.message).toContain('relation "users"');
    expect(e500.upstreamStatus).toBe(500);

    const down = BastionHttpException.from(new BastionHttpError(503, 'Bastion unreachable: ECONNREFUSED 10.0.0.3', 'UNAVAILABLE'));
    expect(down.getStatus()).toBe(503);
    expect(down.getResponse()).toEqual({ code: 'UNAVAILABLE', message: 'Upstream service unavailable' });
  });
});

describe('request context', () => {
  it('exposes req.id across the async chain, read lazily', async () => {
    const req: { id?: unknown } = {};
    const seen = await new Promise<string | undefined>((resolve) =>
      requestContextMiddleware(req, {}, () => {
        req.id = 'r-1'; // pino-http may set it after this middleware
        setTimeout(() => resolve(currentRequestId()), 0);
      }),
    );
    expect(seen).toBe('r-1');
    expect(currentRequestId()).toBeUndefined();
  });
});

describe('BastionModule request id wiring', () => {
  it('registers the context middleware on every route', () => {
    const forRoutes = vi.fn();
    const apply = vi.fn(() => ({ forRoutes }));
    new BastionModule().configure({ apply } as unknown as MiddlewareConsumer);
    expect(apply).toHaveBeenCalledWith(requestContextMiddleware);
    expect(forRoutes).toHaveBeenCalledWith({ path: '{*splat}', method: RequestMethod.ALL });
  });

  it('BastionService sends the served req.id by default', async () => {
    const seen: (string | undefined)[] = [];
    vi.stubGlobal('fetch', async (_: string, init: RequestInit) => {
      seen.push((init.headers as Record<string, string>)['X-Request-Id']);
      return { ok: true, status: 204 } as Response;
    });
    try {
      const service = new BastionService({ baseUrl: 'http://b', serviceSlug: 's' });
      await new Promise<void>((resolve, reject) =>
        requestContextMiddleware({ id: 'srv-1' }, {}, () => void service.call('GET', '/x').then(() => resolve(), reject)),
      );
      expect(seen).toEqual(['srv-1']);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('BastionHttpException — codes', () => {
  it('omits an empty errors array; an unclassified 4xx keeps Bastion code or the status default', () => {
    expect(BastionHttpException.from(new BastionHttpError(400, 'Bad', 'VALIDATION_FAILED', [])).getResponse()).toEqual({ code: 'VALIDATION_FAILED', message: 'Bad' });
    expect(BastionHttpException.from(new BastionHttpError(404, 'User not found')).getResponse()).toMatchObject({ code: 'NOT_FOUND' });
    expect(BastionHttpException.from(new BastionHttpError(422, 'Too short', undefined, undefined, 'PASSWORD_TOO_SHORT')).getResponse()).toMatchObject({ code: 'PASSWORD_TOO_SHORT' });
    expect(BastionHttpException.from(new BastionHttpError(422, 'Nope')).getResponse()).toMatchObject({ code: 'UNPROCESSABLE' });
  });
});
