import 'reflect-metadata';
import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import { ServiceClientJwtGuard } from '../src/nest/guards/service-client-jwt.guard.js';
import { BastionUserGuard } from '../src/nest/guards/bastion-user.guard.js';
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
