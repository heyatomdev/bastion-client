import { BastionTokenError } from './errors.js';

/** Claims Bastion puts on every RS256 token it signs (see bastion/CLAUDE.md, "JWT payload"). */
interface CommonClaims {
  sub: string;
  tenantId: string;
  tenantSlug: string;
  iss?: string;
  aud?: string;
  jti?: string;
  iat: number;
  exp: number;
}

/** A user session token: `POST /auth/login`, `/auth/refresh`, `/auth/exchange`. Never carries `type`. */
export interface UserJwtPayload extends CommonClaims {
  type?: undefined;
  email: string | null;
  username: string | null;
  image: string | null;
  preferredLocale: string | null;
  appSlug: string;
  role: string;
  permissions: string[];
  sessionId?: string;
}

/** A machine token from `POST /auth/client`. Discriminated by `type`. */
export interface ServiceClientJwtPayload extends CommonClaims {
  type: 'service_client';
  clientName: string;
  serviceSlug: string;
  scopes: string[];
}

export type BastionJwtPayload = UserJwtPayload | ServiceClientJwtPayload;

/**
 * For an app backend that accepts its *users'* tokens: the payload must be a
 * user token (machine tokens are rejected whatever their scopes), minted for
 * this app — Bastion sets `aud` and `appSlug` to the app slug at issuance, and
 * one signing key serves the whole fleet, so a valid signature alone proves
 * nothing about which app the session belongs to.
 */
export function assertUserTokenFor(
  payload: BastionJwtPayload,
  appSlug: string,
): UserJwtPayload {
  if (payload.type !== undefined) {
    throw new BastionTokenError('not_user_token', 'Service token not allowed');
  }
  if (payload.aud !== appSlug || payload.appSlug !== appSlug) {
    throw new BastionTokenError('wrong_app', 'Invalid app context');
  }
  if (!payload.sub) throw new BastionTokenError('wrong_app', 'Token without subject');
  return payload;
}

export function isServiceClientToken(
  payload: BastionJwtPayload,
): payload is ServiceClientJwtPayload {
  return payload.type === 'service_client';
}

export interface TokenResponse {
  accessToken: string;
}

export interface AuditEventInput {
  event: string;
  userId?: string;
  metadata?: Record<string, unknown>;
}

/** Minimal logger so the core never depends on a framework. Defaults to silent. */
export interface BastionLogger {
  warn(message: string): void;
  error(message: string): void;
  log(message: string): void;
}

export const silentLogger: BastionLogger = {
  warn: () => undefined,
  error: () => undefined,
  log: () => undefined,
};
