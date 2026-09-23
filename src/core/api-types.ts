/**
 * Bastion's public API contract as seen by an app backend. Field names and
 * nullability mirror Bastion's DTOs; when Bastion changes one, it changes here.
 */

export interface BastionTokenPair {
  accessToken: string;
  refreshToken: string;
  /** ISO timestamp — the refresh token is opaque, this is the only way to learn its lifetime. */
  refreshTokenExpiresAt?: string;
}

export interface BastionTwoFactorPending {
  requiresTwoFactor: true;
  twoFactorToken: string;
}

export type BastionLoginResult = BastionTokenPair | BastionTwoFactorPending;

export function isTwoFactorPending(result: BastionLoginResult): result is BastionTwoFactorPending {
  return (result as BastionTwoFactorPending).requiresTwoFactor === true;
}

/** `GET /auth/me`. */
export interface BastionMe {
  id: string;
  email: string;
  username: string | null;
  image: string | null;
  preferredLocale: string | null;
  emailVerified: boolean;
  hasPassword: boolean;
  role: string | null;
  appSlug: string;
  tenantId: string;
  tenantSlug: string;
  tenantName: string;
  tenantActive: boolean;
  apps: string[];
  ageVerified: boolean;
  ageVerificationRequired: boolean;
  /** `null` = never screened, which is NOT "adult". */
  isMinor: boolean | null;
}

export interface BastionSession {
  id: string;
  appSlug: string;
  createdAt: string;
  lastUsedAt: string | null;
  userAgent: string | null;
  ip: string | null;
  isCurrent: boolean;
}

export interface BastionRegisterInput {
  email: string;
  password: string;
  username: string;
  preferredLocale?: string;
  /** ISO `YYYY-MM-DD`, required only when the app has `minimumAge`. */
  birthDate?: string;
}

export interface BastionAgeVerificationResult {
  ageVerified: true;
  isMinor: boolean;
}

export interface BastionProfileUpdate {
  username?: string;
  image?: string | null;
  preferredLocale?: string;
}

export interface BastionEmailChangeRequest {
  email: string;
  currentPassword?: string;
  twoFactorCode?: string;
}

export interface BastionTwoFactorStatus {
  enabled: boolean;
}

export interface BastionTwoFactorSetup {
  qrCodeDataUrl: string;
  secret: string;
}

export interface BastionTwoFactorConfirmed {
  recoveryCodes: string[];
}

export interface BastionTwoFactorRequest {
  code?: string;
  currentPassword?: string;
}

/** The end user behind a call: forwarded as `X-Real-IP` / `User-Agent` so Bastion's rate-limit and audit see the browser, not your container. */
export interface BastionClientContext {
  ip?: string;
  userAgent?: string;
}

export interface BastionSocialAccount {
  provider: string;
  username: string | null;
  email: string | null;
  avatar: string | null;
  syncAvatar: boolean;
  createdAt: string;
}

/** `GET /auth/methods`. */
export interface BastionAuthMethods {
  tenantSlug: string;
  appSlug: string;
  password: { login: boolean; register: boolean };
  oauth: { provider: string; authorizeUrl: string }[];
  oauthSignup: boolean;
}

export interface BastionLinkTicket {
  url: string;
}
