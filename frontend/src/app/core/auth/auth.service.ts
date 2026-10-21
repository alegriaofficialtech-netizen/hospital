import { Injectable, computed, signal } from '@angular/core';
import type Keycloak from 'keycloak-js';
import { environment } from '../../../environments/environment';
import { ROLE_LABELS, SessionUser, UserRole, USER_ROLES } from '../models';

const STORAGE_KEY = 'sgsi-zta.session';

const ROLE_ALIASES: Record<string, UserRole> = {
  reception: 'ROLE_RECEPTION',
  recepcion: 'ROLE_RECEPTION',
  lab: 'ROLE_LAB_TECH',
  lab_tech: 'ROLE_LAB_TECH',
  laboratory: 'ROLE_LAB_TECH',
  pathologist: 'ROLE_PATHOLOGIST',
  medico: 'ROLE_PATHOLOGIST',
  auditor: 'ROLE_SECURITY_AUDITOR',
  audit: 'ROLE_SECURITY_AUDITOR',
};

function mapRealmRole(rawRole: string): UserRole | undefined {
  const upper = rawRole.toUpperCase();
  const direct = USER_ROLES.find((role) => role === upper);
  if (direct) {
    return direct;
  }
  return ROLE_ALIASES[rawRole.toLowerCase()];
}

function readStoredSession(): SessionUser | null {
  if (typeof sessionStorage === 'undefined') {
    return null;
  }
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as SessionUser;
    return parsed?.username && Array.isArray(parsed.roles) ? parsed : null;
  } catch {
    return null;
  }
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly _session = signal<SessionUser | null>(
    environment.useMockAuth ? readStoredSession() : null,
  );
  private keycloak?: Keycloak;
  private initPromise?: Promise<void>;

  readonly session = this._session.asReadonly();
  readonly user = computed(() => this._session());
  readonly isAuthenticated = computed(() => this._session() !== null);
  readonly roles = computed<readonly UserRole[]>(() => this._session()?.roles ?? []);
  readonly mfaVerified = computed(() => this._session()?.mfaVerified === true);

  get accessToken(): string | undefined {
    return this.keycloak?.token;
  }

  initialize(): Promise<void> {
    if (environment.useMockAuth) {
      return Promise.resolve();
    }
    if (!this.initPromise) {
      this.initPromise = this.initializeKeycloak();
    }
    return this.initPromise;
  }

  loginDemo(role: UserRole, username: string): void {
    const cleanUsername = username.trim() || this.defaultUsername(role);
    const session: SessionUser = {
      username: cleanUsername,
      displayName: cleanUsername || ROLE_LABELS[role],
      roles: [role],
      mfaVerified: false,
      authMode: 'demo',
    };
    this.storeSession(session);
  }

  async loginWithKeycloak(): Promise<void> {
    if (environment.useMockAuth) {
      throw new Error('Keycloak sign-in is disabled while demo authentication is enabled.');
    }
    await this.initialize();
    if (!this.keycloak) {
      throw new Error('Keycloak client is not available.');
    }
    if (this.keycloak.authenticated) {
      this.applyKeycloakSession(this.keycloak);
      return;
    }
    await this.keycloak.login({
      redirectUri: `${window.location.origin}/dashboard`,
    });
  }

  markMfaVerified(): void {
    const current = this._session();
    if (!current) {
      return;
    }
    const updated: SessionUser = { ...current, mfaVerified: true };
    this._session.set(updated);
    if (updated.authMode === 'demo') {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    }
  }

  async logout(): Promise<void> {
    const activeKeycloak = this.keycloak;
    this._session.set(null);
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(STORAGE_KEY);
    }
    if (activeKeycloak?.authenticated) {
      try {
        await activeKeycloak.logout({
          redirectUri: `${window.location.origin}/login`,
        });
      } catch {
        // The local session is already cleared; a failed remote logout must not block the UI.
      }
    }
  }

  hasAnyRole(required: readonly UserRole[]): boolean {
    return this.roles().some((role) => required.includes(role));
  }

  private async initializeKeycloak(): Promise<void> {
    try {
      const { default: KeycloakClient } = await import('keycloak-js');
      const keycloak = new KeycloakClient(environment.keycloak);
      this.keycloak = keycloak;
      const authenticated = await keycloak.init({
        onLoad: 'check-sso',
        pkceMethod: 'S256',
        checkLoginIframe: false,
      });
      if (authenticated) {
        this.applyKeycloakSession(keycloak);
      }
    } catch (error) {
      console.warn('Keycloak initialization failed.', error);
    }
  }

  private applyKeycloakSession(keycloak: Keycloak): void {
    const parsed = keycloak.tokenParsed as
      | (Record<string, unknown> & {
          realm_access?: { roles?: string[] };
          acr?: string;
          amr?: string | string[];
          name?: string;
          preferred_username?: string;
        })
      | undefined;
    const realmRoles = parsed?.realm_access?.roles ?? [];
    const roles = Array.from(
      new Set(realmRoles.map((role) => mapRealmRole(role)).filter((role): role is UserRole => !!role)),
    );
    const amr = Array.isArray(parsed?.amr)
      ? parsed?.amr
      : typeof parsed?.amr === 'string'
        ? [parsed.amr]
        : [];
    const acr = typeof parsed?.acr === 'string' ? parsed.acr.toLowerCase() : '';
    const acrLevel = Number.parseInt(acr, 10);
    const mfaVerified =
      amr.some((value) => value.toLowerCase() === 'otp') ||
      acr.includes('otp') ||
      acr.includes('mfa') ||
      (Number.isFinite(acrLevel) && acrLevel >= 2);

    const session: SessionUser = {
      username: parsed?.preferred_username ?? parsed?.name ?? 'keycloak-user',
      displayName: parsed?.name ?? parsed?.preferred_username ?? 'Keycloak user',
      roles,
      mfaVerified,
      authMode: 'keycloak',
    };
    this._session.set(session);
  }

  private storeSession(session: SessionUser): void {
    this._session.set(session);
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    }
  }

  private defaultUsername(role: UserRole): string {
    const suffix = role.replace('ROLE_', '').toLowerCase().replace(/_/g, '.');
    return `demo.${suffix}`;
  }
}
