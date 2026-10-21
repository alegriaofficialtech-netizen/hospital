import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service';

const STORAGE_KEY = 'sgsi-zta.session';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthService);
  });

  it('starts unauthenticated with no roles', () => {
    expect(service.isAuthenticated()).toBe(false);
    expect(service.user()).toBeNull();
    expect(service.roles()).toEqual([]);
  });

  it('logs in a demo role and persists the session only in sessionStorage', () => {
    service.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');

    expect(service.isAuthenticated()).toBe(true);
    expect(service.user()?.username).toBe('demo.pathologist');
    expect(service.roles()).toEqual(['ROLE_PATHOLOGIST']);
    expect(service.user()?.mfaVerified).toBe(false);
    expect(service.hasAnyRole(['ROLE_PATHOLOGIST'])).toBe(true);
    expect(service.hasAnyRole(['ROLE_SECURITY_AUDITOR'])).toBe(false);

    const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? 'null');
    expect(stored.username).toBe('demo.pathologist');
    expect(stored.authMode).toBe('demo');
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('marks MFA verified and resets it on logout', async () => {
    service.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');
    service.markMfaVerified();

    expect(service.mfaVerified()).toBe(true);
    expect(service.user()?.mfaVerified).toBe(true);

    await service.logout();

    expect(service.isAuthenticated()).toBe(false);
    expect(service.session()).toBeNull();
    expect(service.mfaVerified()).toBe(false);
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();

    service.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');
    expect(service.mfaVerified()).toBe(false);
  });

  it('enforces role membership per role', () => {
    service.loginDemo('ROLE_RECEPTION', 'demo.reception');

    expect(service.hasAnyRole(['ROLE_RECEPTION', 'ROLE_LAB_TECH'])).toBe(true);
    expect(service.hasAnyRole(['ROLE_PATHOLOGIST'])).toBe(false);
    expect(service.hasAnyRole(['ROLE_SECURITY_AUDITOR'])).toBe(false);
  });
});
