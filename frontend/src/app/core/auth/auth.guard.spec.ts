import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree, provideRouter } from '@angular/router';
import { AuthService } from './auth.service';
import { authGuard } from './auth.guard';
import { roleGuard } from './role.guard';

describe('auth guards', () => {
  const route = {} as ActivatedRouteSnapshot;
  const state = {} as RouterStateSnapshot;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [provideRouter([])],
    });
  });

  it('redirects unauthenticated users to /login', () => {
    const router = TestBed.inject(Router);
    const result = TestBed.runInInjectionContext(() => authGuard(route, state));

    expect(result).toBeInstanceOf(UrlTree);
    expect(router.serializeUrl(result as UrlTree)).toBe('/login');
  });

  it('allows authenticated users through the auth guard', () => {
    const auth = TestBed.inject(AuthService);
    auth.loginDemo('ROLE_LAB_TECH', 'demo.lab.tech');

    const result = TestBed.runInInjectionContext(() => authGuard(route, state));

    expect(result).toBe(true);
  });

  it('redirects wrong-role users to /dashboard', () => {
    const auth = TestBed.inject(AuthService);
    const router = TestBed.inject(Router);
    auth.loginDemo('ROLE_RECEPTION', 'demo.reception');

    const guard = roleGuard(['ROLE_PATHOLOGIST']);
    const result = TestBed.runInInjectionContext(() => guard(route, state));

    expect(result).toBeInstanceOf(UrlTree);
    expect(router.serializeUrl(result as UrlTree)).toBe('/dashboard');
  });

  it('allows the required role through', () => {
    const auth = TestBed.inject(AuthService);
    auth.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');

    const guard = roleGuard(['ROLE_PATHOLOGIST']);
    const result = TestBed.runInInjectionContext(() => guard(route, state));

    expect(result).toBe(true);
  });
});
