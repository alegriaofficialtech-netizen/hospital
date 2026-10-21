import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { UserRole } from '../models';
import { AuthService } from './auth.service';

export function roleGuard(requiredRoles: readonly UserRole[]): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    if (!auth.isAuthenticated()) {
      return router.createUrlTree(['/login']);
    }
    return auth.hasAnyRole(requiredRoles) ? true : router.createUrlTree(['/dashboard']);
  };
}
