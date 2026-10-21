import {
  HttpErrorResponse,
  HttpEvent,
  HttpInterceptorFn,
  HttpResponse,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Observable, of, throwError, timer } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { environment } from '../../../environments/environment';
import { UserRole } from '../models';
import { AuthService } from '../auth/auth.service';
import { MockApiError, MockDataService } from './mock-data.service';

interface MockResult {
  status: number;
  body: unknown;
}

function isApiRequest(path: string): boolean {
  return path === '/health' || path.startsWith('/api/');
}

function toHttpError(error: unknown, url: string): HttpErrorResponse {
  if (error instanceof MockApiError) {
    return new HttpErrorResponse({
      status: error.status,
      error: { message: error.message, code: error.code },
      url,
    });
  }
  return new HttpErrorResponse({
    status: 500,
    error: {
      message: 'Unexpected error in the mock API.',
      code: 'MOCK_INTERNAL_ERROR',
    },
    url,
  });
}

function requireRoles(
  auth: AuthService,
  roles: readonly UserRole[],
  code: string,
): void {
  if (!auth.isAuthenticated()) {
    throw new MockApiError(401, 'UNAUTHENTICATED', 'Authentication is required.');
  }
  if (!auth.hasAnyRole(roles)) {
    throw new MockApiError(403, code, 'The current role cannot perform this operation.');
  }
}

export const mockApiInterceptor: HttpInterceptorFn = (req, next) => {
  if (!environment.useMockApi) {
    return next(req);
  }

  const path = new URL(req.url, 'http://mock.local').pathname;
  if (!isApiRequest(path)) {
    return next(req);
  }

  const auth = inject(AuthService);
  const mock = inject(MockDataService);

  return timer(250).pipe(
    switchMap((): Observable<HttpEvent<unknown>> => {
      try {
        const result = handleRequest(req.method, path, req.body, auth, mock);
        return of(
          new HttpResponse({
            status: result.status,
            body: result.body,
            url: req.url,
          }),
        );
      } catch (error) {
        return throwError(() => toHttpError(error, req.url));
      }
    }),
  );
};

function handleRequest(
  method: string,
  path: string,
  body: unknown,
  auth: AuthService,
  mock: MockDataService,
): MockResult {
  if (path === '/health' && method === 'GET') {
    return { status: 200, body: mock.health() };
  }

  if (path === '/api/v1/orders' && method === 'GET') {
    requireRoles(
      auth,
      ['ROLE_RECEPTION', 'ROLE_LAB_TECH', 'ROLE_PATHOLOGIST'],
      'INSUFFICIENT_ROLE_PERMISSIONS',
    );
    return { status: 200, body: mock.listOrders() };
  }

  if (path === '/api/v1/orders' && method === 'POST') {
    requireRoles(auth, ['ROLE_RECEPTION'], 'RECEPTION_ROLE_REQUIRED');
    return {
      status: 201,
      body: mock.createOrder(body as { order_id: string; patient_dni: string; test_type: string }),
    };
  }

  if (path === '/api/v1/orders/validate' && method === 'POST') {
    requireRoles(auth, ['ROLE_PATHOLOGIST'], 'PATHOLOGIST_ROLE_REQUIRED');
    if (!auth.session()?.mfaVerified) {
      throw new MockApiError(
        403,
        'MFA_AUTHENTICATION_REQUIRED',
        'Clinical validation requires a verified MFA factor.',
      );
    }
    return {
      status: 200,
      body: mock.validateOrder(body as { order_id: string; observations: string }),
    };
  }

  if (path === '/api/v1/audit/events' && method === 'GET') {
    requireRoles(auth, ['ROLE_SECURITY_AUDITOR'], 'AUDITOR_ROLE_REQUIRED');
    return { status: 200, body: mock.getAuditEvents() };
  }

  throw new MockApiError(404, 'NOT_FOUND', `No mock handler for ${method} ${path}.`);
}
